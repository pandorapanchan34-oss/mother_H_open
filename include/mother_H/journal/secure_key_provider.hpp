#pragma once

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#ifdef MOTHER_H_TEST_BUILD
#include <mutex>
#include <openssl/rand.h>
#include <unordered_map>
#endif

namespace mother_h::journal {

enum class KeyStatus : std::uint8_t {
    Ok,
    NotFound,
    Revoked,
    InvalidRequest,
    BackendUnavailable
};

struct KeyReference {
    std::string key_id;
    std::uint32_t version{0};

    bool operator==(const KeyReference& other) const noexcept {
        return key_id == other.key_id && version == other.version;
    }

    bool operator!=(const KeyReference& other) const noexcept {
        return !(*this == other);
    }
};

class KeyMaterial {
public:
    KeyMaterial() = default;
    KeyMaterial(KeyReference reference, std::vector<std::uint8_t>&& secret) noexcept
        : reference_(std::move(reference)), secret_(std::move(secret)) {}

    KeyMaterial(const KeyMaterial&) = delete;
    KeyMaterial& operator=(const KeyMaterial&) = delete;

    KeyMaterial(KeyMaterial&& other) noexcept
        : reference_(std::move(other.reference_)),
          secret_(std::move(other.secret_)) {
        other.reset();
    }

    KeyMaterial& operator=(KeyMaterial&& other) noexcept {
        if (this != &other) {
            reset();
            reference_ = std::move(other.reference_);
            secret_ = std::move(other.secret_);
            other.reset();
        }
        return *this;
    }

    ~KeyMaterial() { reset(); }

    const KeyReference& reference() const noexcept { return reference_; }
    const std::vector<std::uint8_t>& secret() const noexcept { return secret_; }

    void reset() noexcept {
        if (!secret_.empty()) OPENSSL_cleanse(secret_.data(), secret_.size());
        secret_.clear();
        reference_ = {};
    }

private:
    KeyReference reference_;
    std::vector<std::uint8_t> secret_;
};

class ISecureKeyProvider {
public:
    virtual ~ISecureKeyProvider() = default;

    // On failure, implementations must leave out empty. Retired keys remain
    // available for verification; revoked keys must not be returned.
    virtual KeyStatus current_signing_key(KeyMaterial& out) const noexcept = 0;
    virtual KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept = 0;

    // Rotation must create a never-reused version and keep older versions
    // verification-capable until they are explicitly revoked.
    virtual KeyStatus rotate_key(
        const std::string& key_id,
        KeyReference& new_reference
    ) noexcept = 0;
    virtual KeyStatus revoke_key(const KeyReference& reference) noexcept = 0;
};

struct DataKeyReference {
    std::string key_id;
    std::uint32_t version{0};

    bool operator==(const DataKeyReference& other) const noexcept {
        return key_id == other.key_id && version == other.version;
    }

    bool operator!=(const DataKeyReference& other) const noexcept {
        return !(*this == other);
    }
};

class DataKeyMaterial {
public:
    static constexpr std::size_t kAes256KeyBytes = 32;

    DataKeyMaterial() = default;
    DataKeyMaterial(
        DataKeyReference reference,
        std::vector<std::uint8_t>&& secret
    ) noexcept
        : reference_(std::move(reference)), secret_(std::move(secret)) {}

    DataKeyMaterial(const DataKeyMaterial&) = delete;
    DataKeyMaterial& operator=(const DataKeyMaterial&) = delete;

    DataKeyMaterial(DataKeyMaterial&& other) noexcept
        : reference_(std::move(other.reference_)),
          secret_(std::move(other.secret_)) {
        other.reset();
    }

    DataKeyMaterial& operator=(DataKeyMaterial&& other) noexcept {
        if (this != &other) {
            reset();
            reference_ = std::move(other.reference_);
            secret_ = std::move(other.secret_);
            other.reset();
        }
        return *this;
    }

    ~DataKeyMaterial() { reset(); }

    const DataKeyReference& reference() const noexcept { return reference_; }
    const std::vector<std::uint8_t>& secret() const noexcept { return secret_; }

    void reset() noexcept {
        if (!secret_.empty()) {
            OPENSSL_cleanse(secret_.data(), secret_.size());
        }
        secret_.clear();
        reference_ = {};
    }

private:
    DataKeyReference reference_;
    std::vector<std::uint8_t> secret_;
};

class IKeyEncryptionKeyProvider {
public:
    virtual ~IKeyEncryptionKeyProvider() = default;

    virtual KeyStatus wrap_dek(
        const std::vector<std::uint8_t>& plaintext_dek,
        std::vector<std::uint8_t>& wrapped_dek_out
    ) const noexcept = 0;

    virtual KeyStatus unwrap_dek(
        const std::vector<std::uint8_t>& wrapped_dek,
        std::vector<std::uint8_t>& plaintext_dek_out
    ) const noexcept = 0;
};

class IDataEncryptionKeyProvider {
public:
    using KeyUseCallback = std::function<bool(const DataKeyMaterial&)>;

    virtual ~IDataEncryptionKeyProvider() = default;

    virtual KeyStatus with_key(
        const DataKeyReference& reference,
        const KeyUseCallback& fn
    ) const noexcept = 0;

    virtual KeyStatus revoke_key(const DataKeyReference& reference) noexcept = 0;
};

#ifdef MOTHER_H_TEST_BUILD
class InMemoryTestDataEncryptionKeyProvider final : public IDataEncryptionKeyProvider {
public:
    KeyStatus generate_key(
        const std::string& key_id,
        DataKeyReference& out_ref
    ) noexcept {
        std::vector<std::uint8_t> raw;
        try {
            if (!valid_id(key_id)) return KeyStatus::InvalidRequest;
            raw.resize(DataKeyMaterial::kAes256KeyBytes);
            if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
                OPENSSL_cleanse(raw.data(), raw.size());
                return KeyStatus::BackendUnavailable;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            auto& entry = entries_[key_id];
            if (entry.next_version == 0) {
                OPENSSL_cleanse(raw.data(), raw.size());
                return KeyStatus::BackendUnavailable;
            }
            const std::uint32_t version = entry.next_version++;
            entry.versions[version] = KeySlot{std::move(raw), false};
            out_ref = DataKeyReference{key_id, version};
            return KeyStatus::Ok;
        } catch (...) {
            if (!raw.empty()) {
                OPENSSL_cleanse(raw.data(), raw.size());
            }
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus with_key(
        const DataKeyReference& reference,
        const KeyUseCallback& fn
    ) const noexcept override {
        DataKeyMaterial scoped_key;
        try {
            if (!fn || !valid_id(reference.key_id) || reference.version == 0) {
                return KeyStatus::InvalidRequest;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto entry = entries_.find(reference.key_id);
                if (entry == entries_.end()) return KeyStatus::NotFound;
                const auto version = entry->second.versions.find(reference.version);
                if (version == entry->second.versions.end()) return KeyStatus::NotFound;
                if (version->second.revoked) return KeyStatus::Revoked;
                if (version->second.secret.size() != DataKeyMaterial::kAes256KeyBytes) {
                    return KeyStatus::BackendUnavailable;
                }
                std::vector<std::uint8_t> ephemeral = version->second.secret;
                scoped_key = DataKeyMaterial(reference, std::move(ephemeral));
            }
            const bool ok = fn(scoped_key);
            scoped_key.reset();
            return ok ? KeyStatus::Ok : KeyStatus::InvalidRequest;
        } catch (...) {
            scoped_key.reset();
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus revoke_key(const DataKeyReference& reference) noexcept override {
        try {
            if (!valid_id(reference.key_id) || reference.version == 0) {
                return KeyStatus::InvalidRequest;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            const auto entry = entries_.find(reference.key_id);
            if (entry == entries_.end()) return KeyStatus::NotFound;
            const auto version = entry->second.versions.find(reference.version);
            if (version == entry->second.versions.end()) return KeyStatus::NotFound;
            if (!version->second.secret.empty()) {
                OPENSSL_cleanse(
                    version->second.secret.data(),
                    version->second.secret.size()
                );
                version->second.secret.clear();
            }
            version->second.revoked = true;
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

private:
    struct KeySlot {
        std::vector<std::uint8_t> secret;
        bool revoked{false};
    };

    struct KeyFamily {
        std::uint32_t next_version{1};
        std::unordered_map<std::uint32_t, KeySlot> versions;
    };

    static bool valid_id(const std::string& id) noexcept {
        if (id.empty() || id.size() > 128) return false;
        for (const unsigned char character : id) {
            const bool valid =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '-' || character == '_' || character == '.';
            if (!valid) return false;
        }
        return true;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, KeyFamily> entries_;
};
#endif

}  // namespace mother_h::journal
