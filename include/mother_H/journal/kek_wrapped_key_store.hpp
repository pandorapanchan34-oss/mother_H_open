#pragma once

#include "mother_H/journal/secure_key_provider.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace mother_h::journal {

class IContextBoundKeyEncryptionKeyProvider {
public:
    virtual ~IContextBoundKeyEncryptionKeyProvider() = default;

    virtual KeyStatus wrap_dek(
        const DataKeyReference& reference,
        const std::vector<std::uint8_t>& plaintext_dek,
        std::vector<std::uint8_t>& wrapped_dek_out
    ) const noexcept = 0;

    virtual KeyStatus unwrap_dek(
        const DataKeyReference& reference,
        const std::vector<std::uint8_t>& wrapped_dek,
        std::vector<std::uint8_t>& plaintext_dek_out
    ) const noexcept = 0;
};

class Aes256GcmMasterKekProvider final
    : public IContextBoundKeyEncryptionKeyProvider {
public:
    static constexpr std::size_t kMasterKeyBytes = 32;
    static constexpr std::size_t kIvBytes = 12;
    static constexpr std::size_t kTagBytes = 16;
    static constexpr std::size_t kWrappedDekBytes =
        kIvBytes + DataKeyMaterial::kAes256KeyBytes + kTagBytes;

    explicit Aes256GcmMasterKekProvider(
        const std::array<std::uint8_t, kMasterKeyBytes>& master_key
    ) noexcept
        : master_key_(master_key) {}

    Aes256GcmMasterKekProvider(
        const Aes256GcmMasterKekProvider&
    ) = delete;
    Aes256GcmMasterKekProvider& operator=(
        const Aes256GcmMasterKekProvider&
    ) = delete;
    Aes256GcmMasterKekProvider(
        Aes256GcmMasterKekProvider&&
    ) = delete;
    Aes256GcmMasterKekProvider& operator=(
        Aes256GcmMasterKekProvider&&
    ) = delete;

    ~Aes256GcmMasterKekProvider() override {
        OPENSSL_cleanse(master_key_.data(), master_key_.size());
    }

    KeyStatus wrap_dek(
        const DataKeyReference& reference,
        const std::vector<std::uint8_t>& plaintext_dek,
        std::vector<std::uint8_t>& wrapped_dek_out
    ) const noexcept override {
        cleanse(wrapped_dek_out);
        if (!valid_reference(reference) ||
            plaintext_dek.size() != DataKeyMaterial::kAes256KeyBytes) {
            return KeyStatus::InvalidRequest;
        }

        try {
            std::vector<std::uint8_t> aad;
            if (!make_aad(reference, aad)) return KeyStatus::BackendUnavailable;

            std::vector<std::uint8_t> wrapped(kWrappedDekBytes, 0);
            VectorCleanser wrapped_cleanser(wrapped);
            if (RAND_bytes(wrapped.data(), static_cast<int>(kIvBytes)) != 1) {
                return KeyStatus::BackendUnavailable;
            }

            using CipherContext =
                std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
            CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context) return KeyStatus::BackendUnavailable;

            int written = 0;
            int total = 0;
            bool ok =
                EVP_EncryptInit_ex(
                    context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                EVP_EncryptInit_ex(
                    context.get(),
                    nullptr,
                    nullptr,
                    master_key_.data(),
                    wrapped.data()) == 1 &&
                EVP_EncryptUpdate(
                    context.get(), nullptr, &written, aad.data(),
                    static_cast<int>(aad.size())) == 1 &&
                EVP_EncryptUpdate(
                    context.get(),
                    wrapped.data() + kIvBytes,
                    &written,
                    plaintext_dek.data(),
                    static_cast<int>(plaintext_dek.size())) == 1;
            if (ok) {
                total = written;
                ok = EVP_EncryptFinal_ex(
                    context.get(),
                    wrapped.data() + kIvBytes + static_cast<std::size_t>(total),
                    &written) == 1;
                total += written;
            }
            if (!ok ||
                total != static_cast<int>(DataKeyMaterial::kAes256KeyBytes) ||
                EVP_CIPHER_CTX_ctrl(
                    context.get(),
                    EVP_CTRL_GCM_GET_TAG,
                    static_cast<int>(kTagBytes),
                    wrapped.data() + kIvBytes + DataKeyMaterial::kAes256KeyBytes
                ) != 1) {
                return KeyStatus::BackendUnavailable;
            }

            wrapped_dek_out.swap(wrapped);
            return KeyStatus::Ok;
        } catch (...) {
            cleanse(wrapped_dek_out);
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus unwrap_dek(
        const DataKeyReference& reference,
        const std::vector<std::uint8_t>& wrapped_dek,
        std::vector<std::uint8_t>& plaintext_dek_out
    ) const noexcept override {
        cleanse(plaintext_dek_out);
        if (!valid_reference(reference) ||
            wrapped_dek.size() != kWrappedDekBytes) {
            return KeyStatus::InvalidRequest;
        }

        try {
            std::vector<std::uint8_t> plaintext(
                DataKeyMaterial::kAes256KeyBytes, 0);
            VectorCleanser plaintext_cleanser(plaintext);
            std::vector<std::uint8_t> aad;
            if (!make_aad(reference, aad)) return KeyStatus::BackendUnavailable;

            using CipherContext =
                std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
            CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context) return KeyStatus::BackendUnavailable;

            int written = 0;
            int total = 0;
            bool ok =
                EVP_DecryptInit_ex(
                    context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                EVP_DecryptInit_ex(
                    context.get(),
                    nullptr,
                    nullptr,
                    master_key_.data(),
                    wrapped_dek.data()) == 1 &&
                EVP_DecryptUpdate(
                    context.get(), nullptr, &written, aad.data(),
                    static_cast<int>(aad.size())) == 1 &&
                EVP_DecryptUpdate(
                    context.get(),
                    plaintext.data(),
                    &written,
                    wrapped_dek.data() + kIvBytes,
                    static_cast<int>(DataKeyMaterial::kAes256KeyBytes)) == 1;
            if (ok) {
                total = written;
                ok =
                    EVP_CIPHER_CTX_ctrl(
                        context.get(),
                        EVP_CTRL_GCM_SET_TAG,
                        static_cast<int>(kTagBytes),
                        const_cast<std::uint8_t*>(
                            wrapped_dek.data() + kIvBytes +
                            DataKeyMaterial::kAes256KeyBytes)) == 1 &&
                    EVP_DecryptFinal_ex(
                        context.get(),
                        plaintext.data() + static_cast<std::size_t>(total),
                        &written) == 1;
                total += written;
            }
            if (!ok ||
                total != static_cast<int>(DataKeyMaterial::kAes256KeyBytes)) {
                return KeyStatus::BackendUnavailable;
            }

            plaintext_dek_out = plaintext;
            return KeyStatus::Ok;
        } catch (...) {
            cleanse(plaintext_dek_out);
            return KeyStatus::BackendUnavailable;
        }
    }

private:
    struct VectorCleanser {
        explicit VectorCleanser(std::vector<std::uint8_t>& value) noexcept
            : value_(value) {}
        ~VectorCleanser() { cleanse(value_); }
        std::vector<std::uint8_t>& value_;
    };

    static void cleanse(std::vector<std::uint8_t>& value) noexcept {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
        value.clear();
    }

    static bool valid_reference(const DataKeyReference& reference) noexcept {
        if (reference.version == 0 || reference.key_id.empty() ||
            reference.key_id.size() > 128) {
            return false;
        }
        for (const unsigned char character : reference.key_id) {
            const bool valid =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '-' || character == '_' || character == '.';
            if (!valid) return false;
        }
        return true;
    }

    static bool make_aad(
        const DataKeyReference& reference,
        std::vector<std::uint8_t>& aad
    ) {
        static constexpr char domain[] = "Mother_H/DEK-KEK-wrap/v1";
        aad.insert(aad.end(), domain, domain + sizeof(domain));
        const auto id_size = static_cast<std::uint16_t>(reference.key_id.size());
        aad.push_back(static_cast<std::uint8_t>(id_size >> 8U));
        aad.push_back(static_cast<std::uint8_t>(id_size));
        aad.insert(
            aad.end(), reference.key_id.begin(), reference.key_id.end());
        aad.push_back(static_cast<std::uint8_t>(reference.version >> 24U));
        aad.push_back(static_cast<std::uint8_t>(reference.version >> 16U));
        aad.push_back(static_cast<std::uint8_t>(reference.version >> 8U));
        aad.push_back(static_cast<std::uint8_t>(reference.version));
        return true;
    }

    std::array<std::uint8_t, kMasterKeyBytes> master_key_;
};

#ifdef _WIN32
class WindowsDpapiKekProvider final
    : public IContextBoundKeyEncryptionKeyProvider {
public:
    KeyStatus wrap_dek(
        const DataKeyReference& reference,
        const std::vector<std::uint8_t>& plaintext_dek,
        std::vector<std::uint8_t>& wrapped_dek_out
    ) const noexcept override {
        cleanse(wrapped_dek_out);
        if (!valid_reference(reference) ||
            plaintext_dek.size() != DataKeyMaterial::kAes256KeyBytes) {
            return KeyStatus::InvalidRequest;
        }
        try {
            std::vector<std::uint8_t> entropy;
            if (!make_entropy(reference, entropy)) {
                return KeyStatus::BackendUnavailable;
            }
            DATA_BLOB input{
                static_cast<DWORD>(plaintext_dek.size()),
                const_cast<BYTE*>(plaintext_dek.data())};
            DATA_BLOB optional_entropy{
                static_cast<DWORD>(entropy.size()), entropy.data()};
            DATA_BLOB output{};
            LocalBlob output_owner(output, false);
            if (!CryptProtectData(
                    &input,
                    L"Mother_H DEK",
                    &optional_entropy,
                    nullptr,
                    nullptr,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &output) ||
                output.pbData == nullptr || output.cbData == 0) {
                return KeyStatus::BackendUnavailable;
            }
            wrapped_dek_out.assign(
                output.pbData, output.pbData + output.cbData);
            return KeyStatus::Ok;
        } catch (...) {
            cleanse(wrapped_dek_out);
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus unwrap_dek(
        const DataKeyReference& reference,
        const std::vector<std::uint8_t>& wrapped_dek,
        std::vector<std::uint8_t>& plaintext_dek_out
    ) const noexcept override {
        cleanse(plaintext_dek_out);
        if (!valid_reference(reference) || wrapped_dek.empty() ||
            wrapped_dek.size() > (std::numeric_limits<DWORD>::max)()) {
            return KeyStatus::InvalidRequest;
        }
        try {
            std::vector<std::uint8_t> entropy;
            if (!make_entropy(reference, entropy)) {
                return KeyStatus::BackendUnavailable;
            }
            DATA_BLOB input{
                static_cast<DWORD>(wrapped_dek.size()),
                const_cast<BYTE*>(wrapped_dek.data())};
            DATA_BLOB optional_entropy{
                static_cast<DWORD>(entropy.size()), entropy.data()};
            DATA_BLOB output{};
            LocalBlob output_owner(output, true);
            if (!CryptUnprotectData(
                    &input,
                    nullptr,
                    &optional_entropy,
                    nullptr,
                    nullptr,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &output) ||
                output.pbData == nullptr ||
                output.cbData != DataKeyMaterial::kAes256KeyBytes) {
                return KeyStatus::BackendUnavailable;
            }
            plaintext_dek_out.assign(
                output.pbData, output.pbData + output.cbData);
            return KeyStatus::Ok;
        } catch (...) {
            cleanse(plaintext_dek_out);
            return KeyStatus::BackendUnavailable;
        }
    }

private:
    struct LocalBlob {
        LocalBlob(DATA_BLOB& value, bool wipe) noexcept
            : value_(value), wipe_(wipe) {}
        ~LocalBlob() {
            if (value_.pbData != nullptr) {
                if (wipe_) OPENSSL_cleanse(value_.pbData, value_.cbData);
                LocalFree(value_.pbData);
            }
        }
        DATA_BLOB& value_;
        bool wipe_;
    };

    static void cleanse(std::vector<std::uint8_t>& value) noexcept {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
        value.clear();
    }

    static bool valid_reference(const DataKeyReference& reference) noexcept {
        if (reference.version == 0 || reference.key_id.empty() ||
            reference.key_id.size() > 128) {
            return false;
        }
        for (const unsigned char character : reference.key_id) {
            const bool valid =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '-' || character == '_' || character == '.';
            if (!valid) return false;
        }
        return true;
    }

    static bool make_entropy(
        const DataKeyReference& reference,
        std::vector<std::uint8_t>& entropy
    ) {
        static constexpr char domain[] = "Mother_H/DPAPI-DEK-wrap/v1";
        entropy.insert(entropy.end(), domain, domain + sizeof(domain));
        const auto id_size = static_cast<std::uint16_t>(reference.key_id.size());
        entropy.push_back(static_cast<std::uint8_t>(id_size >> 8U));
        entropy.push_back(static_cast<std::uint8_t>(id_size));
        entropy.insert(
            entropy.end(), reference.key_id.begin(), reference.key_id.end());
        entropy.push_back(static_cast<std::uint8_t>(reference.version >> 24U));
        entropy.push_back(static_cast<std::uint8_t>(reference.version >> 16U));
        entropy.push_back(static_cast<std::uint8_t>(reference.version >> 8U));
        entropy.push_back(static_cast<std::uint8_t>(reference.version));
        return true;
    }
};
#endif

class IMonotonicRevocationAnchor {
public:
    virtual ~IMonotonicRevocationAnchor() = default;

    using UsageLease = std::uint64_t;

    // Implementations must persist this generation outside the store file;
    // an in-memory implementation alone is not a production rollback anchor.
    virtual bool read_generation(std::uint64_t& generation_out) const noexcept = 0;

    // Must atomically change exactly expected to next, or leave the value intact.
    // Reject the change while any usage lease or revocation transaction is active.
    virtual bool advance(
        std::uint64_t expected,
        std::uint64_t next
    ) noexcept = 0;

    // Shared-use operations default to fail-closed for existing implementations.
    // Callers must release each unique, nonzero lease with a scope guard.
    virtual bool acquire_usage(
        const DataKeyReference& reference,
        std::uint64_t expected_generation,
        UsageLease& lease_out
    ) noexcept {
        (void)reference;
        (void)expected_generation;
        lease_out = 0;
        return false;
    }

    virtual bool release_usage(UsageLease lease) noexcept {
        (void)lease;
        return false;
    }

    // begin_revocation succeeds only when no usage lease is outstanding.
    // While revocation is pending, new leases and competing generation changes
    // must be rejected.
    virtual bool begin_revocation(
        const DataKeyReference& reference,
        std::uint64_t expected_generation
    ) noexcept {
        (void)reference;
        (void)expected_generation;
        return false;
    }

    // Commits the pending revocation and advances exactly one generation.
    virtual bool commit_revocation(
        const DataKeyReference& reference,
        std::uint64_t expected_generation,
        std::uint64_t next_generation
    ) noexcept {
        (void)reference;
        (void)expected_generation;
        (void)next_generation;
        return false;
    }

    // Cancels a pending revocation after its associated store update fails.
    virtual bool cancel_revocation(
        const DataKeyReference& reference,
        std::uint64_t expected_generation
    ) noexcept {
        (void)reference;
        (void)expected_generation;
        return false;
    }
};

class KekWrappedDataEncryptionKeyStore final
    : public IDataEncryptionKeyProvider {
public:
    static constexpr std::size_t kMaximumSlots = 1024;
    static constexpr std::size_t kMaximumKeyIdBytes = 128;
    static constexpr std::size_t kMaximumWrappedBytes = 4096;
    static constexpr std::size_t kMaximumFileBytes = 8U * 1024U * 1024U;

    KekWrappedDataEncryptionKeyStore(
        std::filesystem::path path,
        const IContextBoundKeyEncryptionKeyProvider& kek_provider,
        IMonotonicRevocationAnchor* anchor
    )
        : path_(std::move(path)),
          kek_provider_(kek_provider),
          anchor_(anchor) {}

    KekWrappedDataEncryptionKeyStore(
        const KekWrappedDataEncryptionKeyStore&
    ) = delete;
    KekWrappedDataEncryptionKeyStore& operator=(
        const KekWrappedDataEncryptionKeyStore&
    ) = delete;

    KeyStatus load() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (initialized_ || !use_counts_.empty()) {
                return KeyStatus::InvalidRequest;
            }
            slots_.clear();
            use_counts_.clear();
            generation_ = 0;
            initialized_ = false;
            failed_closed_ = false;
            if (anchor_ == nullptr) return fail_load();

            std::vector<std::uint8_t> bytes;
            bool exists = false;
            if (!read_store_file(bytes, exists)) return fail_load();

            SlotMap loaded_slots;
            std::uint64_t file_generation = 0;
            if (exists) {
                if (!parse(bytes, loaded_slots, file_generation)) {
                    return fail_load();
                }
            }

            std::uint64_t anchor_generation = 0;
            if (!anchor_->read_generation(anchor_generation) ||
                anchor_generation != file_generation) {
                return fail_load();
            }

            slots_.swap(loaded_slots);
            generation_ = file_generation;
            initialized_ = true;
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus generate_key(
        const std::string& key_id,
        DataKeyReference& out_reference
    ) noexcept {
        if (!valid_key_id(key_id)) return KeyStatus::InvalidRequest;

        try {
            std::vector<std::uint8_t> plaintext(
                DataKeyMaterial::kAes256KeyBytes);
            VectorCleanser plaintext_cleanser(plaintext);
            if (RAND_bytes(
                    plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
                return KeyStatus::BackendUnavailable;
            }

            std::lock_guard<std::mutex> lock(mutex_);
            if (!ready()) return KeyStatus::BackendUnavailable;
            if (slots_.size() >= kMaximumSlots ||
                generation_ == (std::numeric_limits<std::uint64_t>::max)()) {
                return KeyStatus::BackendUnavailable;
            }

            std::uint32_t latest_version = 0;
            auto it = slots_.lower_bound(SlotKey{key_id, 0});
            while (it != slots_.end() && it->first.first == key_id) {
                latest_version = (std::max)(latest_version, it->first.second);
                ++it;
            }
            if (latest_version == (std::numeric_limits<std::uint32_t>::max)()) {
                return KeyStatus::BackendUnavailable;
            }

            DataKeyReference reference{key_id, latest_version + 1U};
            std::vector<std::uint8_t> wrapped;
            const KeyStatus wrap_status =
                kek_provider_.wrap_dek(reference, plaintext, wrapped);
            VectorCleanser wrapped_cleanser(wrapped);
            if (wrap_status != KeyStatus::Ok || wrapped.empty() ||
                wrapped.size() > kMaximumWrappedBytes) {
                return wrap_status == KeyStatus::InvalidRequest
                    ? wrap_status
                    : KeyStatus::BackendUnavailable;
            }

            SlotMap candidate = slots_;
            const auto inserted = candidate.emplace(
                SlotKey{reference.key_id, reference.version},
                Slot{std::move(wrapped), false});
            if (!inserted.second) return KeyStatus::BackendUnavailable;

            const std::uint64_t next_generation = generation_ + 1U;
            DataKeyReference result = reference;
            if (!persist_candidate(candidate, generation_, next_generation)) {
                return KeyStatus::BackendUnavailable;
            }
            slots_.swap(candidate);
            generation_ = next_generation;
            out_reference = std::move(result);
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

    // Calling revoke_key for this same reference from fn is forbidden; while
    // the callback is active, revoke_key returns BackendUnavailable.
    KeyStatus with_key(
        const DataKeyReference& reference,
        const KeyUseCallback& fn
    ) const noexcept override {
        if (!fn || !valid_reference(reference)) return KeyStatus::InvalidRequest;

        const SlotKey active_key{reference.key_id, reference.version};
        std::vector<std::uint8_t> wrapped;
        std::uint64_t expected_generation = 0;
        try {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!ready()) return KeyStatus::BackendUnavailable;
                const auto slot =
                    slots_.find(active_key);
                if (slot == slots_.end()) return KeyStatus::NotFound;
                if (slot->second.revoked) return KeyStatus::Revoked;

                auto& count = use_counts_[slot->first];
                if (count == (std::numeric_limits<std::size_t>::max)()) {
                    return KeyStatus::BackendUnavailable;
                }
                ++count;
                expected_generation = generation_;
                try {
                    wrapped = slot->second.wrapped;
                } catch (...) {
                    --count;
                    return KeyStatus::BackendUnavailable;
                }
            }

            ActiveUse active_use(this, std::move(active_key));
            std::uint64_t anchor_generation = 0;
            if (anchor_ == nullptr ||
                !anchor_->read_generation(anchor_generation)) {
                mark_failed_closed();
                return KeyStatus::BackendUnavailable;
            }
            if (anchor_generation != expected_generation) {
                mark_failed_closed();
                return KeyStatus::BackendUnavailable;
            }

            IMonotonicRevocationAnchor::UsageLease lease = 0;
            if (!anchor_->acquire_usage(
                    reference, expected_generation, lease)) {
                return KeyStatus::BackendUnavailable;
            }
            if (lease == 0) {
                mark_failed_closed();
                return KeyStatus::BackendUnavailable;
            }
            SharedUsage shared_usage(this, anchor_, lease);

            VectorCleanser wrapped_cleanser(wrapped);
            std::vector<std::uint8_t> plaintext;
            VectorCleanser plaintext_cleanser(plaintext);
            KeyStatus result = KeyStatus::BackendUnavailable;
            const KeyStatus unwrap_status = kek_provider_.unwrap_dek(
                reference, wrapped, plaintext);
            if (unwrap_status != KeyStatus::Ok) {
                result = unwrap_status;
            } else if (plaintext.size() !=
                       DataKeyMaterial::kAes256KeyBytes) {
                result = KeyStatus::BackendUnavailable;
            } else {
                DataKeyMaterial material(reference, std::move(plaintext));
                const bool accepted = fn(material);
                material.reset();
                result = accepted ? KeyStatus::Ok : KeyStatus::InvalidRequest;
            }

            if (!shared_usage.release()) {
                return KeyStatus::BackendUnavailable;
            }
            return result;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus revoke_key(
        const DataKeyReference& reference
    ) noexcept override {
        if (!valid_reference(reference)) return KeyStatus::InvalidRequest;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!ready()) return KeyStatus::BackendUnavailable;
            const SlotKey key{reference.key_id, reference.version};
            const auto slot = slots_.find(key);
            if (slot == slots_.end()) return KeyStatus::NotFound;
            const auto active = use_counts_.find(key);
            if (active != use_counts_.end() && active->second != 0) {
                return KeyStatus::BackendUnavailable;
            }
            if (slot->second.revoked) return KeyStatus::Revoked;
            if (generation_ == (std::numeric_limits<std::uint64_t>::max)()) {
                return KeyStatus::BackendUnavailable;
            }

            const std::uint64_t expected_generation = generation_;
            std::uint64_t anchor_generation = 0;
            if (anchor_ == nullptr ||
                !anchor_->read_generation(anchor_generation)) {
                mark_failed_closed();
                return KeyStatus::BackendUnavailable;
            }
            if (anchor_generation != expected_generation) {
                mark_failed_closed();
                return KeyStatus::BackendUnavailable;
            }
            if (!anchor_->begin_revocation(reference, expected_generation)) {
                return KeyStatus::BackendUnavailable;
            }
            PendingRevocation pending(
                this, anchor_, reference, expected_generation);

            SlotMap candidate = slots_;
            Slot& revoked_slot = candidate.find(key)->second;
            revoked_slot.revoked = true;
            cleanse(revoked_slot.wrapped);
            const std::uint64_t next_generation = expected_generation + 1U;
            const PersistResult persist_result =
                persist_candidate_file(candidate, next_generation);
            if (persist_result == PersistResult::NotReplaced) {
                return KeyStatus::BackendUnavailable;
            }

            if (persist_result != PersistResult::Persisted) {
                pending.leave_pending_fail_closed();
                return KeyStatus::BackendUnavailable;
            }
            if (!pending.commit(next_generation)) {
                return KeyStatus::BackendUnavailable;
            }

            slots_.swap(candidate);
            generation_ = next_generation;
            return KeyStatus::Ok;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

private:
    enum class PersistResult : std::uint8_t {
        NotReplaced,
        Persisted,
        ReplacedUnconfirmed
    };

    enum class AtomicReplaceResult : std::uint8_t {
        NotReplaced,
        Replaced,
        ReplacedUnconfirmed
    };

    using SlotKey = std::pair<std::string, std::uint32_t>;

    struct Slot {
        std::vector<std::uint8_t> wrapped;
        bool revoked{false};
    };

    using SlotMap = std::map<SlotKey, Slot>;

    struct VectorCleanser {
        explicit VectorCleanser(std::vector<std::uint8_t>& value) noexcept
            : value_(value) {}
        ~VectorCleanser() { cleanse(value_); }
        std::vector<std::uint8_t>& value_;
    };

    struct ActiveUse {
        ActiveUse(const KekWrappedDataEncryptionKeyStore* store, SlotKey key)
            : store_(store), key_(std::move(key)) {}
        ~ActiveUse() { store_->release_use(key_); }
        const KekWrappedDataEncryptionKeyStore* store_;
        SlotKey key_;
    };

    struct SharedUsage {
        SharedUsage(
            const KekWrappedDataEncryptionKeyStore* store,
            IMonotonicRevocationAnchor* anchor,
            IMonotonicRevocationAnchor::UsageLease lease
        ) noexcept
            : store_(store), anchor_(anchor), lease_(lease) {}

        SharedUsage(const SharedUsage&) = delete;
        SharedUsage& operator=(const SharedUsage&) = delete;

        ~SharedUsage() {
            if (active_) release();
        }

        bool release() noexcept {
            if (!active_) return true;
            if (anchor_ != nullptr && anchor_->release_usage(lease_)) {
                active_ = false;
                return true;
            }
            store_->mark_failed_closed();
            return false;
        }

        const KekWrappedDataEncryptionKeyStore* store_;
        IMonotonicRevocationAnchor* anchor_;
        IMonotonicRevocationAnchor::UsageLease lease_;
        bool active_{true};
    };

    struct PendingRevocation {
        PendingRevocation(
            KekWrappedDataEncryptionKeyStore* store,
            IMonotonicRevocationAnchor* anchor,
            const DataKeyReference& reference,
            std::uint64_t expected_generation
        ) noexcept
            : store_(store),
              anchor_(anchor),
              reference_(&reference),
              expected_generation_(expected_generation) {}

        PendingRevocation(const PendingRevocation&) = delete;
        PendingRevocation& operator=(const PendingRevocation&) = delete;

        ~PendingRevocation() {
            if (active_) cancel();
        }

        bool cancel() noexcept {
            if (!active_) return true;
            if (anchor_ != nullptr &&
                anchor_->cancel_revocation(
                    *reference_, expected_generation_)) {
                active_ = false;
                return true;
            }
            store_->mark_failed_closed();
            return false;
        }

        bool commit(std::uint64_t next_generation) noexcept {
            if (!active_) return false;
            const bool committed =
                anchor_ != nullptr &&
                anchor_->commit_revocation(
                    *reference_, expected_generation_, next_generation);
            active_ = false;
            if (!committed) store_->mark_failed_closed();
            return committed;
        }

        void leave_pending_fail_closed() noexcept {
            if (!active_) return;
            active_ = false;
            store_->mark_failed_closed();
        }

        KekWrappedDataEncryptionKeyStore* store_;
        IMonotonicRevocationAnchor* anchor_;
        const DataKeyReference* reference_;
        std::uint64_t expected_generation_;
        bool active_{true};
    };

    void mark_failed_closed() const noexcept {
        failed_closed_.store(true);
    }

    static void cleanse(std::vector<std::uint8_t>& value) noexcept {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
        value.clear();
    }

    static bool valid_key_id(const std::string& key_id) noexcept {
        if (key_id.empty() || key_id.size() > kMaximumKeyIdBytes) return false;
        for (const unsigned char character : key_id) {
            const bool valid =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '-' || character == '_' || character == '.';
            if (!valid) return false;
        }
        return true;
    }

    static bool valid_reference(const DataKeyReference& reference) noexcept {
        return valid_key_id(reference.key_id) && reference.version != 0;
    }

    bool ready() const noexcept {
        return initialized_ && !failed_closed_.load() && anchor_ != nullptr;
    }

    KeyStatus fail_load() noexcept {
        slots_.clear();
        use_counts_.clear();
        generation_ = 0;
        initialized_ = false;
        failed_closed_ = true;
        return KeyStatus::BackendUnavailable;
    }

    static void append_u16(
        std::vector<std::uint8_t>& output,
        std::uint16_t value
    ) {
        output.push_back(static_cast<std::uint8_t>(value >> 8U));
        output.push_back(static_cast<std::uint8_t>(value));
    }

    static void append_u32(
        std::vector<std::uint8_t>& output,
        std::uint32_t value
    ) {
        output.push_back(static_cast<std::uint8_t>(value >> 24U));
        output.push_back(static_cast<std::uint8_t>(value >> 16U));
        output.push_back(static_cast<std::uint8_t>(value >> 8U));
        output.push_back(static_cast<std::uint8_t>(value));
    }

    static void append_u64(
        std::vector<std::uint8_t>& output,
        std::uint64_t value
    ) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    }

    static bool read_u16(
        const std::vector<std::uint8_t>& input,
        std::size_t& offset,
        std::uint16_t& value
    ) noexcept {
        if (input.size() - offset < 2) return false;
        value = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(input[offset]) << 8U) |
            input[offset + 1]);
        offset += 2;
        return true;
    }

    static bool read_u32(
        const std::vector<std::uint8_t>& input,
        std::size_t& offset,
        std::uint32_t& value
    ) noexcept {
        if (input.size() - offset < 4) return false;
        value =
            (static_cast<std::uint32_t>(input[offset]) << 24U) |
            (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
            (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
            static_cast<std::uint32_t>(input[offset + 3]);
        offset += 4;
        return true;
    }

    static bool read_u64(
        const std::vector<std::uint8_t>& input,
        std::size_t& offset,
        std::uint64_t& value
    ) noexcept {
        if (input.size() - offset < 8) return false;
        value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value = (value << 8U) | input[offset + i];
        }
        offset += 8;
        return true;
    }

    static bool parse(
        const std::vector<std::uint8_t>& bytes,
        SlotMap& slots,
        std::uint64_t& generation
    ) {
        static constexpr std::array<std::uint8_t, 8> magic{{
            'M', 'H', 'K', 'W', 'S', '0', '0', '1'}};
        constexpr std::size_t kHeaderBytes = 8 + 8 + 4;
        if (bytes.size() < kHeaderBytes || bytes.size() > kMaximumFileBytes ||
            !std::equal(magic.begin(), magic.end(), bytes.begin())) {
            return false;
        }
        std::size_t offset = magic.size();
        std::uint32_t count = 0;
        if (!read_u64(bytes, offset, generation) ||
            !read_u32(bytes, offset, count) ||
            count > kMaximumSlots) {
            return false;
        }

        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint16_t id_size = 0;
            if (!read_u16(bytes, offset, id_size) ||
                id_size == 0 || id_size > kMaximumKeyIdBytes ||
                bytes.size() - offset < id_size) {
                return false;
            }
            std::string key_id(
                reinterpret_cast<const char*>(bytes.data() + offset), id_size);
            offset += id_size;
            std::uint32_t version = 0;
            if (!read_u32(bytes, offset, version) || version == 0 ||
                offset >= bytes.size()) {
                return false;
            }
            const std::uint8_t revoked = bytes[offset++];
            if (revoked > 1) return false;
            std::uint32_t wrapped_size = 0;
            if (!read_u32(bytes, offset, wrapped_size) ||
                wrapped_size > kMaximumWrappedBytes ||
                (revoked == 0 && wrapped_size == 0) ||
                (revoked != 0 && wrapped_size != 0) ||
                bytes.size() - offset < wrapped_size ||
                !valid_key_id(key_id)) {
                return false;
            }
            std::vector<std::uint8_t> wrapped(
                bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                bytes.begin() +
                    static_cast<std::ptrdiff_t>(offset + wrapped_size));
            offset += wrapped_size;
            if (!slots.emplace(
                    SlotKey{std::move(key_id), version},
                    Slot{std::move(wrapped), revoked != 0}).second) {
                return false;
            }
        }
        return offset == bytes.size();
    }

    static bool serialize(
        const SlotMap& slots,
        std::uint64_t generation,
        std::vector<std::uint8_t>& bytes
    ) {
        static constexpr std::array<std::uint8_t, 8> magic{{
            'M', 'H', 'K', 'W', 'S', '0', '0', '1'}};
        if (slots.size() > kMaximumSlots) return false;
        bytes.clear();
        bytes.insert(bytes.end(), magic.begin(), magic.end());
        append_u64(bytes, generation);
        append_u32(bytes, static_cast<std::uint32_t>(slots.size()));
        for (const auto& entry : slots) {
            const auto& key_id = entry.first.first;
            const auto version = entry.first.second;
            const auto& wrapped = entry.second.wrapped;
            if (!valid_key_id(key_id) || version == 0 ||
                wrapped.size() > kMaximumWrappedBytes ||
                (entry.second.revoked && !wrapped.empty()) ||
                (!entry.second.revoked && wrapped.empty()) ||
                key_id.size() > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            append_u16(bytes, static_cast<std::uint16_t>(key_id.size()));
            bytes.insert(bytes.end(), key_id.begin(), key_id.end());
            append_u32(bytes, version);
            bytes.push_back(entry.second.revoked ? 1U : 0U);
            append_u32(bytes, static_cast<std::uint32_t>(wrapped.size()));
            bytes.insert(bytes.end(), wrapped.begin(), wrapped.end());
            if (bytes.size() > kMaximumFileBytes) return false;
        }
        return bytes.size() <= kMaximumFileBytes;
    }

    bool read_store_file(
        std::vector<std::uint8_t>& bytes,
        bool& exists
    ) const {
        std::ifstream input(path_, std::ios::binary);
        if (!input) {
            std::error_code error;
            exists = std::filesystem::exists(path_, error);
            if (error || exists) return false;
            bytes.clear();
            return true;
        }

        exists = true;
        char buffer[8192];
        while (input) {
            input.read(buffer, sizeof(buffer));
            const std::streamsize received = input.gcount();
            if (received > 0) {
                const auto count = static_cast<std::size_t>(received);
                if (count > kMaximumFileBytes - bytes.size()) return false;
                bytes.insert(
                    bytes.end(),
                    reinterpret_cast<const std::uint8_t*>(buffer),
                    reinterpret_cast<const std::uint8_t*>(buffer) + count);
            }
        }
        return input.eof();
    }

    bool persist_candidate(
        const SlotMap& candidate,
        std::uint64_t expected_generation,
        std::uint64_t next_generation
    ) noexcept {
        std::filesystem::path temporary_path;
        bool has_temporary = false;
        bool anchor_advanced = false;
        try {
            std::vector<std::uint8_t> bytes;
            if (!serialize(candidate, next_generation, bytes) ||
                !write_temporary_file(bytes, temporary_path)) {
                return false;
            }
            has_temporary = true;
            if (anchor_ == nullptr ||
                !anchor_->advance(expected_generation, next_generation)) {
                failed_closed_ = true;
                remove_temporary_file(temporary_path);
                return false;
            }
            anchor_advanced = true;
            const AtomicReplaceResult replace_result =
                atomic_replace(temporary_path, path_);
            if (replace_result != AtomicReplaceResult::Replaced) {
                failed_closed_ = true;
                remove_temporary_file(temporary_path);
                return false;
            }
            has_temporary = false;
            return true;
        } catch (...) {
            if (anchor_advanced) failed_closed_ = true;
            if (has_temporary) remove_temporary_file(temporary_path);
            return false;
        }
    }

    PersistResult persist_candidate_file(
        const SlotMap& candidate,
        std::uint64_t next_generation
    ) noexcept {
        std::filesystem::path temporary_path;
        bool has_temporary = false;
        try {
            std::vector<std::uint8_t> bytes;
            if (!serialize(candidate, next_generation, bytes) ||
                !write_temporary_file(bytes, temporary_path)) {
                return PersistResult::NotReplaced;
            }
            has_temporary = true;

            const AtomicReplaceResult replace_result =
                atomic_replace(temporary_path, path_);
            if (replace_result == AtomicReplaceResult::NotReplaced) {
                remove_temporary_file(temporary_path);
                return PersistResult::NotReplaced;
            }
            has_temporary = false;
            if (replace_result == AtomicReplaceResult::ReplacedUnconfirmed) {
                mark_failed_closed();
                return PersistResult::ReplacedUnconfirmed;
            }
            return PersistResult::Persisted;
        } catch (...) {
            if (has_temporary) remove_temporary_file(temporary_path);
            return PersistResult::NotReplaced;
        }
    }

    static std::string random_suffix() {
        std::array<std::uint8_t, 12> random{};
        if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
            return {};
        }
        static constexpr char digits[] = "0123456789abcdef";
        std::string suffix;
        suffix.reserve(random.size() * 2);
        for (const std::uint8_t byte : random) {
            suffix.push_back(digits[byte >> 4U]);
            suffix.push_back(digits[byte & 0x0FU]);
        }
        OPENSSL_cleanse(random.data(), random.size());
        return suffix;
    }

    bool write_temporary_file(
        const std::vector<std::uint8_t>& bytes,
        std::filesystem::path& temporary_path
    ) const {
        for (unsigned attempt = 0; attempt < 16; ++attempt) {
            const std::string suffix = random_suffix();
            if (suffix.empty()) return false;
            temporary_path = path_;
            temporary_path += ".tmp-" + suffix;
#ifdef _WIN32
            HANDLE file = CreateFileW(
                temporary_path.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                if (GetLastError() == ERROR_FILE_EXISTS ||
                    GetLastError() == ERROR_ALREADY_EXISTS) {
                    continue;
                }
                return false;
            }
            bool ok = true;
            std::size_t offset = 0;
            while (offset < bytes.size()) {
                const DWORD request = static_cast<DWORD>((std::min)(
                    bytes.size() - offset,
                    static_cast<std::size_t>(
                        (std::numeric_limits<DWORD>::max)())));
                DWORD written = 0;
                if (!WriteFile(
                        file, bytes.data() + offset, request, &written, nullptr) ||
                    written == 0) {
                    ok = false;
                    break;
                }
                offset += written;
            }
            if (ok && !FlushFileBuffers(file)) ok = false;
            if (!CloseHandle(file)) ok = false;
            if (!ok) {
                remove_temporary_file(temporary_path);
                return false;
            }
            return true;
#else
            const int file = ::open(
                temporary_path.c_str(),
                O_WRONLY | O_CREAT | O_EXCL,
                S_IRUSR | S_IWUSR);
            if (file < 0) {
                if (errno == EEXIST) continue;
                return false;
            }
            bool ok = true;
            std::size_t offset = 0;
            while (offset < bytes.size()) {
                const ssize_t written = ::write(
                    file, bytes.data() + offset, bytes.size() - offset);
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) {
                    ok = false;
                    break;
                }
                offset += static_cast<std::size_t>(written);
            }
            if (ok && ::fsync(file) != 0) ok = false;
            if (::close(file) != 0) ok = false;
            if (!ok) {
                remove_temporary_file(temporary_path);
                return false;
            }
            return true;
#endif
        }
        return false;
    }

    static AtomicReplaceResult atomic_replace(
        const std::filesystem::path& temporary_path,
        const std::filesystem::path& destination
    ) noexcept {
#ifdef _WIN32
        return MoveFileExW(
                   temporary_path.c_str(),
                   destination.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0
            ? AtomicReplaceResult::Replaced
            : AtomicReplaceResult::NotReplaced;
#else
        try {
            std::filesystem::path parent = destination.parent_path();
            if (parent.empty()) parent = ".";
            if (::rename(temporary_path.c_str(), destination.c_str()) != 0) {
                return AtomicReplaceResult::NotReplaced;
            }
            const int directory = ::open(parent.c_str(), O_RDONLY);
            if (directory < 0) {
                return AtomicReplaceResult::ReplacedUnconfirmed;
            }
            const bool synced = ::fsync(directory) == 0;
            const bool closed = ::close(directory) == 0;
            return synced && closed
                ? AtomicReplaceResult::Replaced
                : AtomicReplaceResult::ReplacedUnconfirmed;
        } catch (...) {
            return AtomicReplaceResult::NotReplaced;
        }
#endif
    }

    static void remove_temporary_file(
        const std::filesystem::path& path
    ) noexcept {
        if (path.empty()) return;
#ifdef _WIN32
        DeleteFileW(path.c_str());
#else
        ::unlink(path.c_str());
#endif
    }

    void release_use(const SlotKey& key) const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto count = use_counts_.find(key);
            if (count != use_counts_.end() && count->second != 0) {
                --count->second;
                if (count->second == 0) use_counts_.erase(count);
            }
        } catch (...) {
        }
    }

    std::filesystem::path path_;
    const IContextBoundKeyEncryptionKeyProvider& kek_provider_;
    IMonotonicRevocationAnchor* anchor_;
    mutable std::mutex mutex_;
    SlotMap slots_;
    mutable std::map<SlotKey, std::size_t> use_counts_;
    std::uint64_t generation_{0};
    bool initialized_{false};
    mutable std::atomic<bool> failed_closed_{false};
};

}  // namespace mother_h::journal
