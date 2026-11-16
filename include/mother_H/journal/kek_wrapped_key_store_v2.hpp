#pragma once

#include "mother_H/journal/kek_wrapped_key_store.hpp"
#include "mother_H/journal/monotonic_revocation_anchor_v2.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace mother_h::journal::v2 {

class KekWrappedDataEncryptionKeyStoreV2 final
    : public IDataEncryptionKeyProvider {
public:
    static constexpr std::size_t kMaximumSlots = 1024;
    static constexpr std::size_t kMaximumFileBytes = 8U * 1024U * 1024U;
    static constexpr std::size_t kMaximumWrappedBytes = 4096;

    KekWrappedDataEncryptionKeyStoreV2(
        std::filesystem::path store_path,
        const IContextBoundKeyEncryptionKeyProvider& kek,
        IMonotonicRevocationAnchorV2& anchor
    )
        : store_path_(std::move(store_path)), kek_(kek), anchor_(anchor) {}

    KeyStatus provision(
        std::uint64_t initial_counter,
        std::uint64_t initial_generation
    ) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return KeyStatus::InvalidRequest;
        try {
            std::error_code error;
            std::vector<std::uint8_t> image;
            SlotMap initial_slots;
            std::uint64_t stored_generation = initial_generation;
            if (std::filesystem::exists(store_path_, error)) {
                if (error || !read_file(store_path_, image) ||
                    !parse(image, initial_slots, stored_generation) ||
                    !initial_slots.empty() ||
                    stored_generation != initial_generation) {
                    return KeyStatus::BackendUnavailable;
                }
            } else {
                if (error || !serialize(
                        initial_slots, initial_generation, image) ||
                    !atomic_write(store_path_, image)) {
                    return KeyStatus::BackendUnavailable;
                }
            }
            Digest image_digest{};
            if (!digest_bytes(image, image_digest)) {
                return KeyStatus::BackendUnavailable;
            }
            AnchorStatus provisioned = anchor_.provision(
                initial_counter, initial_generation, image_digest);
            if (provisioned == AnchorStatus::AlreadyProvisioned) {
                provisioned = anchor_.recover();
                AnchorSnapshot existing{};
                if (provisioned == AnchorStatus::Ok) {
                    provisioned = anchor_.snapshot(existing);
                    if (provisioned == AnchorStatus::Ok &&
                        (existing.counter != initial_counter ||
                         existing.generation != initial_generation ||
                         existing.store_digest != image_digest)) {
                        provisioned = AnchorStatus::CounterMismatch;
                    }
                }
            }
            if (provisioned != AnchorStatus::Ok) {
                failed_closed_ = true;
                return KeyStatus::BackendUnavailable;
            }
            slots_.clear();
            generation_ = initial_generation;
            image_digest_ = image_digest;
            initialized_ = true;
            return KeyStatus::Ok;
        } catch (...) {
            failed_closed_ = true;
            return KeyStatus::BackendUnavailable;
        }
    }

    KeyStatus load() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return KeyStatus::InvalidRequest;
        try {
            const AnchorStatus recovery = anchor_.recover();
            if (recovery == AnchorStatus::Busy) {
                return KeyStatus::BackendUnavailable;
            }
            if (recovery != AnchorStatus::Ok) return fail_load();
            AnchorSnapshot snapshot{};
            const AnchorStatus snapshot_status = anchor_.snapshot(snapshot);
            if (snapshot_status == AnchorStatus::Busy) {
                return KeyStatus::BackendUnavailable;
            }
            if (snapshot_status != AnchorStatus::Ok) {
                return fail_load();
            }
            AnchorToken token = 0;
            const AnchorStatus lease_status = anchor_.acquire_usage(
                DataKeyReference{"v2-store-load", 1}, snapshot, token);
            if (lease_status == AnchorStatus::Busy) {
                return KeyStatus::BackendUnavailable;
            }
            if (lease_status != AnchorStatus::Ok || token == 0) {
                return fail_load();
            }
            SharedUse load_lease(this, token);
            std::vector<std::uint8_t> image;
            if (!read_file(store_path_, image)) {
                load_lease.release();
                return fail_load();
            }
            SlotMap loaded;
            std::uint64_t file_generation = 0;
            Digest file_digest{};
            if (!parse(image, loaded, file_generation) ||
                file_generation != snapshot.generation ||
                !digest_bytes(image, file_digest) ||
                file_digest != snapshot.store_digest) {
                load_lease.release();
                return fail_load();
            }
            if (!load_lease.release()) return fail_load();
            slots_.swap(loaded);
            generation_ = file_generation;
            image_digest_ = file_digest;
            initialized_ = true;
            return KeyStatus::Ok;
        } catch (...) {
            return fail_load();
        }
    }

    KeyStatus generate_key(
        const std::string& key_id,
        DataKeyReference& reference_out
    ) noexcept {
        if (!valid_key_id(key_id)) return KeyStatus::InvalidRequest;
        try {
            std::vector<std::uint8_t> plaintext(
                DataKeyMaterial::kAes256KeyBytes);
            VectorCleanser plaintext_cleanser(plaintext);
            if (RAND_bytes(plaintext.data(),
                           static_cast<int>(plaintext.size())) != 1) {
                return KeyStatus::BackendUnavailable;
            }

            std::lock_guard<std::mutex> lock(mutex_);
            if (!ready() || slots_.size() >= kMaximumSlots ||
                generation_ == (std::numeric_limits<std::uint64_t>::max)()) {
                return KeyStatus::BackendUnavailable;
            }
            std::uint32_t latest = 0;
            for (auto it = slots_.lower_bound({key_id, 0});
                 it != slots_.end() && it->first.first == key_id; ++it) {
                latest = (std::max)(latest, it->first.second);
            }
            if (latest == (std::numeric_limits<std::uint32_t>::max)()) {
                return KeyStatus::BackendUnavailable;
            }
            DataKeyReference reference{key_id, latest + 1U};
            std::vector<std::uint8_t> wrapped;
            VectorCleanser wrapped_cleanser(wrapped);
            const KeyStatus wrapping = kek_.wrap_dek(reference, plaintext, wrapped);
            if (wrapping != KeyStatus::Ok || wrapped.empty() ||
                wrapped.size() > kMaximumWrappedBytes) {
                return wrapping == KeyStatus::InvalidRequest
                    ? wrapping
                    : KeyStatus::BackendUnavailable;
            }

            SlotMap candidate = slots_;
            if (!candidate.emplace(
                    SlotKey{key_id, reference.version},
                    Slot{wrapped, false}).second) {
                return KeyStatus::BackendUnavailable;
            }
            return persist_update(
                       UpdateKind::Issue, reference, candidate, reference_out)
                ? KeyStatus::Ok
                : KeyStatus::BackendUnavailable;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

    // Calling revoke_key from this callback is unsupported; the held shared
    // lease makes the revocation request fail with BackendUnavailable.
    KeyStatus with_key(
        const DataKeyReference& reference,
        const KeyUseCallback& callback
    ) const noexcept override {
        if (!callback || !valid_reference(reference)) {
            return KeyStatus::InvalidRequest;
        }
        std::vector<std::uint8_t> wrapped;
        const SlotKey key{reference.key_id, reference.version};
        AnchorSnapshot snapshot{};
        try {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!ready()) return KeyStatus::BackendUnavailable;
                const auto found = slots_.find(key);
                if (found == slots_.end()) return KeyStatus::NotFound;
                if (found->second.revoked) return KeyStatus::Revoked;
                auto& active = use_counts_[key];
                if (active == (std::numeric_limits<std::size_t>::max)()) {
                    return KeyStatus::BackendUnavailable;
                }
                ++active;
                try {
                    wrapped = found->second.wrapped;
                } catch (...) {
                    --use_counts_[key];
                    return KeyStatus::BackendUnavailable;
                }
                const AnchorStatus snapshot_status =
                    anchor_.snapshot(snapshot);
                if (snapshot_status == AnchorStatus::Busy) {
                    --active;
                    return KeyStatus::BackendUnavailable;
                }
                if (snapshot_status != AnchorStatus::Ok ||
                    snapshot.generation != generation_ ||
                    snapshot.store_digest != image_digest_) {
                    --use_counts_[key];
                    failed_closed_ = true;
                    return KeyStatus::BackendUnavailable;
                }
            }
            ActiveUse local_use(this, key);
            AnchorToken token = 0;
            const AnchorStatus acquired =
                anchor_.acquire_usage(reference, snapshot, token);
            if (acquired != AnchorStatus::Ok || token == 0) {
                return KeyStatus::BackendUnavailable;
            }
            SharedUse shared_use(this, token);
            VectorCleanser wrapped_cleanser(wrapped);
            std::vector<std::uint8_t> plaintext;
            VectorCleanser plaintext_cleanser(plaintext);
            const KeyStatus unwrapped =
                kek_.unwrap_dek(reference, wrapped, plaintext);
            KeyStatus result = unwrapped;
            if (unwrapped == KeyStatus::Ok) {
                if (plaintext.size() != DataKeyMaterial::kAes256KeyBytes) {
                    result = KeyStatus::BackendUnavailable;
                } else {
                    DataKeyMaterial material(reference, std::move(plaintext));
                    const bool accepted = callback(material);
                    material.reset();
                    result = accepted ? KeyStatus::Ok : KeyStatus::InvalidRequest;
                }
            }
            return shared_use.release() ? result : KeyStatus::BackendUnavailable;
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
            const auto found = slots_.find(key);
            if (found == slots_.end()) return KeyStatus::NotFound;
            if (found->second.revoked) return KeyStatus::Revoked;
            const auto active = use_counts_.find(key);
            if (active != use_counts_.end() && active->second != 0) {
                return KeyStatus::BackendUnavailable;
            }
            SlotMap candidate = slots_;
            auto& target = candidate.find(key)->second;
            cleanse(target.wrapped);
            target.revoked = true;
            DataKeyReference ignored{};
            return persist_update(
                       UpdateKind::Revoke, reference, candidate, ignored)
                ? KeyStatus::Ok
                : KeyStatus::BackendUnavailable;
        } catch (...) {
            return KeyStatus::BackendUnavailable;
        }
    }

private:
    using SlotKey = std::pair<std::string, std::uint32_t>;
    struct Slot {
        std::vector<std::uint8_t> wrapped;
        bool revoked{false};
    };
    using SlotMap = std::map<SlotKey, Slot>;
    using Digest = FileMonotonicRevocationAnchorV2::Digest;

    struct VectorCleanser {
        explicit VectorCleanser(std::vector<std::uint8_t>& value) noexcept
            : value(value) {}
        ~VectorCleanser() { cleanse(value); }
        std::vector<std::uint8_t>& value;
    };

    struct ActiveUse {
        ActiveUse(const KekWrappedDataEncryptionKeyStoreV2* owner, SlotKey key)
            : owner(owner), key(std::move(key)) {}
        ~ActiveUse() { owner->release_local_use(key); }
        const KekWrappedDataEncryptionKeyStoreV2* owner;
        SlotKey key;
    };

    struct SharedUse {
        SharedUse(const KekWrappedDataEncryptionKeyStoreV2* owner,
                  AnchorToken token) noexcept
            : owner(owner), token(token) {}
        ~SharedUse() {
            if (active) release();
        }
        bool release() noexcept {
            if (!active) return true;
            const AnchorStatus status = owner->anchor_.release_usage(token);
            active = false;
            if (status != AnchorStatus::Ok) owner->failed_closed_ = true;
            return status == AnchorStatus::Ok;
        }
        const KekWrappedDataEncryptionKeyStoreV2* owner;
        AnchorToken token;
        bool active{true};
    };

    static void cleanse(std::vector<std::uint8_t>& value) noexcept {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
        value.clear();
    }

    static bool valid_key_id(const std::string& id) noexcept {
        if (id.empty() || id.size() > 128) return false;
        return std::all_of(id.begin(), id.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
        });
    }

    static bool valid_reference(const DataKeyReference& reference) noexcept {
        return valid_key_id(reference.key_id) && reference.version != 0;
    }

    bool ready() const noexcept {
        return initialized_ && !failed_closed_;
    }

    KeyStatus fail_load() noexcept {
        slots_.clear();
        generation_ = 0;
        initialized_ = false;
        failed_closed_ = true;
        return KeyStatus::BackendUnavailable;
    }

    bool persist_update(
        UpdateKind kind,
        const DataKeyReference& reference,
        const SlotMap& candidate,
        DataKeyReference& result
    ) noexcept {
        try {
            AnchorSnapshot expected{};
            const AnchorStatus snapshot_status =
                anchor_.snapshot(expected);
            if (snapshot_status == AnchorStatus::Busy) return false;
            if (snapshot_status != AnchorStatus::Ok ||
                expected.generation != generation_ ||
                expected.store_digest != image_digest_ ||
                generation_ == (std::numeric_limits<std::uint64_t>::max)()) {
                failed_closed_ = true;
                return false;
            }
            std::vector<std::uint8_t> image;
            if (!serialize(candidate, generation_ + 1U, image)) return false;
            Digest digest{};
            if (!digest_bytes(image, digest)) return false;
            AnchorToken token = 0;
            if (anchor_.prepare_update(
                    kind, reference, expected, digest, token) !=
                    AnchorStatus::Ok) {
                return false;
            }
            if (!atomic_write(store_path_, image)) {
                const AnchorStatus aborted = anchor_.abort_update(token);
                if (aborted != AnchorStatus::Ok) failed_closed_ = true;
                return false;
            }
            if (anchor_.commit_update(token) != AnchorStatus::Ok) {
                failed_closed_ = true;
                return false;
            }
            slots_ = candidate;
            ++generation_;
            image_digest_ = digest;
            if (kind == UpdateKind::Issue) result = reference;
            return true;
        } catch (...) {
            failed_closed_ = true;
            return false;
        }
    }

    void release_local_use(const SlotKey& key) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = use_counts_.find(key);
        if (found == use_counts_.end()) return;
        if (--found->second == 0) use_counts_.erase(found);
    }

    static void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v >> 8U));
        out.push_back(static_cast<std::uint8_t>(v));
    }
    static void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
        for (unsigned i = 0; i != 4; ++i)
            out.push_back(static_cast<std::uint8_t>(v >> (24U - 8U * i)));
    }
    static void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
        for (unsigned i = 0; i != 8; ++i)
            out.push_back(static_cast<std::uint8_t>(v >> (56U - 8U * i)));
    }
    static bool read_u16(
        const std::vector<std::uint8_t>& in, std::size_t& offset,
        std::uint16_t& value
    ) noexcept {
        if (in.size() - offset < 2) return false;
        value = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(in[offset]) << 8U) | in[offset + 1]);
        offset += 2;
        return true;
    }
    static bool read_u32(
        const std::vector<std::uint8_t>& in, std::size_t& offset,
        std::uint32_t& value
    ) noexcept {
        if (in.size() - offset < 4) return false;
        value = (static_cast<std::uint32_t>(in[offset]) << 24U) |
            (static_cast<std::uint32_t>(in[offset + 1]) << 16U) |
            (static_cast<std::uint32_t>(in[offset + 2]) << 8U) | in[offset + 3];
        offset += 4;
        return true;
    }
    static bool read_u64(
        const std::vector<std::uint8_t>& in, std::size_t& offset,
        std::uint64_t& value
    ) noexcept {
        if (in.size() - offset < 8) return false;
        value = 0;
        for (unsigned i = 0; i != 8; ++i)
            value = (value << 8U) | in[offset++];
        return true;
    }

    static bool serialize(
        const SlotMap& slots,
        std::uint64_t generation,
        std::vector<std::uint8_t>& output
    ) {
        if (slots.size() > kMaximumSlots) return false;
        output = {'M','H','K','W','V','2','0','1'};
        append_u64(output, generation);
        append_u32(output, static_cast<std::uint32_t>(slots.size()));
        for (const auto& entry : slots) {
            const auto& id = entry.first.first;
            const auto& wrapped = entry.second.wrapped;
            if (!valid_key_id(id) || entry.first.second == 0 ||
                id.size() > (std::numeric_limits<std::uint16_t>::max)() ||
                wrapped.size() > kMaximumWrappedBytes ||
                (entry.second.revoked && !wrapped.empty()) ||
                (!entry.second.revoked && wrapped.empty())) return false;
            append_u16(output, static_cast<std::uint16_t>(id.size()));
            output.insert(output.end(), id.begin(), id.end());
            append_u32(output, entry.first.second);
            output.push_back(entry.second.revoked ? 1U : 0U);
            append_u32(output, static_cast<std::uint32_t>(wrapped.size()));
            output.insert(output.end(), wrapped.begin(), wrapped.end());
            if (output.size() > kMaximumFileBytes) return false;
        }
        return true;
    }

    static bool parse(
        const std::vector<std::uint8_t>& input,
        SlotMap& slots,
        std::uint64_t& generation
    ) {
        static constexpr std::array<std::uint8_t, 8> magic{{
            'M','H','K','W','V','2','0','1'}};
        if (input.size() < 20 || input.size() > kMaximumFileBytes ||
            !std::equal(magic.begin(), magic.end(), input.begin())) return false;
        std::size_t offset = 8;
        std::uint32_t count = 0;
        if (!read_u64(input, offset, generation) ||
            !read_u32(input, offset, count) || count > kMaximumSlots) return false;
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint16_t id_size = 0;
            if (!read_u16(input, offset, id_size) || id_size == 0 ||
                id_size > 128 || input.size() - offset < id_size) return false;
            std::string id(reinterpret_cast<const char*>(input.data() + offset),
                           id_size);
            offset += id_size;
            std::uint32_t version = 0;
            if (!read_u32(input, offset, version) || version == 0 ||
                offset >= input.size()) return false;
            const auto revoked = input[offset++];
            std::uint32_t wrapped_size = 0;
            if (revoked > 1 || !read_u32(input, offset, wrapped_size) ||
                wrapped_size > kMaximumWrappedBytes ||
                (revoked == 0 && wrapped_size == 0) ||
                (revoked != 0 && wrapped_size != 0) ||
                input.size() - offset < wrapped_size || !valid_key_id(id)) {
                return false;
            }
            std::vector<std::uint8_t> wrapped(
                input.begin() + static_cast<std::ptrdiff_t>(offset),
                input.begin() + static_cast<std::ptrdiff_t>(
                    offset + wrapped_size));
            offset += wrapped_size;
            if (!slots.emplace(
                    SlotKey{id, version}, Slot{std::move(wrapped), revoked != 0})
                     .second) return false;
        }
        return offset == input.size();
    }

    static bool digest_bytes(
        const std::vector<std::uint8_t>& input,
        Digest& output
    ) noexcept {
        unsigned int written = 0;
        return EVP_Digest(input.data(), input.size(), output.data(), &written,
                          EVP_sha256(), nullptr) == 1 &&
            written == output.size();
    }

    static bool read_file(
        const std::filesystem::path& path,
        std::vector<std::uint8_t>& output
    ) {
        std::ifstream input(path, std::ios::binary);
        if (!input) return false;
        char buffer[8192];
        while (input) {
            input.read(buffer, sizeof(buffer));
            const auto received = input.gcount();
            if (received > 0) {
                const auto count = static_cast<std::size_t>(received);
                if (count > kMaximumFileBytes - output.size()) return false;
                output.insert(output.end(),
                    reinterpret_cast<const std::uint8_t*>(buffer),
                    reinterpret_cast<const std::uint8_t*>(buffer) + count);
            }
        }
        return input.eof();
    }

    static bool atomic_write(
        const std::filesystem::path& destination,
        const std::vector<std::uint8_t>& bytes
    ) noexcept {
        try {
            std::array<std::uint8_t, 8> random{};
            if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
                return false;
            static constexpr char hex[] = "0123456789abcdef";
            std::string suffix;
            for (const auto value : random) {
                suffix.push_back(hex[value >> 4U]);
                suffix.push_back(hex[value & 0x0FU]);
            }
            auto temporary = destination;
            temporary += ".tmp-" + suffix;
#ifdef _WIN32
            HANDLE file = CreateFileW(
                temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) return false;
            std::size_t offset = 0;
            bool ok = true;
            while (offset < bytes.size()) {
                DWORD written = 0;
                const DWORD request = static_cast<DWORD>((std::min)(
                    bytes.size() - offset,
                    static_cast<std::size_t>(
                        (std::numeric_limits<DWORD>::max)())));
                if (!WriteFile(file, bytes.data() + offset, request, &written,
                               nullptr) || written == 0) {
                    ok = false;
                    break;
                }
                offset += written;
            }
            if (ok && !FlushFileBuffers(file)) ok = false;
            const bool closed = CloseHandle(file) != 0;
            if (!ok || !closed || !MoveFileExW(
                    temporary.c_str(), destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(temporary.c_str());
                return false;
            }
            return true;
#else
            const int file = ::open(
                temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL,
                S_IRUSR | S_IWUSR);
            if (file < 0) return false;
            std::size_t offset = 0;
            bool ok = true;
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
            const bool closed = ::close(file) == 0;
            if (!ok || !closed ||
                ::rename(temporary.c_str(), destination.c_str()) != 0) {
                ::unlink(temporary.c_str());
                return false;
            }
            auto parent = destination.parent_path();
            if (parent.empty()) parent = ".";
            const int directory = ::open(parent.c_str(), O_RDONLY);
            if (directory < 0) return false;
            const bool synced = ::fsync(directory) == 0;
            const bool dir_closed = ::close(directory) == 0;
            return synced && dir_closed;
#endif
        } catch (...) {
            return false;
        }
    }

    std::filesystem::path store_path_;
    const IContextBoundKeyEncryptionKeyProvider& kek_;
    IMonotonicRevocationAnchorV2& anchor_;
    mutable std::mutex mutex_;
    SlotMap slots_;
    mutable std::map<SlotKey, std::size_t> use_counts_;
    std::uint64_t generation_{0};
    Digest image_digest_{};
    bool initialized_{false};
    mutable std::atomic<bool> failed_closed_{false};
};

}  // namespace mother_h::journal::v2
