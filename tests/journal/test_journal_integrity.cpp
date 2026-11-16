#include "mother_H/journal/journal_integrity.hpp"

#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
using namespace mother_h::journal;

const JournalStorageIdentity kJournalStorage{
    "test-journal-backend", "journal-object-1", "journal-rollback-domain", true};

class MemoryKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        if (!available_) return KeyStatus::BackendUnavailable;
        const auto current = current_versions_.find(current_key_id_);
        if (current == current_versions_.end()) return KeyStatus::NotFound;
        return verification_key(
            KeyReference{current_key_id_, current->second}, out);
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (!available_) return KeyStatus::BackendUnavailable;
        const auto key_set = keys_.find(reference.key_id);
        if (key_set == keys_.end()) return KeyStatus::NotFound;
        const auto key = key_set->second.find(reference.version);
        if (key == key_set->second.end()) return KeyStatus::NotFound;
        if (key->second.revoked) return KeyStatus::Revoked;
        out = KeyMaterial(reference, std::vector<std::uint8_t>(key->second.secret));
        return KeyStatus::Ok;
    }

    KeyStatus rotate_key(
        const std::string& key_id,
        KeyReference& new_reference
    ) noexcept override {
        if (!available_) return KeyStatus::BackendUnavailable;
        if (key_id.empty()) return KeyStatus::InvalidRequest;
        const auto highest = highest_versions_.find(key_id);
        if (highest != highest_versions_.end() && highest->second == UINT32_MAX) {
            return KeyStatus::InvalidRequest;
        }
        const std::uint32_t version =
            highest == highest_versions_.end() ? 1U : highest->second + 1U;
        keys_[key_id][version] = Entry{make_secret(version), false};
        highest_versions_[key_id] = version;
        current_versions_[key_id] = version;
        current_key_id_ = key_id;
        new_reference = KeyReference{key_id, version};
        return KeyStatus::Ok;
    }

    KeyStatus revoke_key(const KeyReference& reference) noexcept override {
        if (!available_) return KeyStatus::BackendUnavailable;
        const auto key_set = keys_.find(reference.key_id);
        if (key_set == keys_.end()) return KeyStatus::NotFound;
        const auto key = key_set->second.find(reference.version);
        if (key == key_set->second.end()) return KeyStatus::NotFound;
        key->second.revoked = true;
        const auto current = current_versions_.find(reference.key_id);
        if (current != current_versions_.end() &&
            current->second == reference.version) {
            current_versions_.erase(current);
        }
        return KeyStatus::Ok;
    }

    void set_available(bool available) noexcept { available_ = available; }

private:
    struct Entry {
        std::vector<std::uint8_t> secret;
        bool revoked{false};
    };

    static std::vector<std::uint8_t> make_secret(std::uint32_t version) {
        return std::vector<std::uint8_t>(32, static_cast<std::uint8_t>(version));
    }

    bool available_{true};
    std::string current_key_id_;
    std::map<std::string, std::uint32_t> highest_versions_;
    std::map<std::string, std::uint32_t> current_versions_;
    std::map<std::string, std::map<std::uint32_t, Entry>> keys_;
};

class MemoryCheckpointStore final : public IJournalCheckpointStore {
public:
    CheckpointIsolation verify_independence(
        const JournalStorageIdentity& journal_storage
    ) const noexcept override {
        if (isolation_ != CheckpointIsolation::Independent) return isolation_;
        if (!journal_storage.verified ||
            (journal_storage.backend_id == checkpoint_backend_id_ &&
             journal_storage.object_id == checkpoint_object_id_)) {
            return CheckpointIsolation::SameStorage;
        }
        if (journal_storage.rollback_domain_id == checkpoint_rollback_domain_id_) {
            return CheckpointIsolation::SameRollbackDomain;
        }
        return CheckpointIsolation::Independent;
    }

    CheckpointStatus load(JournalCheckpoint& out) const noexcept override {
        if (!available_) return CheckpointStatus::BackendUnavailable;
        if (!initialized_) return CheckpointStatus::NotFound;
        out = checkpoint_;
        return CheckpointStatus::Ok;
    }

    CheckpointStatus compare_and_advance(
        const JournalCheckpoint& expected,
        const JournalCheckpoint& next
    ) noexcept override {
        if (!available_) return CheckpointStatus::BackendUnavailable;
        if (fail_update_ || !initialized_ ||
            expected.lsn != checkpoint_.lsn ||
            expected.record_hash != checkpoint_.record_hash ||
            expected.revision != checkpoint_.revision) {
            return CheckpointStatus::Conflict;
        }
        if (next.lsn <= expected.lsn ||
            expected.revision == UINT64_MAX ||
            next.revision != expected.revision + 1U) {
            return CheckpointStatus::Conflict;
        }
        checkpoint_ = next;
        return CheckpointStatus::Ok;
    }

    void initialize() noexcept {
        checkpoint_ = JournalCheckpoint{
            0, JournalIntegrity::genesis_hash(), 0};
        initialized_ = true;
    }

    void set_available(bool available) noexcept { available_ = available; }
    void set_fail_update(bool fail) noexcept { fail_update_ = fail; }
    void set_isolation(CheckpointIsolation isolation) noexcept {
        isolation_ = isolation;
    }
    const JournalCheckpoint& value() const noexcept { return checkpoint_; }

private:
    static constexpr const char* checkpoint_backend_id_ = "test-checkpoint-backend";
    static constexpr const char* checkpoint_object_id_ = "checkpoint-object-1";
    static constexpr const char* checkpoint_rollback_domain_id_ = "checkpoint-trust-domain";
    bool initialized_{false};
    bool available_{true};
    bool fail_update_{false};
    CheckpointIsolation isolation_{CheckpointIsolation::Independent};
    JournalCheckpoint checkpoint_{};
};

void check(bool condition) {
    assert(condition);
}

JournalRecord make_record(std::uint64_t lsn, std::string payload) {
    JournalRecord record;
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-04T02:59:31.214000000Z";
    record.payload = std::move(payload);
    return record;
}

}  // namespace

int main() {
    static_assert(!std::is_copy_constructible<KeyMaterial>::value,
                  "key material must not be copied");
    static_assert(std::is_nothrow_move_constructible<KeyMaterial>::value,
                  "key material must be safely movable");
    static_assert(std::is_nothrow_move_assignable<KeyMaterial>::value,
                  "key material must be safely move-assignable");

    KeyMaterial moved_key(
        KeyReference{"move-test", 1},
        std::vector<std::uint8_t>(32, 0xA5U));
    KeyMaterial move_target;
    move_target = std::move(moved_key);
    check(moved_key.secret().empty());
    check(move_target.secret().size() == 32);
    move_target.reset();
    check(move_target.secret().empty());
    check(move_target.reference().key_id.empty());

    MemoryKeyProvider keys;
    KeyReference key_v1;
    check(keys.rotate_key("journal-main", key_v1) == KeyStatus::Ok);
    check(key_v1.version == 1);

    const JournalHash genesis = JournalIntegrity::genesis_hash();
    JournalRecord first = make_record(1, "held event");
    const IntegrityResult first_sealed =
        JournalIntegrity::seal(first, 1, genesis, keys);
    check(static_cast<bool>(first_sealed));
    check(first.key == key_v1);

    JournalRecord deterministic = make_record(1, "held event");
    const IntegrityResult deterministic_sealed =
        JournalIntegrity::seal(deterministic, 1, genesis, keys);
    check(static_cast<bool>(deterministic_sealed));
    check(deterministic.hmac_sha256 == first.hmac_sha256);
    check(deterministic_sealed.record_hash == first_sealed.record_hash);

    KeyReference key_v2;
    check(keys.rotate_key("journal-main", key_v2) == KeyStatus::Ok);
    check(key_v2.version == 2);

    JournalRecord second = make_record(2, "ready event");
    const IntegrityResult second_sealed =
        JournalIntegrity::seal(second, 2, first_sealed.record_hash, keys);
    check(static_cast<bool>(second_sealed));
    check(second.key == key_v2);

    MemoryCheckpointStore checkpoints;
    checkpoints.initialize();
    const std::vector<JournalRecord> valid_chain{first, second};
    const IntegrityResult chain_result =
        JournalIntegrity::verify_chain_and_advance(
            valid_chain, keys, checkpoints, kJournalStorage);
    check(static_cast<bool>(chain_result));
    check(chain_result.record_hash == second_sealed.record_hash);
    check(checkpoints.value().lsn == 2);

    const IntegrityResult old_key_result =
        JournalIntegrity::verify(first, 1, genesis, keys);
    check(static_cast<bool>(old_key_result));

    JournalRecord changed_payload = first;
    changed_payload.payload[0] = 'H';
    check(JournalIntegrity::verify(changed_payload, 1, genesis, keys).status ==
          IntegrityStatus::HmacMismatch);

    JournalRecord changed_timestamp = first;
    changed_timestamp.timestamp_utc[3] = '7';
    check(JournalIntegrity::verify(changed_timestamp, 1, genesis, keys).status ==
          IntegrityStatus::HmacMismatch);

    JournalRecord changed_mac = first;
    changed_mac.hmac_sha256[0] ^= 0x01U;
    check(JournalIntegrity::verify(changed_mac, 1, genesis, keys).status ==
          IntegrityStatus::HmacMismatch);

    JournalRecord changed_lsn = first;
    changed_lsn.lsn = 2;
    check(JournalIntegrity::verify(changed_lsn, 1, genesis, keys).status ==
          IntegrityStatus::LsnOutOfOrder);

    JournalHash wrong_previous = genesis;
    wrong_previous[0] = 0x01U;
    check(JournalIntegrity::verify(first, 1, wrong_previous, keys).status ==
          IntegrityStatus::ChainMismatch);

    JournalRecord changed_key = first;
    changed_key.key.version = 99;
    check(JournalIntegrity::verify(changed_key, 1, genesis, keys).status ==
          IntegrityStatus::KeyUnavailable);

    const IntegrityResult reordered =
        JournalIntegrity::verify_chain_and_advance(
            {second, first}, keys, checkpoints, kJournalStorage);
    check(reordered.status == IntegrityStatus::LsnOutOfOrder);
    check(checkpoints.value().lsn == 2);

    const IntegrityResult rolled_back =
        JournalIntegrity::verify_chain_and_advance(
            {first}, keys, checkpoints, kJournalStorage);
    check(rolled_back.status == IntegrityStatus::RollbackDetected);
    check(checkpoints.value().lsn == 2);

    JournalRecord invalid_time = make_record(1, "bad time");
    invalid_time.timestamp_utc = "2026-02-29T02:59:31.214000000Z";
    check(JournalIntegrity::seal(invalid_time, 1, genesis, keys).status ==
          IntegrityStatus::InvalidTimestamp);
    check(JournalIntegrity::is_canonical_utc_timestamp(
        "2024-02-29T23:59:59.999999999Z"));
    check(!JournalIntegrity::is_canonical_utc_timestamp(
        "2026-02-29T23:59:59.999999999Z"));

    MemoryCheckpointStore missing_checkpoint;
    check(JournalIntegrity::verify_chain_and_advance(
              valid_chain, keys, missing_checkpoint, kJournalStorage).status ==
          IntegrityStatus::CheckpointUnavailable);

    MemoryCheckpointStore unavailable_checkpoint;
    unavailable_checkpoint.initialize();
    unavailable_checkpoint.set_available(false);
    check(JournalIntegrity::verify_chain_and_advance(
              valid_chain, keys, unavailable_checkpoint, kJournalStorage).status ==
          IntegrityStatus::CheckpointUnavailable);

    MemoryCheckpointStore failed_update;
    failed_update.initialize();
    failed_update.set_fail_update(true);
    check(JournalIntegrity::verify_chain_and_advance(
              valid_chain, keys, failed_update, kJournalStorage).status ==
          IntegrityStatus::CheckpointUpdateFailed);
    check(failed_update.value().lsn == 0);

    keys.set_available(false);
    check(JournalIntegrity::verify(first, 1, genesis, keys).status ==
          IntegrityStatus::KeyProviderUnavailable);
    JournalRecord provider_down = make_record(1, "provider down");
    check(JournalIntegrity::seal(provider_down, 1, genesis, keys).status ==
          IntegrityStatus::KeyProviderUnavailable);

    keys.set_available(true);
    check(keys.revoke_key(key_v1) == KeyStatus::Ok);
    check(JournalIntegrity::verify(first, 1, genesis, keys).status ==
          IntegrityStatus::KeyRevoked);
    check(JournalIntegrity::verify_chain_and_advance(
              valid_chain, keys, checkpoints, kJournalStorage).status ==
          IntegrityStatus::KeyRevoked);
    KeyReference key_v3;
    check(keys.rotate_key("journal-main", key_v3) == KeyStatus::Ok);
    check(key_v3.version == 3);

    MemoryCheckpointStore invalid_checkpoint;
    invalid_checkpoint.initialize();
    JournalCheckpoint corrupted_anchor = invalid_checkpoint.value();
    corrupted_anchor.record_hash[0] = 0xFFU;
    class InvalidAnchorStore final : public IJournalCheckpointStore {
    public:
        explicit InvalidAnchorStore(JournalCheckpoint value) : value_(value) {}
        CheckpointStatus load(JournalCheckpoint& out) const noexcept override {
            out = value_;
            return CheckpointStatus::Ok;
        }
        CheckpointIsolation verify_independence(
            const JournalStorageIdentity&
        ) const noexcept override {
            return CheckpointIsolation::Independent;
        }
        CheckpointStatus compare_and_advance(
            const JournalCheckpoint&,
            const JournalCheckpoint&
        ) noexcept override {
            return CheckpointStatus::Conflict;
        }
    private:
        JournalCheckpoint value_;
    } invalid_anchor(corrupted_anchor);
    check(JournalIntegrity::verify_chain_and_advance(
              {}, keys, invalid_anchor, kJournalStorage).status ==
          IntegrityStatus::CheckpointInvalid);

    return 0;
}
