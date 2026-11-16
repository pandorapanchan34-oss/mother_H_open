#include "mother_H/journal/journal_integrity.hpp"

#include <cassert>
#include <cstdint>
#include <string>

namespace {
using namespace mother_h::journal;

class UnavailableKeys final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial&) const noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus verification_key(
        const KeyReference&,
        KeyMaterial&
    ) const noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
};

class TestCheckpointStore final : public IJournalCheckpointStore {
public:
    explicit TestCheckpointStore(CheckpointIsolation isolation)
        : isolation_(isolation) {}

    CheckpointIsolation verify_independence(
        const JournalStorageIdentity& journal_storage
    ) const noexcept override {
        ++isolation_checks_;
        if (!journal_storage.verified) return CheckpointIsolation::Unverified;
        return isolation_;
    }

    CheckpointStatus load(JournalCheckpoint& out) const noexcept override {
        ++load_calls_;
        if (!available_) return CheckpointStatus::BackendUnavailable;
        out = JournalCheckpoint{0, JournalIntegrity::genesis_hash(), 0};
        return CheckpointStatus::Ok;
    }

    CheckpointStatus compare_and_advance(
        const JournalCheckpoint&,
        const JournalCheckpoint&
    ) noexcept override {
        return CheckpointStatus::BackendUnavailable;
    }

    mutable std::size_t isolation_checks_{0};
    mutable std::size_t load_calls_{0};

private:
    CheckpointIsolation isolation_;
    bool available_{true};
};

void check(bool condition) {
    assert(condition);
}

}  // namespace

int main() {
    UnavailableKeys keys;
    const std::vector<JournalRecord> no_records;
    const JournalStorageIdentity verified_journal{
        "filesystem", "device-1:inode-10", "snapshot-domain-1", true};

    TestCheckpointStore no_identity(CheckpointIsolation::Independent);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, no_identity).status ==
          IntegrityStatus::CheckpointIsolationUnverified);
    check(no_identity.isolation_checks_ == 0);
    check(no_identity.load_calls_ == 0);

    TestCheckpointStore unverified(CheckpointIsolation::Unverified);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, unverified, verified_journal).status ==
          IntegrityStatus::CheckpointIsolationUnverified);
    check(unverified.load_calls_ == 0);

    TestCheckpointStore same_object(CheckpointIsolation::SameStorage);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, same_object, verified_journal).status ==
          IntegrityStatus::CheckpointSharesStorage);
    check(same_object.load_calls_ == 0);

    // A trusted backend must resolve aliases to canonical object identities.
    // Distinct path spellings for a hardlink/symlink still report SameStorage.
    const JournalStorageIdentity hardlink_alias{
        "filesystem", "device-1:inode-10", "snapshot-domain-1", true};
    TestCheckpointStore same_alias(CheckpointIsolation::SameStorage);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, same_alias, hardlink_alias).status ==
          IntegrityStatus::CheckpointSharesStorage);
    check(same_alias.load_calls_ == 0);

    TestCheckpointStore same_domain(CheckpointIsolation::SameRollbackDomain);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, same_domain, verified_journal).status ==
          IntegrityStatus::CheckpointSharesRollbackDomain);
    check(same_domain.load_calls_ == 0);

    TestCheckpointStore backend_missing(CheckpointIsolation::BackendUnavailable);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, backend_missing, verified_journal).status ==
          IntegrityStatus::CheckpointUnavailable);
    check(backend_missing.load_calls_ == 0);

    TestCheckpointStore independent(CheckpointIsolation::Independent);
    check(JournalIntegrity::verify_chain_and_advance(
              no_records, keys, independent, JournalStorageIdentity{}).status ==
          IntegrityStatus::CheckpointIsolationUnverified);
    check(independent.isolation_checks_ == 0);
    check(independent.load_calls_ == 0);

    return 0;
}
