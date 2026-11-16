#include "mother_H/journal/journal_integrity.hpp"

#include <cassert>
#include <string>
#include <vector>

namespace {
using namespace mother_h::journal;

class NoKeyProvider final : public ISecureKeyProvider {
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

class UnavailableCheckpointStore final : public IJournalCheckpointStore {
public:
    CheckpointIsolation verify_independence(
        const JournalStorageIdentity&
    ) const noexcept override {
        return CheckpointIsolation::BackendUnavailable;
    }

    CheckpointStatus load(JournalCheckpoint&) const noexcept override {
        ++load_calls;
        return CheckpointStatus::BackendUnavailable;
    }

    CheckpointStatus compare_and_advance(
        const JournalCheckpoint&,
        const JournalCheckpoint&
    ) noexcept override {
        ++advance_calls;
        return CheckpointStatus::BackendUnavailable;
    }

    mutable unsigned load_calls{0};
    unsigned advance_calls{0};
};

class UnverifiedCheckpointStore final : public IJournalCheckpointStore {
public:
    CheckpointStatus load(JournalCheckpoint&) const noexcept override {
        ++load_calls;
        return CheckpointStatus::Ok;
    }

    CheckpointStatus compare_and_advance(
        const JournalCheckpoint&,
        const JournalCheckpoint&
    ) noexcept override {
        ++advance_calls;
        return CheckpointStatus::Ok;
    }

    mutable unsigned load_calls{0};
    unsigned advance_calls{0};
};
}  // namespace

int main() {
    const std::vector<JournalRecord> no_records;
    const JournalStorageIdentity identity{
        "journal-backend", "journal-object", "journal-rollback-domain", true};
    NoKeyProvider no_keys;

    UnverifiedCheckpointStore unverified;
    const IntegrityResult unverified_result =
        JournalIntegrity::verify_chain_and_advance(
            no_records, no_keys, unverified, identity);
    assert(unverified_result.status ==
           IntegrityStatus::CheckpointIsolationUnverified);
    assert(unverified.load_calls == 0);
    assert(unverified.advance_calls == 0);

    UnavailableCheckpointStore unavailable;
    const IntegrityResult unavailable_result =
        JournalIntegrity::verify_chain_and_advance(
            no_records, no_keys, unavailable, identity);
    assert(unavailable_result.status == IntegrityStatus::CheckpointUnavailable);
    assert(unavailable.load_calls == 0);
    assert(unavailable.advance_calls == 0);
}
