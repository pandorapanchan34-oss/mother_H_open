#include <cassert>
#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

#include "mother_H/journal/journal_integrity.hpp"

namespace {
using namespace mother_h::journal;

class UnusedKeyProvider final : public ISecureKeyProvider {
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

    KeyStatus rotate_key(
        const std::string&,
        KeyReference&
    ) noexcept override {
        return KeyStatus::BackendUnavailable;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::BackendUnavailable;
    }
};

class CountingCheckpointStore final : public IJournalCheckpointStore {
public:
    explicit CountingCheckpointStore(CheckpointIsolation isolation)
        : isolation_(isolation) {}

    CheckpointIsolation verify_independence(
        const JournalStorageIdentity&
    ) const noexcept override {
        ++verify_calls;
        return isolation_;
    }

    CheckpointStatus load(JournalCheckpoint& out) const noexcept override {
        ++load_calls;
        out = {};
        return CheckpointStatus::Ok;
    }

    CheckpointStatus compare_and_advance(
        const JournalCheckpoint&,
        const JournalCheckpoint&
    ) noexcept override {
        ++advance_calls;
        return CheckpointStatus::Ok;
    }

    mutable std::size_t verify_calls{0};
    mutable std::size_t load_calls{0};
    std::size_t advance_calls{0};

private:
    CheckpointIsolation isolation_;
};

void assert_checkpoint_io_not_called(
    const CountingCheckpointStore& store
) {
    assert(store.load_calls == 0);
    assert(store.advance_calls == 0);
}
}  // namespace

int main() {
    const std::vector<JournalRecord> empty_chain;
    UnusedKeyProvider keys;
    const JournalStorageIdentity verified_identity{
        "test-backend", "journal-object", "rollback-domain", true};

    {
        CountingCheckpointStore store(CheckpointIsolation::SameStorage);
        const IntegrityResult result =
            JournalIntegrity::verify_chain_and_advance(
                empty_chain, keys, store, verified_identity);

        assert(result.status == IntegrityStatus::CheckpointSharesStorage);
        assert(store.verify_calls == 1);
        assert_checkpoint_io_not_called(store);
        std::cout << "[PASS] CP-06-03 SameStorage rejected before checkpoint I/O\n";
    }

    {
        CountingCheckpointStore store(
            CheckpointIsolation::SameRollbackDomain);
        const IntegrityResult result =
            JournalIntegrity::verify_chain_and_advance(
                empty_chain, keys, store, verified_identity);

        assert(result.status ==
               IntegrityStatus::CheckpointSharesRollbackDomain);
        assert(store.verify_calls == 1);
        assert_checkpoint_io_not_called(store);
        std::cout << "[PASS] CP-06-04 SameRollbackDomain rejected before checkpoint I/O\n";
    }

    {
        CountingCheckpointStore store(CheckpointIsolation::Independent);
        const JournalStorageIdentity unverified_identity{
            "test-backend", "journal-object", "rollback-domain", false};
        const IntegrityResult result =
            JournalIntegrity::verify_chain_and_advance(
                empty_chain, keys, store, unverified_identity);

        assert(result.status == IntegrityStatus::CheckpointIsolationUnverified);
        assert(store.verify_calls == 0);
        assert_checkpoint_io_not_called(store);
        std::cout << "[PASS] CP-06-05 Unverified identity rejected before verification\n";
    }

    std::cout << "[RESULT] All checkpoint isolation rejection tests passed\n";
    return 0;
}
