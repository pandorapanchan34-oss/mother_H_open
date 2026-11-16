#include "mother_H/journal/journal_recovery_policy.hpp"

#include <cassert>

namespace {
using namespace mother_h::journal;

void check(RecoveryStrategy actual, RecoveryStrategy expected) {
    assert(actual == expected);
}
}  // namespace

int main() {
    const JournalRecoveryPolicy policy;

    check(policy.evaluate({IntegrityStatus::HmacMismatch}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::ChainMismatch}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::RollbackDetected}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::CheckpointSharesStorage}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::CheckpointSharesRollbackDomain}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::CheckpointInvalid}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::CheckpointUnavailable, 0, true}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::CheckpointIsolationUnverified}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::CheckpointUpdateFailed}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::HmacMismatch, 0, true}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::ChainMismatch, 0, true}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::Ok, 0, true, true}),
          RecoveryStrategy::StrictAbort);

    check(policy.evaluate({IntegrityStatus::InvalidRecord, 0, true, false}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::InvalidRecord, 0, true, false, true}),
          RecoveryStrategy::TruncateToLastValid);
    check(policy.evaluate({IntegrityStatus::InvalidRecord, 1, true, false, true}),
          RecoveryStrategy::TruncateToLastValid);
    check(policy.evaluate({IntegrityStatus::InvalidRecord, 2, true, false, true}),
          RecoveryStrategy::TruncateToLastValid);
    check(policy.evaluate({IntegrityStatus::InvalidRecord, 3, true, false, true}),
          RecoveryStrategy::QuarantineAndRecover);
    check(policy.evaluate({IntegrityStatus::InvalidRecord, 4, true, false, true}),
          RecoveryStrategy::QuarantineAndRecover);
    check(policy.evaluate({IntegrityStatus::KeyProviderUnavailable, 0, true, false, true}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::KeyRevoked, 0, true, false, true}),
          RecoveryStrategy::StrictAbort);

    check(policy.evaluate({IntegrityStatus::LsnOutOfOrder}),
          RecoveryStrategy::QuarantineAndRecover);
    check(policy.evaluate({IntegrityStatus::LsnOutOfOrder, 1}),
          RecoveryStrategy::StrictAbort);
    check(policy.evaluate({IntegrityStatus::Ok}),
          RecoveryStrategy::StrictAbort);

    return 0;
}
