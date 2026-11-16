#pragma once

#include "mother_H/journal/journal_integrity.hpp"

#include <cstdint>

namespace mother_h::journal {

enum class RecoveryStrategy {
    TruncateToLastValid,
    StrictAbort,
    QuarantineAndRecover
};

struct RecoveryContext {
    IntegrityStatus status{IntegrityStatus::Ok};
    std::uint32_t consecutive_failures{0};
    bool is_tail_partial{false};
    bool has_checkpoint_mismatch{false};
    // Set only by a trusted framing layer after confirming an incomplete tail.
    bool tail_is_confirmed_incomplete{false};
};

class JournalRecoveryPolicy {
public:
    // Pure decision function. It neither parses nor modifies journal storage;
    // only a trusted framing layer may set tail_is_confirmed_incomplete.
    RecoveryStrategy evaluate(const RecoveryContext& ctx) const noexcept {
        if (ctx.has_checkpoint_mismatch ||
            ctx.status == IntegrityStatus::HmacMismatch ||
            ctx.status == IntegrityStatus::ChainMismatch ||
            ctx.status == IntegrityStatus::RollbackDetected ||
            ctx.status == IntegrityStatus::CheckpointUnavailable ||
            ctx.status == IntegrityStatus::CheckpointIsolationUnverified ||
            ctx.status == IntegrityStatus::CheckpointSharesStorage ||
            ctx.status == IntegrityStatus::CheckpointSharesRollbackDomain ||
            ctx.status == IntegrityStatus::CheckpointInvalid ||
            ctx.status == IntegrityStatus::CheckpointUpdateFailed) {
            return RecoveryStrategy::StrictAbort;
        }

        if (ctx.is_tail_partial) {
            if (!ctx.tail_is_confirmed_incomplete ||
                ctx.status != IntegrityStatus::InvalidRecord) {
                return RecoveryStrategy::StrictAbort;
            }
            return ctx.consecutive_failures < 3
                ? RecoveryStrategy::TruncateToLastValid
                : RecoveryStrategy::QuarantineAndRecover;
        }

        if (ctx.status == IntegrityStatus::LsnOutOfOrder) {
            return ctx.consecutive_failures == 0
                ? RecoveryStrategy::QuarantineAndRecover
                : RecoveryStrategy::StrictAbort;
        }

        return RecoveryStrategy::StrictAbort;
    }
};

}  // namespace mother_h::journal
