#pragma once

#include "mother_H/fsm/fsm_engine.hpp"
#include "mother_H/integration/event_journal.hpp"
#include "mother_H/integration/fsm_journal_recovery.hpp"

#include <limits>
#include <mutex>
#include <utility>
#include <vector>

namespace mother_h::integration {

class IRecoverableJournalRecordSink : public mb::H::IJournalRecordSink {
public:
    virtual bool read_records(
        std::vector<mother_h::journal::JournalRecord>& out
    ) const noexcept = 0;
};

enum class FsmJournalCommitStatus : std::uint8_t {
    Ok,
    InvalidEvent,
    LimitExceeded,
    JournalFailure,
    JournalCommittedNeedsRecovery,
    RecoveryRequired,
    RecoveryFailure,
    InternalError
};

class FsmJournalCoordinator {
public:
    FsmJournalCoordinator(
        mb::H::AuthenticatedEventJournal& journal,
        IRecoverableJournalRecordSink& sink,
        const mother_h::journal::ISecureKeyProvider& keys,
        mother_h::fsm::FsmEngine& engine
    ) noexcept
        : journal_(journal), sink_(sink), keys_(keys), engine_(engine) {}

    FsmJournalCommitStatus append(
        const mb::cqs13_4::EventPayload& event
    ) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (recovery_required_) return FsmJournalCommitStatus::RecoveryRequired;

            const std::uint64_t lsn = journal_.next_lsn();
            mother_h::fsm::FsmEngine staged(engine_.limits());
            const auto prior_history = engine_.history();
            if (staged.rebuild_from_verified_history(prior_history) !=
                mother_h::fsm::FsmStatus::Ok) {
                recovery_required_ = true;
                return FsmJournalCommitStatus::RecoveryRequired;
            }
            const mother_h::fsm::FsmRecord candidate = make_record(event, lsn);
            const auto validation = staged.apply(candidate);
            if (validation == mother_h::fsm::FsmStatus::LimitExceeded) {
                return FsmJournalCommitStatus::LimitExceeded;
            }
            if (validation == mother_h::fsm::FsmStatus::InternalError) {
                return FsmJournalCommitStatus::InternalError;
            }
            if (validation != mother_h::fsm::FsmStatus::Ok) {
                return FsmJournalCommitStatus::InvalidEvent;
            }

            const auto stored = journal_.append(event);
            if (!stored) {
                recovery_required_ = true;
                return FsmJournalCommitStatus::JournalFailure;
            }
            if (stored.lsn != lsn) {
                recovery_required_ = true;
                return FsmJournalCommitStatus::JournalCommittedNeedsRecovery;
            }

            const auto applied = engine_.apply(candidate);
            if (applied != mother_h::fsm::FsmStatus::Ok) {
                recovery_required_ = true;
                return FsmJournalCommitStatus::JournalCommittedNeedsRecovery;
            }
            return FsmJournalCommitStatus::Ok;
        } catch (...) {
            return FsmJournalCommitStatus::InternalError;
        }
    }

    FsmJournalCommitStatus recover() noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            recovery_required_ = true;
            std::vector<mother_h::journal::JournalRecord> records;
            if (!sink_.read_records(records)) {
                return FsmJournalCommitStatus::RecoveryFailure;
            }

            const auto result = FsmJournalRecovery::rebuild(records, keys_, engine_);
            if (result != FsmJournalRecoveryStatus::Ok) {
                return FsmJournalCommitStatus::RecoveryFailure;
            }

            const std::uint64_t expected_next_lsn =
                records.empty() ? 1 :
                (records.back().lsn == (std::numeric_limits<std::uint64_t>::max)()
                    ? records.back().lsn
                    : records.back().lsn + 1);
            if (journal_.next_lsn() == 1) {
                if (!journal_.resume_from_records(records)) {
                    return FsmJournalCommitStatus::RecoveryFailure;
                }
            } else if (journal_.next_lsn() != expected_next_lsn) {
                return FsmJournalCommitStatus::RecoveryFailure;
            }

            recovery_required_ = false;
            return FsmJournalCommitStatus::Ok;
        } catch (...) {
            return FsmJournalCommitStatus::InternalError;
        }
    }

    bool recovery_required() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return recovery_required_;
    }

private:
    static mother_h::fsm::FsmRecord make_record(
        const mb::cqs13_4::EventPayload& event,
        std::uint64_t lsn
    ) {
        mother_h::fsm::FsmRecord record;
        record.event_id = event.event_id;
        record.request_id = event.request_id;
        record.event_type = mother_h::fsm::EventType::Generic;
        record.lsn = lsn;
        record.parent_event_id = event.parent_event_id;
        switch (event.state) {
            case mb::cqs13_4::EventState::HELD:
                record.state = mother_h::fsm::FsmState::Held;
                break;
            case mb::cqs13_4::EventState::READY:
                record.state = mother_h::fsm::FsmState::Ready;
                break;
            case mb::cqs13_4::EventState::PROCESSED:
                record.state = mother_h::fsm::FsmState::Processed;
                break;
            case mb::cqs13_4::EventState::FAILED:
                record.state = mother_h::fsm::FsmState::Failed;
                break;
            case mb::cqs13_4::EventState::CANCELLED:
                record.state = mother_h::fsm::FsmState::Cancelled;
                break;
            case mb::cqs13_4::EventState::NONE:
            case mb::cqs13_4::EventState::UNKNOWN:
            default:
                record.state = mother_h::fsm::FsmState::Unknown;
                break;
        }
        return record;
    }

    mb::H::AuthenticatedEventJournal& journal_;
    IRecoverableJournalRecordSink& sink_;
    const mother_h::journal::ISecureKeyProvider& keys_;
    mother_h::fsm::FsmEngine& engine_;
    mutable std::mutex mutex_;
    bool recovery_required_{true};
};

}  // namespace mother_h::integration
