#pragma once

#include "mother_H/fsm/fsm_engine.hpp"
#include "mother_H/integration/event_journal.hpp"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace mother_h::integration {

enum class FsmJournalRecoveryStatus : std::uint8_t {
    Ok,
    IntegrityFailure,
    InvalidEvent,
    InvalidHistory,
    LimitExceeded,
    InternalError
};

struct FsmRecoveryReport {
    std::size_t total_records{0};
    std::vector<std::uint64_t> cryptographically_erased_lsns;
};

class FsmJournalRecovery {
public:
    static FsmJournalRecoveryStatus rebuild(
        const std::vector<mother_h::journal::JournalRecord>& records,
        const mother_h::journal::ISecureKeyProvider& keys,
        const mother_h::journal::IDataEncryptionKeyProvider* dek_provider,
        mother_h::fsm::FsmEngine& engine,
        FsmRecoveryReport* report = nullptr
    ) noexcept {
        try {
            std::vector<mb::cqs13_4::EventPayload> events;
            std::vector<bool> erased_flags;
            mother_h::journal::IntegrityStatus integrity_status{};
            if (!mb::H::AuthenticatedEventJournal::verify_records(
                    records, keys, dek_provider, events, erased_flags, integrity_status)) {
                return FsmJournalRecoveryStatus::IntegrityFailure;
            }
            if (events.size() != records.size() ||
                erased_flags.size() != records.size()) {
                return FsmJournalRecoveryStatus::InternalError;
            }

            std::vector<mother_h::fsm::FsmRecord> history;
            std::vector<std::uint64_t> erased_lsns;
            history.reserve(events.size());
            for (std::size_t i = 0; i < events.size(); ++i) {
                if (erased_flags[i]) erased_lsns.push_back(records[i].lsn);
                mother_h::fsm::FsmRecord record;
                record.event_id = events[i].event_id;
                record.request_id = events[i].request_id;
                record.event_type = mother_h::fsm::EventType::Generic;
                record.state = to_fsm_state(events[i].state);
                record.lsn = records[i].lsn;
                record.parent_event_id = events[i].parent_event_id;
                if (record.state == mother_h::fsm::FsmState::Unknown) {
                    return FsmJournalRecoveryStatus::InvalidEvent;
                }
                history.push_back(std::move(record));
            }

            const auto status = engine.rebuild_from_verified_history(history);
            switch (status) {
            case mother_h::fsm::FsmStatus::Ok:
                if (report != nullptr) {
                    report->total_records = records.size();
                    report->cryptographically_erased_lsns = std::move(erased_lsns);
                }
                return FsmJournalRecoveryStatus::Ok;
            case mother_h::fsm::FsmStatus::LimitExceeded:
                return FsmJournalRecoveryStatus::LimitExceeded;
            case mother_h::fsm::FsmStatus::InvalidHistory:
            case mother_h::fsm::FsmStatus::InvalidInput:
            case mother_h::fsm::FsmStatus::InvalidTransition:
            case mother_h::fsm::FsmStatus::ParentInvalid:
            case mother_h::fsm::FsmStatus::DuplicateEvent:
            case mother_h::fsm::FsmStatus::LsnOutOfOrder:
                return FsmJournalRecoveryStatus::InvalidHistory;
            case mother_h::fsm::FsmStatus::InternalError:
            default:
                return FsmJournalRecoveryStatus::InternalError;
            }
        } catch (...) {
            return FsmJournalRecoveryStatus::InternalError;
        }
    }

    static FsmJournalRecoveryStatus rebuild(
        const std::vector<mother_h::journal::JournalRecord>& records,
        const mother_h::journal::ISecureKeyProvider& keys,
        mother_h::fsm::FsmEngine& engine
    ) noexcept {
        try {
            std::vector<mb::cqs13_4::EventPayload> events;
            mother_h::journal::IntegrityStatus integrity_status{};
            if (!mb::H::AuthenticatedEventJournal::verify_records(
                    records, keys, events, integrity_status)) {
                return FsmJournalRecoveryStatus::IntegrityFailure;
            }
            if (events.size() != records.size()) {
                return FsmJournalRecoveryStatus::InternalError;
            }

            std::vector<mother_h::fsm::FsmRecord> history;
            history.reserve(events.size());
            for (std::size_t i = 0; i < events.size(); ++i) {
                mother_h::fsm::FsmRecord record;
                record.event_id = events[i].event_id;
                record.request_id = events[i].request_id;
                record.event_type = mother_h::fsm::EventType::Generic;
                record.state = to_fsm_state(events[i].state);
                record.lsn = records[i].lsn;
                record.parent_event_id = events[i].parent_event_id;
                if (record.state == mother_h::fsm::FsmState::Unknown) {
                    return FsmJournalRecoveryStatus::InvalidEvent;
                }
                history.push_back(std::move(record));
            }

            const auto status = engine.rebuild_from_verified_history(history);
            switch (status) {
                case mother_h::fsm::FsmStatus::Ok:
                    return FsmJournalRecoveryStatus::Ok;
                case mother_h::fsm::FsmStatus::LimitExceeded:
                    return FsmJournalRecoveryStatus::LimitExceeded;
                case mother_h::fsm::FsmStatus::InvalidHistory:
                case mother_h::fsm::FsmStatus::InvalidInput:
                case mother_h::fsm::FsmStatus::InvalidTransition:
                case mother_h::fsm::FsmStatus::ParentInvalid:
                case mother_h::fsm::FsmStatus::DuplicateEvent:
                case mother_h::fsm::FsmStatus::LsnOutOfOrder:
                    return FsmJournalRecoveryStatus::InvalidHistory;
                case mother_h::fsm::FsmStatus::InternalError:
                default:
                    return FsmJournalRecoveryStatus::InternalError;
            }
        } catch (...) {
            return FsmJournalRecoveryStatus::InternalError;
        }
    }

private:
    static mother_h::fsm::FsmState to_fsm_state(
        mb::cqs13_4::EventState state
    ) noexcept {
        switch (state) {
            case mb::cqs13_4::EventState::HELD:
                return mother_h::fsm::FsmState::Held;
            case mb::cqs13_4::EventState::READY:
                return mother_h::fsm::FsmState::Ready;
            case mb::cqs13_4::EventState::PROCESSED:
                return mother_h::fsm::FsmState::Processed;
            case mb::cqs13_4::EventState::FAILED:
                return mother_h::fsm::FsmState::Failed;
            case mb::cqs13_4::EventState::CANCELLED:
                return mother_h::fsm::FsmState::Cancelled;
            case mb::cqs13_4::EventState::NONE:
            case mb::cqs13_4::EventState::UNKNOWN:
            default:
                return mother_h::fsm::FsmState::Unknown;
        }
    }
};

}  // namespace mother_h::integration
