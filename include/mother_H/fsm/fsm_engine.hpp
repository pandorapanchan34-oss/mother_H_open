#pragma once

#include "mother_H/fsm/fsm_types.hpp"
#include "mother_H/fsm/fsm_validator.hpp"

#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mother_h::fsm {

// In-memory transactional state only; this engine does not persist records
// or authenticate them cryptographically.
class FsmEngine {
public:
    explicit FsmEngine(FsmLimits limits = {}) noexcept
        : limits_(limits) {}

    FsmStatus apply(const FsmRecord& record) noexcept {
        try {
            const FsmStatus input_status = validate_input(record);
            if (input_status != FsmStatus::Ok) return input_status;

            std::lock_guard<std::mutex> lock(mutex_);
            if (contains_event(record.event_id)) return FsmStatus::DuplicateEvent;
            if (record.lsn <= snapshot_.lsn) return FsmStatus::LsnOutOfOrder;
            if (history_.size() >= limits_.max_history_events) {
                return FsmStatus::LimitExceeded;
            }

            if (record.parent_event_id.empty()) {
                if (record.state != FsmState::Held ||
                    has_request(record.request_id)) {
                    return FsmStatus::InvalidTransition;
                }
            } else {
                const FsmRecord* parent = find_event(record.parent_event_id);
                if (parent == nullptr || parent->request_id != record.request_id ||
                    parent->lsn >= record.lsn ||
                    validate_transition(parent->state, record.state) != FsmStatus::Ok ||
                    latest_request_event(record.request_id) != record.parent_event_id) {
                    return FsmStatus::ParentInvalid;
                }
            }

#ifdef MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
            if (trip_fault(FsmFaultPoint::BeforeAppend)) {
                return FsmStatus::InternalError;
            }
#endif

            FsmRequestSnapshot staged_request;
            staged_request.request_id = record.request_id;
            staged_request.state = record.state;
            staged_request.event_id = record.event_id;
            staged_request.lsn = record.lsn;

            FsmSnapshot staged_global;
            staged_global.state = record.state;
            staged_global.lsn = record.lsn;
            staged_global.event_id = record.event_id;
            staged_global.request_id = record.request_id;

            auto request_it = request_snapshots_.find(record.request_id);
            const bool new_request = request_it == request_snapshots_.end();
            if (new_request) {
                request_it = request_snapshots_.emplace(
                    record.request_id, std::move(staged_request)).first;
            }
            try {
                history_.push_back(record);
            } catch (...) {
                if (new_request) request_snapshots_.erase(request_it);
                throw;
            }
#ifdef MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
            if (trip_fault(FsmFaultPoint::AfterAppend) ||
                trip_fault(FsmFaultPoint::BeforeCommit)) {
                history_.pop_back();
                if (new_request) request_snapshots_.erase(request_it);
                return FsmStatus::InternalError;
            }
#endif

            if (!new_request) {
                request_it->second.state = staged_request.state;
                request_it->second.lsn = staged_request.lsn;
                request_it->second.event_id.swap(staged_request.event_id);
            }
            snapshot_.state = staged_global.state;
            snapshot_.lsn = staged_global.lsn;
            snapshot_.event_id.swap(staged_global.event_id);
            snapshot_.request_id.swap(staged_global.request_id);
            return FsmStatus::Ok;
        } catch (...) {
            return FsmStatus::InternalError;
        }
    }

    FsmState state() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return snapshot_.state;
    }

    std::vector<FsmRecord> history() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return history_;
    }

    FsmSnapshot snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return snapshot_;
    }

    FsmLimits limits() const noexcept {
        return limits_;
    }

#ifdef MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
    void inject_fault(FsmFaultPoint point) {
        std::lock_guard<std::mutex> lock(mutex_);
        fault_point_ = point;
    }

    std::uint64_t fault_hits() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return fault_hits_;
    }

    void corrupt_global_snapshot_for_test() {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot_.event_id = "test-corruption";
    }
#endif

    bool request_snapshot(
        const std::string& request_id,
        FsmRequestSnapshot& out
    ) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = request_snapshots_.find(request_id);
        if (it == request_snapshots_.end()) return false;
        out = it->second;
        return true;
    }

    std::unordered_map<std::string, FsmRequestSnapshot> request_snapshots() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return request_snapshots_;
    }

    FsmStatus rebuild_from_verified_history(
        const std::vector<FsmRecord>& verified_history
    ) noexcept {
        try {
            if (verified_history.size() > limits_.max_history_events) {
                return FsmStatus::LimitExceeded;
            }
            FsmSnapshot rebuilt_global;
            std::unordered_map<std::string, FsmRequestSnapshot> rebuilt_requests;
            rebuilt_requests.reserve(verified_history.size());
            for (const FsmRecord& record : verified_history) {
                FsmRequestSnapshot request_snapshot;
                request_snapshot.request_id = record.request_id;
                request_snapshot.state = record.state;
                request_snapshot.event_id = record.event_id;
                request_snapshot.lsn = record.lsn;
                rebuilt_requests[record.request_id] = std::move(request_snapshot);

                rebuilt_global.state = record.state;
                rebuilt_global.lsn = record.lsn;
                rebuilt_global.event_id = record.event_id;
                rebuilt_global.request_id = record.request_id;
            }
            if (validate_history(verified_history, rebuilt_global) != FsmStatus::Ok ||
                validate_request_snapshots(verified_history, rebuilt_requests) != FsmStatus::Ok) {
                return FsmStatus::InvalidHistory;
            }
            std::vector<FsmRecord> staged_history = verified_history;

            std::lock_guard<std::mutex> lock(mutex_);
            history_.swap(staged_history);
            request_snapshots_.swap(rebuilt_requests);
            snapshot_ = std::move(rebuilt_global);
            return FsmStatus::Ok;
        } catch (...) {
            return FsmStatus::InternalError;
        }
    }

    FsmStatus self_diagnose() const noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (validate_history(history_, snapshot_) != FsmStatus::Ok ||
                validate_request_snapshots(history_, request_snapshots_) != FsmStatus::Ok) {
                return FsmStatus::InvalidHistory;
            }
            return FsmStatus::Ok;
        } catch (...) {
            return FsmStatus::InternalError;
        }
    }

private:
    bool contains_event(const std::string& event_id) const noexcept {
        for (const FsmRecord& record : history_) {
            if (record.event_id == event_id) return true;
        }
        return false;
    }

    bool has_request(const std::string& request_id) const noexcept {
        for (const FsmRecord& record : history_) {
            if (record.request_id == request_id) return true;
        }
        return false;
    }

    std::string latest_request_event(const std::string& request_id) const {
        for (auto it = history_.rbegin(); it != history_.rend(); ++it) {
            if (it->request_id == request_id) return it->event_id;
        }
        return {};
    }

    const FsmRecord* find_event(const std::string& event_id) const noexcept {
        for (const FsmRecord& record : history_) {
            if (record.event_id == event_id) return &record;
        }
        return nullptr;
    }

#ifdef MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
    bool trip_fault(FsmFaultPoint point) noexcept {
        if (fault_point_ != point) return false;
        if (fault_hits_ != (std::numeric_limits<std::uint64_t>::max)()) {
            ++fault_hits_;
        }
        return true;
    }
#endif

    FsmLimits limits_;
    mutable std::mutex mutex_;
    std::vector<FsmRecord> history_;
    FsmSnapshot snapshot_;
    std::unordered_map<std::string, FsmRequestSnapshot> request_snapshots_;
#ifdef MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
    FsmFaultPoint fault_point_{FsmFaultPoint::None};
    std::uint64_t fault_hits_{0};
#endif
};

}  // namespace mother_h::fsm
