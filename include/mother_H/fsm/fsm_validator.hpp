#pragma once

#include "mother_H/fsm/fsm_types.hpp"

#include <cstddef>
#include <vector>

namespace mother_h::fsm {

inline bool is_valid_state(FsmState state) noexcept {
    switch (state) {
        case FsmState::Held:
        case FsmState::Ready:
        case FsmState::Processed:
        case FsmState::Failed:
        case FsmState::Cancelled:
            return true;
        case FsmState::None:
        case FsmState::Unknown:
        default:
            return false;
    }
}

inline bool is_valid_event_type(EventType event_type) noexcept {
    return event_type == EventType::Generic;
}

inline FsmStatus validate_transition(FsmState from, FsmState to) noexcept {
    switch (from) {
        case FsmState::None:
            return to == FsmState::Held
                ? FsmStatus::Ok
                : FsmStatus::InvalidTransition;
        case FsmState::Held:
            return to == FsmState::Ready || to == FsmState::Failed ||
                    to == FsmState::Cancelled
                ? FsmStatus::Ok
                : FsmStatus::InvalidTransition;
        case FsmState::Ready:
            return to == FsmState::Processed || to == FsmState::Failed
                ? FsmStatus::Ok
                : FsmStatus::InvalidTransition;
        case FsmState::Processed:
        case FsmState::Failed:
        case FsmState::Cancelled:
        case FsmState::Unknown:
        default:
            return FsmStatus::InvalidTransition;
    }
}

inline FsmStatus validate_input(const FsmRecord& record) noexcept {
    if (record.event_id.empty() || record.request_id.empty() ||
        !is_valid_event_type(record.event_type) || !is_valid_state(record.state) ||
        record.lsn == 0) {
        return FsmStatus::InvalidInput;
    }
    return FsmStatus::Ok;
}

inline FsmStatus validate_context(const StateContext& context) noexcept {
    if (context.event_id.empty() || context.request_id.empty() ||
        !is_valid_event_type(context.event_type) || context.lsn == 0) {
        return FsmStatus::InvalidInput;
    }
    return FsmStatus::Ok;
}

inline FsmStatus validate_parent(
    const FsmRecord& child,
    const ParentMap& parents,
    const StateContext& context
) noexcept {
    if (validate_input(child) != FsmStatus::Ok ||
        validate_context(context) != FsmStatus::Ok ||
        context.event_id != child.event_id ||
        context.request_id != child.request_id ||
        context.event_type != child.event_type ||
        context.lsn != child.lsn ||
        context.parent_event_id != child.parent_event_id ||
        child.parent_event_id.empty()) {
        return FsmStatus::ParentInvalid;
    }

    const auto parent_it = parents.find(child.parent_event_id);
    if (parent_it == parents.end()) return FsmStatus::ParentInvalid;

    const FsmRecord& parent = parent_it->second;
    if (parent.event_id != child.parent_event_id ||
        parent.request_id != child.request_id ||
        parent.lsn == 0 || parent.lsn >= child.lsn ||
        validate_input(parent) != FsmStatus::Ok ||
        validate_transition(parent.state, child.state) != FsmStatus::Ok) {
        return FsmStatus::ParentInvalid;
    }
    return FsmStatus::Ok;
}

inline FsmStatus validate_history(
    const std::vector<FsmRecord>& history,
    const FsmSnapshot& snapshot
) noexcept {
    if (history.empty()) {
        return snapshot.state == FsmState::None && snapshot.lsn == 0 &&
                snapshot.event_id.empty() && snapshot.request_id.empty()
            ? FsmStatus::Ok
            : FsmStatus::InvalidHistory;
    }

    std::uint64_t previous_lsn = 0;
    for (std::size_t i = 0; i < history.size(); ++i) {
        const FsmRecord& record = history[i];
        if (validate_input(record) != FsmStatus::Ok ||
            record.lsn <= previous_lsn) {
            return FsmStatus::InvalidHistory;
        }
        previous_lsn = record.lsn;

        for (std::size_t earlier = 0; earlier < i; ++earlier) {
            if (history[earlier].event_id == record.event_id) {
                return FsmStatus::InvalidHistory;
            }
        }

        if (record.parent_event_id.empty()) {
            if (record.state != FsmState::Held) return FsmStatus::InvalidHistory;
            for (std::size_t earlier = 0; earlier < i; ++earlier) {
                if (history[earlier].request_id == record.request_id) {
                    return FsmStatus::InvalidHistory;
                }
            }
            continue;
        }

        std::size_t parent_index = i;
        for (std::size_t earlier = 0; earlier < i; ++earlier) {
            if (history[earlier].event_id == record.parent_event_id) {
                parent_index = earlier;
                break;
            }
        }
        if (parent_index == i) return FsmStatus::InvalidHistory;

        std::size_t latest_request_index = i;
        for (std::size_t earlier = 0; earlier < i; ++earlier) {
            if (history[earlier].request_id == record.request_id) {
                latest_request_index = earlier;
            }
        }
        if (latest_request_index != parent_index) return FsmStatus::InvalidHistory;

        const FsmRecord& parent = history[parent_index];
        if (parent.request_id != record.request_id ||
            parent.lsn >= record.lsn ||
            validate_transition(parent.state, record.state) != FsmStatus::Ok) {
            return FsmStatus::InvalidHistory;
        }
    }

    const FsmRecord& last = history.back();
    return snapshot.state == last.state && snapshot.lsn == last.lsn &&
            snapshot.event_id == last.event_id &&
            snapshot.request_id == last.request_id
        ? FsmStatus::Ok
        : FsmStatus::InvalidHistory;
}

inline FsmStatus validate_request_snapshots(
    const std::vector<FsmRecord>& history,
    const std::unordered_map<std::string, FsmRequestSnapshot>& snapshots
) {
    std::unordered_map<std::string, const FsmRecord*> latest_by_request;
    latest_by_request.reserve(history.size());
    for (const FsmRecord& record : history) {
        latest_by_request[record.request_id] = &record;
    }
    if (latest_by_request.size() != snapshots.size()) return FsmStatus::InvalidHistory;

    for (const auto& entry : latest_by_request) {
        const auto snapshot = snapshots.find(entry.first);
        if (snapshot == snapshots.end()) return FsmStatus::InvalidHistory;
        const FsmRecord& latest = *entry.second;
        if (snapshot->second.request_id != latest.request_id ||
            snapshot->second.state != latest.state ||
            snapshot->second.event_id != latest.event_id ||
            snapshot->second.lsn != latest.lsn) {
            return FsmStatus::InvalidHistory;
        }
    }
    return FsmStatus::Ok;
}

}  // namespace mother_h::fsm
