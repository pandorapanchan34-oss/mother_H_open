#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace mb::cqs13_4 {

enum class EventState : std::uint8_t {
    NONE,
    HELD,
    READY,
    PROCESSED,
    FAILED,
    CANCELLED,
    UNKNOWN
};

inline EventState parse_event_state(const std::string& value) noexcept {
    if (value == "HELD") return EventState::HELD;
    if (value == "READY") return EventState::READY;
    if (value == "PROCESSED") return EventState::PROCESSED;
    if (value == "FAILED") return EventState::FAILED;
    if (value == "CANCELLED") return EventState::CANCELLED;
    return EventState::UNKNOWN;
}

inline const char* state_name(EventState state) noexcept {
    switch (state) {
        case EventState::NONE: return "NONE";
        case EventState::HELD: return "HELD";
        case EventState::READY: return "READY";
        case EventState::PROCESSED: return "PROCESSED";
        case EventState::FAILED: return "FAILED";
        case EventState::CANCELLED: return "CANCELLED";
        case EventState::UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

enum class EventType : std::uint8_t {
    Generic
};

struct EventPayload {
    std::string event_id;
    std::string request_id;
    EventState state{EventState::UNKNOWN};
    std::string parent_event_id;
    std::string source_concept;
    std::string supplement_text;
    std::string constraints_json;
};

enum class PolicyError {
    OK = 0,
    UNKNOWN_STATE,
    INVALID_TRANSITION,
    TERMINAL_STATE,
    REQUEST_ID_MISMATCH,
    EVENT_ID_EMPTY,
    DUPLICATE_EVENT_ID,
    INVALID_ROOT_PARENT,
    MISSING_PARENT,
    PARENT_NOT_FOUND,
    PARENT_STATE_INVALID,
    PARENT_REQUEST_MISMATCH,
    PARENT_LSN_INVALID,
    LSN_REGRESSION,
    HISTORY_INCONSISTENT
};

struct StateTransitionResult {
    bool allowed{false};
    std::string reason;
    PolicyError error_code{PolicyError::OK};
};

struct EventStateRecord {
    std::string event_id;
    std::string request_id;
    EventState state{EventState::NONE};
    std::uint64_t latest_lsn{0};
    std::string parent_event_id;
};

struct StateContext {
    std::string request_id;
    EventState latest_state{EventState::NONE};
    std::uint64_t latest_lsn{0};
    std::string latest_event_id;
    std::string parent_event_id;
    std::vector<EventState> event_history;
};

class TransitionPolicyGuard {
public:
    static bool is_terminal(EventState state) noexcept {
        return state == EventState::PROCESSED ||
            state == EventState::FAILED ||
            state == EventState::CANCELLED;
    }

    static bool is_fsm_allowed(EventState from, EventState to) noexcept {
        switch (from) {
            case EventState::NONE:
                return to == EventState::HELD;
            case EventState::HELD:
                return to == EventState::READY ||
                    to == EventState::FAILED ||
                    to == EventState::CANCELLED;
            case EventState::READY:
                return to == EventState::PROCESSED ||
                    to == EventState::FAILED;
            case EventState::PROCESSED:
            case EventState::FAILED:
            case EventState::CANCELLED:
            case EventState::UNKNOWN:
            default:
                return false;
        }
    }

    static bool is_parent_state_valid(
        EventState state,
        bool allow_held_overlay = false
    ) noexcept {
        return state == EventState::READY ||
            state == EventState::PROCESSED ||
            (allow_held_overlay && state == EventState::HELD);
    }

    static bool is_history_consistent(const StateContext& context) noexcept {
        if (context.event_history.empty()) {
            return context.latest_state == EventState::NONE &&
                context.latest_lsn == 0 &&
                context.latest_event_id.empty();
        }
        EventState current = EventState::NONE;
        for (const EventState next : context.event_history) {
            if (!is_fsm_allowed(current, next)) return false;
            current = next;
        }
        return current == context.latest_state &&
            context.latest_lsn != 0 &&
            !context.latest_event_id.empty();
    }

    static StateTransitionResult validate_transition(
        const StateContext& current_context,
        const EventPayload& event,
        std::uint64_t new_lsn,
        const std::unordered_map<std::string, EventStateRecord>& global_event_states,
        bool is_root_event,
        bool allow_held_overlay = false
    ) {
        if (event.event_id.empty()) {
            return {false, "Event ID is empty", PolicyError::EVENT_ID_EMPTY};
        }
        if (event.state == EventState::UNKNOWN ||
            event.state == EventState::NONE) {
            return {false, "Unknown event state", PolicyError::UNKNOWN_STATE};
        }
        if (event.request_id.empty()) {
            return {false, "Request ID is empty", PolicyError::REQUEST_ID_MISMATCH};
        }

        const bool initial_context =
            current_context.latest_state == EventState::NONE &&
            current_context.request_id.empty() &&
            current_context.event_history.empty();
        if (!initial_context &&
            (current_context.request_id != event.request_id ||
             !is_history_consistent(current_context))) {
            return {
                false,
                "Request context or history is inconsistent",
                current_context.request_id != event.request_id
                    ? PolicyError::REQUEST_ID_MISMATCH
                    : PolicyError::HISTORY_INCONSISTENT
            };
        }
        if (new_lsn == 0 || new_lsn <= current_context.latest_lsn) {
            return {false, "LSN regression or duplicate detected", PolicyError::LSN_REGRESSION};
        }
        if (global_event_states.find(event.event_id) != global_event_states.end()) {
            return {false, "Duplicate event ID", PolicyError::DUPLICATE_EVENT_ID};
        }
        if (!is_fsm_allowed(current_context.latest_state, event.state)) {
            return {
                false,
                "Invalid FSM transition",
                is_terminal(current_context.latest_state)
                    ? PolicyError::TERMINAL_STATE
                    : PolicyError::INVALID_TRANSITION
            };
        }

        if (is_root_event) {
            if (!event.parent_event_id.empty()) {
                return {false, "Root event must not specify a parent",
                        PolicyError::INVALID_ROOT_PARENT};
            }
            if (initial_context && event.state != EventState::HELD) {
                return {false, "Root event must start with HELD",
                        PolicyError::INVALID_TRANSITION};
            }
        } else {
            if (event.parent_event_id.empty()) {
                return {false, "Child event requires a parent",
                        PolicyError::MISSING_PARENT};
            }
            const auto parent_it = global_event_states.find(event.parent_event_id);
            if (parent_it == global_event_states.end()) {
                return {false, "Parent event does not exist",
                        PolicyError::PARENT_NOT_FOUND};
            }
            const EventStateRecord& parent = parent_it->second;
            const bool allow_held =
                allow_held_overlay && event.state == EventState::READY;
            if (!is_parent_state_valid(parent.state, allow_held)) {
                return {false, "Parent state is not allowed",
                        PolicyError::PARENT_STATE_INVALID};
            }
            if (parent.request_id != event.request_id) {
                return {false, "Parent and child request IDs differ",
                        PolicyError::PARENT_REQUEST_MISMATCH};
            }
            if (parent.latest_lsn == 0 || parent.latest_lsn >= new_lsn) {
                return {false, "Parent LSN must precede child LSN",
                        PolicyError::PARENT_LSN_INVALID};
            }
        }
        return {true, "Transition authorized", PolicyError::OK};
    }
};

}  // namespace mb::cqs13_4
