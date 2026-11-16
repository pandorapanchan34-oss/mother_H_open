#include "mother_H/core/phase13_4_state_policy.hpp"

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
using mb::cqs13_4::EventPayload;
using mb::cqs13_4::EventState;
using mb::cqs13_4::EventStateRecord;
using mb::cqs13_4::PolicyError;
using mb::cqs13_4::StateContext;
using mb::cqs13_4::TransitionPolicyGuard;

EventPayload event(const std::string& id, EventState state,
                   const std::string& parent = {},
                   const std::string& request = "req-1") {
    EventPayload value;
    value.event_id = id;
    value.request_id = request;
    value.state = state;
    value.parent_event_id = parent;
    return value;
}

StateContext held_context() {
    StateContext context;
    context.request_id = "req-1";
    context.latest_state = EventState::HELD;
    context.latest_lsn = 1;
    context.latest_event_id = "root";
    context.event_history.push_back(EventState::HELD);
    return context;
}

bool check(const char* id, const mb::cqs13_4::StateTransitionResult& result,
           PolicyError expected, const char* description) {
    const bool passed = !result.allowed && result.error_code == expected;
    std::cout << (passed ? "[PASS] " : "[FAIL] ") << id << ": "
              << description << '\n';
    return passed;
}
}  // namespace

int main() {
    bool ok = true;
    const StateContext initial;
    const std::unordered_map<std::string, EventStateRecord> empty;

    // Initial READY reaches root policy only after NONE -> READY passes the FSM,
    // so use a non-root call to test missing-parent ordering separately below.
    const auto ready_root = TransitionPolicyGuard::validate_transition(
        initial, event("root-ready", EventState::READY), 1, empty, true);
    ok &= check("FSM-POL-01", ready_root, PolicyError::INVALID_TRANSITION,
                "initial READY is rejected before root-parent checks");

    auto held = held_context();
    const auto missing_parent = TransitionPolicyGuard::validate_transition(
        held, event("ready-no-parent", EventState::READY), 2, empty, false);
    ok &= check("FSM-POL-02", missing_parent, PolicyError::MISSING_PARENT,
                "READY child without parent is rejected");

    std::unordered_map<std::string, EventStateRecord> parents;
    parents.emplace("held-parent", EventStateRecord{
        "held-parent", "req-1", EventState::HELD, 1, {}});
    const auto held_parent_non_ready = TransitionPolicyGuard::validate_transition(
        held, event("failed-child", EventState::FAILED, "held-parent"),
        2, parents, false, true);
    ok &= check("FSM-POL-03", held_parent_non_ready,
                PolicyError::PARENT_STATE_INVALID,
                "held parent overlay is limited to READY children");

    parents.clear();
    parents.emplace("ready-parent", EventStateRecord{
        "ready-parent", "other-request", EventState::READY, 1, {}});
    const auto request_mismatch = TransitionPolicyGuard::validate_transition(
        held, event("ready-child", EventState::READY, "ready-parent"),
        2, parents, false);
    ok &= check("FSM-POL-04", request_mismatch,
                PolicyError::PARENT_REQUEST_MISMATCH,
                "parent and child request IDs must match");

    parents.clear();
    parents.emplace("ready-parent", EventStateRecord{
        "ready-parent", "req-1", EventState::READY, 2, {}});
    const auto parent_lsn_invalid = TransitionPolicyGuard::validate_transition(
        held, event("ready-child", EventState::READY, "ready-parent"),
        2, parents, false);
    ok &= check("FSM-POL-05", parent_lsn_invalid,
                PolicyError::PARENT_LSN_INVALID,
                "parent LSN must be nonzero and precede child LSN");

    parents.clear();
    parents.emplace("already-used", EventStateRecord{
        "already-used", "req-1", EventState::HELD, 1, {}});
    const auto duplicate_id = TransitionPolicyGuard::validate_transition(
        initial, event("already-used", EventState::HELD), 1, parents, true);
    ok &= check("FSM-POL-06", duplicate_id, PolicyError::DUPLICATE_EVENT_ID,
                "event IDs are globally unique");

    return ok ? 0 : 1;
}
