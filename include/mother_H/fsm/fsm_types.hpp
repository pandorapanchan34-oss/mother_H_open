#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace mother_h::fsm {

enum class FsmState : std::uint8_t {
    None,
    Held,
    Ready,
    Processed,
    Failed,
    Cancelled,
    Unknown
};

enum class EventType : std::uint8_t {
    Generic
};

enum class FsmStatus : std::uint8_t {
    Ok,
    InvalidInput,
    InvalidTransition,
    InvalidHistory,
    ParentInvalid,
    DuplicateEvent,
    LsnOutOfOrder,
    LimitExceeded,
    InternalError
};

struct FsmRecord {
    std::string event_id;
    std::string request_id;
    EventType event_type{EventType::Generic};
    FsmState state{FsmState::Unknown};
    std::uint64_t lsn{0};
    std::string parent_event_id;
};

struct FsmSnapshot {
    FsmState state{FsmState::None};
    std::uint64_t lsn{0};
    std::string event_id;
    std::string request_id;
};

struct FsmRequestSnapshot {
    std::string request_id;
    FsmState state{FsmState::None};
    std::string event_id;
    std::uint64_t lsn{0};
};

struct StateContext {
    std::string event_id;
    std::string request_id;
    EventType event_type{EventType::Generic};
    std::uint64_t lsn{0};
    std::string parent_event_id;
};

using ParentMap = std::unordered_map<std::string, FsmRecord>;

struct FsmLimits {
    std::size_t max_history_events{10000};
};

#ifdef MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
enum class FsmFaultPoint : std::uint8_t {
    None,
    BeforeAppend,
    AfterAppend,
    BeforeCommit
};
#endif

}  // namespace mother_h::fsm
