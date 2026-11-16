// FSM-011〜018: 履歴整合性 / FSM-026〜030: 入力検証
//
// 前提とする履歴の形(仕様書の第9章で確定が必要):
//  - 履歴は、イベントのレコードの時系列リスト。
//  - 状態遷移は「親イベントの state -> 子イベントの state」として表す。
//  - 親を持たないイベントは Held (NONE->HELD) でなければならない。
#include "mother_H/fsm/fsm_validator.hpp"
#include "mother_h_fsm_test_support.hpp"

using namespace mother_h::fsm;
using namespace mother_h::fsm::test;

static_assert(noexcept(validate_history(std::declval<const std::vector<FsmRecord>&>(),
                                        std::declval<const FsmSnapshot&>())),
              "validate_history は noexcept であること");
static_assert(noexcept(validate_input(std::declval<const FsmRecord&>())),
              "validate_input は noexcept であること");
static_assert(noexcept(validate_context(std::declval<const StateContext&>())),
              "validate_context は noexcept であること");

static StateContext good_context() {
    StateContext c;
    c.event_id = "e1";
    c.request_id = "r1";
    c.event_type = EventType::Generic;
    c.lsn = 1;
    return c;
}

int main() {
    Runner run;

    // ---- 履歴整合性 ----
    run.run("FSM-011 正常な履歴", [](Runner& r, const char* id) {
        const auto h = good_chain();
        T_CHECK(validate_history(h, snapshot_of(h)) == FsmStatus::Ok);
    });

    run.run("FSM-012 不正な遷移を含む履歴", [](Runner& r, const char* id) {
        auto h = good_chain();
        h.push_back(rec("e4", "r1", FsmState::Ready, 4, "e3"));  // PROCESSED -> READY
        T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
    });

    run.run("FSM-013 最新状態と履歴末尾が不一致", [](Runner& r, const char* id) {
        const auto h = good_chain();
        FsmSnapshot s = snapshot_of(h);
        s.state = FsmState::Ready;
        T_CHECK(validate_history(h, s) != FsmStatus::Ok);
    });

    run.run("FSM-014 最新LSNと履歴末尾LSNが不一致", [](Runner& r, const char* id) {
        const auto h = good_chain();
        FsmSnapshot s = snapshot_of(h);
        s.lsn = 99;
        T_CHECK(validate_history(h, s) != FsmStatus::Ok);
    });

    run.run("FSM-015 最新イベントIDと履歴末尾IDが不一致", [](Runner& r, const char* id) {
        const auto h = good_chain();
        FsmSnapshot s = snapshot_of(h);
        s.event_id = "e2";
        T_CHECK(validate_history(h, s) != FsmStatus::Ok);
    });

    run.run("FSM-016 履歴内に同一イベントIDが存在", [](Runner& r, const char* id) {
        // 別リクエストの Held 2件が同じ event_id。LSNは単調増加で、他に不備はない。
        const std::vector<FsmRecord> h = {
            rec("e1", "r1", FsmState::Held, 1),
            rec("e1", "r2", FsmState::Held, 2),
        };
        T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
    });

    run.run("FSM-017 LSNが逆行する履歴", [](Runner& r, const char* id) {
        const std::vector<FsmRecord> h = {
            rec("a", "r1", FsmState::Held, 1),
            rec("b", "r2", FsmState::Held, 3),
            rec("c", "r3", FsmState::Held, 2),
        };
        T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
    });

    run.run("FSM-017 途中で逆行し、末尾LSNだけは最新と一致", [](Runner& r, const char* id) {
        // 末尾(6)だけ見ると正常に見えるが、履歴全体では 5 -> 3 で逆行している。
        const std::vector<FsmRecord> h = {
            rec("a", "r1", FsmState::Held, 1),
            rec("b", "r2", FsmState::Held, 5),
            rec("c", "r3", FsmState::Held, 3),
            rec("d", "r4", FsmState::Held, 6),
        };
        T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
    });

    run.run("FSM-018 LSNが重複する履歴", [](Runner& r, const char* id) {
        const std::vector<FsmRecord> h = {
            rec("a", "r1", FsmState::Held, 1),
            rec("b", "r2", FsmState::Held, 2),
            rec("c", "r3", FsmState::Held, 2),
        };
        T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
    });

    // ---- 入力検証 ----
    run.run("FSM-026 event_idが空", [](Runner& r, const char* id) {
        T_CHECK(validate_input(rec("e1", "r1", FsmState::Held, 1)) == FsmStatus::Ok);  // 基準
        T_CHECK(validate_input(rec("", "r1", FsmState::Held, 1)) == FsmStatus::InvalidInput);
    });

    run.run("FSM-027 request_idが空", [](Runner& r, const char* id) {
        T_CHECK(validate_input(rec("e1", "", FsmState::Held, 1)) == FsmStatus::InvalidInput);
    });

    run.run("FSM-028 未定義のevent_type", [](Runner& r, const char* id) {
        FsmRecord x = rec("e1", "r1", FsmState::Held, 1);
        x.event_type = static_cast<EventType>(0xFF);
        T_CHECK(validate_input(x) == FsmStatus::InvalidInput);
    });

    run.run("FSM-029 不完全な初期StateContext", [](Runner& r, const char* id) {
        T_CHECK(validate_context(good_context()) == FsmStatus::Ok);  // 基準

        StateContext no_lsn = good_context();
        no_lsn.lsn = 0;
        T_CHECK(validate_context(no_lsn) != FsmStatus::Ok);

        StateContext no_request = good_context();
        no_request.request_id.clear();
        T_CHECK(validate_context(no_request) != FsmStatus::Ok);

        StateContext no_event = good_context();
        no_event.event_id.clear();
        T_CHECK(validate_context(no_event) != FsmStatus::Ok);

        StateContext bad_type = good_context();
        bad_type.event_type = static_cast<EventType>(0xFF);
        T_CHECK(validate_context(bad_type) != FsmStatus::Ok);
    });

    run.run("FSM-030 不正な親子関係を含む履歴", [](Runner& r, const char* id) {
        // (a) 存在しない親
        {
            const std::vector<FsmRecord> h = {
                rec("e1", "r1", FsmState::Held, 1),
                rec("e2", "r1", FsmState::Ready, 2, "ghost"),
            };
            T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
        }
        // (b) 親が履歴の後ろ側にある(子より後に現れる)
        {
            const std::vector<FsmRecord> h = {
                rec("e2", "r1", FsmState::Ready, 1, "e1"),
                rec("e1", "r1", FsmState::Held, 2),
            };
            T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
        }
        // (c) 親子のrequest_idが不一致
        {
            const std::vector<FsmRecord> h = {
                rec("e1", "r1", FsmState::Held, 1),
                rec("e2", "r2", FsmState::Ready, 2, "e1"),
            };
            T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
        }
        // (d) 親を持たないのに Held 以外
        {
            const std::vector<FsmRecord> h = {rec("e1", "r1", FsmState::Ready, 1)};
            T_CHECK(validate_history(h, snapshot_of(h)) != FsmStatus::Ok);
        }
    });

    return run.finish();
}
