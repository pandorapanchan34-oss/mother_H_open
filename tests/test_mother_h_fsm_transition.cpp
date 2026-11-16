// FSM-001〜010: 状態遷移の許可・拒否
#include <type_traits>
#include <utility>

#include "mother_H/fsm/fsm_validator.hpp"
#include "mother_h_fsm_test_support.hpp"

using namespace mother_h::fsm;
using namespace mother_h::fsm::test;

static_assert(noexcept(validate_transition(FsmState::None, FsmState::Held)),
              "validate_transition は noexcept であること");

// 仕様書 第2章の遷移表。実装とは独立に、テスト側の期待値として持つ。
static bool allowed(FsmState from, FsmState to) {
    switch (from) {
        case FsmState::None:
            return to == FsmState::Held;
        case FsmState::Held:
            return to == FsmState::Ready || to == FsmState::Failed ||
                   to == FsmState::Cancelled;
        case FsmState::Ready:
            return to == FsmState::Processed || to == FsmState::Failed;
        default:
            return false;
    }
}

static bool ok(FsmState a, FsmState b) { return validate_transition(a, b) == FsmStatus::Ok; }

int main() {
    Runner run;

    run.run("FSM-001 NONE->HELD", [](Runner& r, const char* id) {
        T_CHECK(ok(FsmState::None, FsmState::Held));
    });
    run.run("FSM-002 HELD->READY", [](Runner& r, const char* id) {
        T_CHECK(ok(FsmState::Held, FsmState::Ready));
    });
    run.run("FSM-003 HELD->FAILED", [](Runner& r, const char* id) {
        T_CHECK(ok(FsmState::Held, FsmState::Failed));
    });
    run.run("FSM-004 HELD->CANCELLED", [](Runner& r, const char* id) {
        T_CHECK(ok(FsmState::Held, FsmState::Cancelled));
    });
    run.run("FSM-005 READY->PROCESSED", [](Runner& r, const char* id) {
        T_CHECK(ok(FsmState::Ready, FsmState::Processed));
    });
    run.run("FSM-006 READY->FAILED", [](Runner& r, const char* id) {
        T_CHECK(ok(FsmState::Ready, FsmState::Failed));
    });
    run.run("FSM-007 PROCESSED->READY 拒否", [](Runner& r, const char* id) {
        T_CHECK(validate_transition(FsmState::Processed, FsmState::Ready) ==
                FsmStatus::InvalidTransition);
    });
    run.run("FSM-008 FAILED->READY 拒否", [](Runner& r, const char* id) {
        T_CHECK(validate_transition(FsmState::Failed, FsmState::Ready) ==
                FsmStatus::InvalidTransition);
    });
    run.run("FSM-009 CANCELLED->READY 拒否", [](Runner& r, const char* id) {
        T_CHECK(validate_transition(FsmState::Cancelled, FsmState::Ready) ==
                FsmStatus::InvalidTransition);
    });
    run.run("FSM-010 UNKNOWNを含む遷移は全て拒否", [](Runner& r, const char* id) {
        const FsmState out_of_range = static_cast<FsmState>(0xFF);
        const FsmState all[] = {FsmState::None,      FsmState::Held,      FsmState::Ready,
                                FsmState::Processed, FsmState::Failed,    FsmState::Cancelled,
                                FsmState::Unknown,   out_of_range};
        for (const FsmState s : all) {
            T_CHECK(!ok(FsmState::Unknown, s));
            T_CHECK(!ok(s, FsmState::Unknown));
            T_CHECK(!ok(out_of_range, s));
            T_CHECK(!ok(s, out_of_range));
        }
    });

    // 全組み合わせ(8x8)を、仕様書の遷移表と照合する。
    // 許可する遷移は仕様の6通りだけで、それ以外は全て拒否される。
    run.run("FSM-007〜010 全組み合わせ", [](Runner& r, const char* id) {
        const FsmState all[] = {FsmState::None,      FsmState::Held,      FsmState::Ready,
                                FsmState::Processed, FsmState::Failed,    FsmState::Cancelled,
                                FsmState::Unknown,   static_cast<FsmState>(0xFF)};
        int allowed_count = 0;
        for (const FsmState from : all) {
            for (const FsmState to : all) {
                T_CHECK(ok(from, to) == allowed(from, to));
                if (allowed(from, to)) ++allowed_count;
            }
        }
        T_CHECK(allowed_count == 6);  // 表そのものの取り違え防止
    });

    return run.finish();
}
