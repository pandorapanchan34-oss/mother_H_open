// FSM-019〜025: 親イベント検証
//
// 各否定ケースは、正常な基準(FSM-019)から1点だけ変えて作る。
// 基準がOkであることを先に確認するので、拒否が別の理由で起きている場合は検出できる。
#include "mother_H/fsm/fsm_validator.hpp"
#include "mother_h_fsm_test_support.hpp"

using namespace mother_h::fsm;
using namespace mother_h::fsm::test;

static_assert(noexcept(validate_parent(std::declval<const FsmRecord&>(),
                                       std::declval<const ParentMap&>(),
                                       std::declval<const StateContext&>())),
              "validate_parent は noexcept であること");

struct Fixture {
    FsmRecord parent = rec("p1", "r1", FsmState::Ready, 2, "p0");
    FsmRecord child = rec("c1", "r1", FsmState::Processed, 3, "p1");
    StateContext ctx;
    ParentMap parents;

    Fixture() {
        ctx.event_id = "c1";
        ctx.request_id = "r1";
        ctx.parent_event_id = "p1";
        ctx.event_type = EventType::Generic;
        ctx.lsn = 3;
        parents["p1"] = parent;
    }

    FsmStatus check() const { return validate_parent(child, parents, ctx); }
};

int main() {
    Runner run;

    run.run("FSM-019 存在する正常な親イベント", [](Runner& r, const char* id) {
        Fixture f;
        T_CHECK(f.check() == FsmStatus::Ok);
    });

    run.run("FSM-020 存在しない親イベント", [](Runner& r, const char* id) {
        Fixture f;
        T_CHECK(f.check() == FsmStatus::Ok);  // 基準
        f.parents.clear();
        T_CHECK(f.check() == FsmStatus::ParentInvalid);
    });

    run.run("FSM-021 親子のrequest_idが不一致", [](Runner& r, const char* id) {
        Fixture f;
        f.parents["p1"].request_id = "r2";
        T_CHECK(f.check() == FsmStatus::ParentInvalid);
    });

    run.run("FSM-022 親LSNが子LSN以上", [](Runner& r, const char* id) {
        {
            Fixture f;
            f.parents["p1"].lsn = 3;  // 子と同じ
            T_CHECK(f.check() == FsmStatus::ParentInvalid);
        }
        {
            Fixture f;
            f.parents["p1"].lsn = 4;  // 子より大きい
            T_CHECK(f.check() == FsmStatus::ParentInvalid);
        }
    });

    run.run("FSM-023 親イベントが許可状態ではない", [](Runner& r, const char* id) {
        // 終端状態(Failed/Cancelled/Processed)の親から子は作れない。
        // 終端状態の親に有効な子は存在しないため、拒否理由の細分化はせず「Ok以外」を確認する。
        const FsmState terminal[] = {FsmState::Failed, FsmState::Cancelled, FsmState::Processed,
                                     FsmState::Unknown};
        for (const FsmState s : terminal) {
            Fixture f;
            f.parents["p1"].state = s;
            T_CHECK(f.check() != FsmStatus::Ok);
        }
        // 注: 親が Held の場合の扱い(仕様書 第9章の未確定事項)は、確定後にここへ追加する。
    });

    run.run("FSM-024 マップのキーと親レコードのevent_idが不一致", [](Runner& r, const char* id) {
        Fixture f;
        f.parents["p1"].event_id = "pX";  // キーは "p1" のまま
        T_CHECK(f.check() == FsmStatus::ParentInvalid);
    });

    run.run("FSM-025 StateContextのparent_event_idと指定親が不一致", [](Runner& r, const char* id) {
        Fixture f;
        f.ctx.parent_event_id = "p9";
        T_CHECK(f.check() == FsmStatus::ParentInvalid);
    });

    return run.finish();
}
