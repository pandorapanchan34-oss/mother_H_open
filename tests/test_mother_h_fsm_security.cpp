// FSM-031〜038: 状態不変・並行実行・上限・連続投入・重複・原子性
//
// ビルド時の切り替え:
//  - MOTHER_H_FSM_SINGLE_THREADED が定義されている場合、FSM-033は適用外(SKIPPED)。
//    その場合は、直列化の契約を別途定義すること。
//  - FSM-033は ThreadSanitizer 付きビルドでも実行すること。
#include <atomic>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "mother_H/fsm/fsm_engine.hpp"
#include "mother_H/fsm/fsm_validator.hpp"
#include "mother_h_fsm_test_support.hpp"

using namespace mother_h::fsm;
using namespace mother_h::fsm::test;

static_assert(noexcept(std::declval<FsmEngine&>().apply(std::declval<const FsmRecord&>())),
              "FsmEngine::apply は noexcept であること");

// Held -> Ready -> Processed まで進めたエンジン
static void drive_to_processed(FsmEngine& e) {
    e.apply(rec("e1", "r1", FsmState::Held, 1));
    e.apply(rec("e2", "r1", FsmState::Ready, 2, "e1"));
    e.apply(rec("e3", "r1", FsmState::Processed, 3, "e2"));
}

int main() {
    Runner run;

    run.run("FSM-031/032 拒否された遷移で状態・履歴が不変", [](Runner& r, const char* id) {
        FsmEngine e;
        T_CHECK(e.apply(rec("e1", "r1", FsmState::Held, 1)) == FsmStatus::Ok);
        const FsmState state_before = e.state();
        const auto history_before = e.history();

        // HELD -> PROCESSED は不正
        const FsmStatus s = e.apply(rec("e2", "r1", FsmState::Processed, 2, "e1"));
        T_CHECK(s != FsmStatus::Ok);
        T_CHECK(e.state() == state_before);
        T_CHECK(same_history(e.history(), history_before));
    });

    run.run("FSM-033 複数スレッドから更新", [](Runner& r, const char* id) {
#ifdef MOTHER_H_FSM_SINGLE_THREADED
        r.skip(id, "単一スレッド設計のため適用外(直列化の契約は別途定義)");
#else
        FsmEngine e;
        T_CHECK(e.apply(rec("e0", "r0", FsmState::Held, 1)) == FsmStatus::Ok);

        constexpr int kThreads = 8;
        constexpr int kPerThread = 50;
        std::atomic<int> accepted{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&, t] {
                for (int i = 0; i < kPerThread; ++i) {
                    const int n = t * kPerThread + i;
                    // LSNの競合で拒否される投入があってよい。守るべきは整合性の不変条件。
                    const FsmStatus s = e.apply(rec("h" + std::to_string(n), "r" + std::to_string(n),
                                                    FsmState::Held,
                                                    static_cast<std::uint64_t>(n + 2)));
                    if (s == FsmStatus::Ok) ++accepted;
                }
            });
        }
        for (auto& th : threads) th.join();

        const auto h = e.history();
        T_CHECK(accepted.load() > 0);
        T_CHECK(h.size() == static_cast<std::size_t>(1 + accepted.load()));  // 受理数=履歴件数
        T_CHECK(validate_history(h, e.snapshot()) == FsmStatus::Ok);       // 単調増加・一意性を維持
#endif
    });

    run.run("FSM-034 許容上限を超える履歴", [](Runner& r, const char* id) {
        FsmLimits limits;
        limits.max_history_events = 4;  // 実際の値は ResourceGuard 統合時に決める(仕様書 第9章)
        FsmEngine e(limits);
        for (std::uint64_t i = 1; i <= 4; ++i) {
            T_CHECK(e.apply(rec("e" + std::to_string(i), "r" + std::to_string(i),
                                FsmState::Held, i)) == FsmStatus::Ok);
        }
        const auto before = e.history();
        const FsmSnapshot snap_before = e.snapshot();

        T_CHECK(e.apply(rec("e5", "r5", FsmState::Held, 5)) == FsmStatus::LimitExceeded);
        T_CHECK(same_history(e.history(), before));
        T_CHECK(e.snapshot().lsn == snap_before.lsn);
    });

    run.run("FSM-035 不正イベントの連続投入", [](Runner& r, const char* id) {
        FsmEngine e;
        T_CHECK(e.apply(rec("e1", "r1", FsmState::Held, 1)) == FsmStatus::Ok);
        const auto before = e.history();

        int rejected = 0;
        for (int i = 0; i < 200; ++i) {
            FsmRecord bad;
            switch (i % 7) {
                case 0: bad = rec("", "r1", FsmState::Held, 10 + i); break;               // event_id 空
                case 1: bad = rec("x" + std::to_string(i), "", FsmState::Held, 10 + i); break;  // request_id 空
                case 2:
                    bad = rec("x" + std::to_string(i), "r1", FsmState::Held, 10 + i);
                    bad.event_type = static_cast<EventType>(0xFF);                        // 未定義の型
                    break;
                case 3: bad = rec("x" + std::to_string(i), "r1", FsmState::Ready, 10 + i, "ghost"); break;  // 親なし
                case 4: bad = rec("x" + std::to_string(i), "r1", FsmState::Processed, 10 + i, "e1"); break;  // HELD->PROCESSED
                case 5: bad = rec("x" + std::to_string(i), "r2", FsmState::Held, 0); break;  // LSN逆行
                default: bad = rec("e1", "r9", FsmState::Held, 10 + i); break;               // event_id 重複
            }
            if (e.apply(bad) != FsmStatus::Ok) ++rejected;
        }
        T_CHECK(rejected == 200);
        T_CHECK(e.state() == FsmState::Held);
        T_CHECK(same_history(e.history(), before));
    });

    run.run("FSM-036 処理済みイベントの再投入", [](Runner& r, const char* id) {
        FsmEngine e;
        drive_to_processed(e);
        T_CHECK(e.state() == FsmState::Processed);  // 基準
        const auto before = e.history();

        // 履歴内の重複(FSM-016)とは別に、同じレコードを再投入したときの拒否を確認する。
        T_CHECK(e.apply(rec("e3", "r1", FsmState::Processed, 3, "e2")) == FsmStatus::DuplicateEvent);
        T_CHECK(e.apply(rec("e2", "r1", FsmState::Ready, 2, "e1")) == FsmStatus::DuplicateEvent);
        T_CHECK(same_history(e.history(), before));
        T_CHECK(e.state() == FsmState::Processed);
    });

    run.run("FSM-037 古い親イベントへの付け替えを拒否", [](Runner& r, const char* id) {
        FsmEngine e;
        T_CHECK(e.apply(rec("e1", "r1", FsmState::Held, 1)) == FsmStatus::Ok);
        T_CHECK(e.apply(rec("e2", "r1", FsmState::Ready, 2, "e1")) == FsmStatus::Ok);
        const auto before = e.history();
        T_CHECK(e.apply(rec("e3", "r1", FsmState::Failed, 3, "e1")) ==
                FsmStatus::ParentInvalid);
        T_CHECK(same_history(e.history(), before));
    });

    run.run("FSM-038 検証・記録中の失敗で部分更新なし", [](Runner& r, const char* id) {
        const FsmFaultPoint points[] = {FsmFaultPoint::BeforeAppend, FsmFaultPoint::AfterAppend,
                                        FsmFaultPoint::BeforeCommit};
        for (const FsmFaultPoint p : points) {
            FsmEngine e;
            T_CHECK(e.apply(rec("e1", "r1", FsmState::Held, 1)) == FsmStatus::Ok);
            const FsmState state_before = e.state();
            const auto history_before = e.history();
            const std::uint64_t hits_before = e.fault_hits();

            e.inject_fault(p);
            const FsmStatus s = e.apply(rec("e2", "r1", FsmState::Ready, 2, "e1"));
            T_CHECK(s == FsmStatus::InternalError);
            T_CHECK(e.fault_hits() > hits_before);  // 注入が実際に発火したこと(未発火ならテスト無効)
            T_CHECK(e.state() == state_before);
            T_CHECK(same_history(e.history(), history_before));

            // 注入を解除して同じレコードを再投入する。部分更新が残っていれば、
            // イベントID重複またはLSN不整合で失敗する。
            e.inject_fault(FsmFaultPoint::None);
            T_CHECK(e.apply(rec("e2", "r1", FsmState::Ready, 2, "e1")) == FsmStatus::Ok);
        }
    });

    return run.finish();
}
