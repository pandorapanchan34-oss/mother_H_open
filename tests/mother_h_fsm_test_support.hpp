#pragma once
// Mother_H 独立FSMテスト共通部。
// 未実施のテストはSKIPPEDとして集計し、PASSには数えない。
// 前提とするAPIは fsm_types.hpp / fsm_validator.hpp / fsm_engine.hpp (仕様書 v0.1 第10章)。

#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mother_H/fsm/fsm_types.hpp"

namespace mother_h::fsm::test {

struct Runner {
    int cases{0};
    int failures{0};
    std::vector<std::string> skipped;

    void check(bool ok, const char* id, const char* expr, int line) {
        if (!ok) {
            ++failures;
            std::fprintf(stderr, "[FAIL] %s: %s (line %d)\n", id, expr, line);
        }
    }

    void run(const char* id, const std::function<void(Runner&, const char*)>& body) {
        ++cases;
        const int before = failures;
        const std::size_t skipped_before = skipped.size();
        try {
            body(*this, id);
        } catch (const std::exception& e) {
            ++failures;
            std::fprintf(stderr, "[FAIL] %s: 想定外の例外: %s\n", id, e.what());
        } catch (...) {
            ++failures;
            std::fprintf(stderr, "[FAIL] %s: 想定外の例外\n", id);
        }
        if (failures != before) {
            std::printf("[FAIL] %s\n", id);
        } else if (skipped.size() == skipped_before) {
            std::printf("[PASS] %s\n", id);
        }
    }

    void skip(const char* id, const char* reason) {
        skipped.push_back(std::string(id) + " — " + reason);
        std::printf("[SKIPPED] %s — %s\n", id, reason);
    }

    int finish() const {
        std::printf("cases=%d failures=%d skipped=%zu\n", cases, failures, skipped.size());
        return failures == 0 ? 0 : 1;
    }
};

// 判定用マクロ。run() に渡すラムダ内(引数名 r, id)で使う。
#define T_CHECK(expr) r.check(static_cast<bool>(expr), id, #expr, __LINE__)

inline FsmRecord rec(
    std::string event_id,
    std::string request_id,
    FsmState state,
    std::uint64_t lsn,
    std::string parent_event_id = {}
) {
    FsmRecord r;
    r.event_id = std::move(event_id);
    r.request_id = std::move(request_id);
    r.event_type = EventType::Generic;
    r.state = state;
    r.lsn = lsn;
    r.parent_event_id = std::move(parent_event_id);
    return r;
}

// 正常な1リクエストの履歴: Held -> Ready -> Processed
inline std::vector<FsmRecord> good_chain() {
    return {
        rec("e1", "r1", FsmState::Held, 1),
        rec("e2", "r1", FsmState::Ready, 2, "e1"),
        rec("e3", "r1", FsmState::Processed, 3, "e2"),
    };
}

inline FsmSnapshot snapshot_of(const std::vector<FsmRecord>& history) {
    FsmSnapshot s;
    if (!history.empty()) {
        s.state = history.back().state;
        s.lsn = history.back().lsn;
        s.event_id = history.back().event_id;
        s.request_id = history.back().request_id;
    }
    return s;
}

inline bool same_history(const std::vector<FsmRecord>& a, const std::vector<FsmRecord>& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i].event_id != b[i].event_id || a[i].request_id != b[i].request_id ||
            a[i].event_type != b[i].event_type || a[i].state != b[i].state ||
            a[i].lsn != b[i].lsn || a[i].parent_event_id != b[i].parent_event_id) {
            return false;
        }
    }
    return true;
}

}  // namespace mother_h::fsm::test
