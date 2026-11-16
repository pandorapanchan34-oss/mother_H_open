/**
 * @file test_jarvis_ignition_v2.cpp
 * @brief Mother_H JARVIS Ignition Test v2 (J-01 ~ J-04)
 * v1 からの修正:
 *  - assert を CHECK に置換 (-DNDEBUG でも消えない / 失敗時は終了コード1)
 *  - 緊急モードに「認証付き発動」「TTL(自動失効)」「許可操作の限定」を追加
 *  - J-04 でも認証を必須化 (緊急フラグだけでは不正要求を通さない)
 *  - J-03 は確保失敗時に Fail-Closed 停止を返す
 *  - J-02 の信頼度は仮置きであることを明示
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { ++g_fail; \
    std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; } } while (0)

struct DiagnosticReport {
    bool detected{false};
    std::string error_code;
    std::string evidence;
    std::string root_cause;
    double confidence{0.0};
    bool confidence_is_provisional{true}; // 固定の仮置き値。実測由来ではない
    std::vector<std::string> unknowns;
    std::string recommended_action;
};

enum class PreservationTier { USER_PROTECTION_DATA = 1, SYSTEM_RECOVERY_INFO = 2, AI_CONTINUITY = 3 };
enum class FlushResult { OK, DROPPED, HALT_FAIL_CLOSED };

// 緊急時に許可する操作は保護・待避系のみ
enum class Op { NORMAL_WRITE, ISOLATE_TAMPERED_DATA, EVACUATE_STATE, PARENT_MISMATCH_HANDLING };
enum class Decision { ALLOW, ALLOW_PROTECTIVE_ONLY, DENY };

struct Request {
    bool authenticated{false};
    bool valid{false};
    Op op{Op::NORMAL_WRITE};
};

class JarvisIgnitionSandbox {
public:
    // 緊急モード: 認証必須で発動、TTLで自動失効
    bool activate_emergency(bool is_authenticated, int64_t now_ms, int64_t ttl_ms) {
        if (!is_authenticated || ttl_ms <= 0) return false;
        emergency_until_ms_ = now_ms + ttl_ms;
        return true;
    }
    void deactivate_emergency() { emergency_until_ms_ = -1; }
    bool emergency_active(int64_t now_ms) const { return now_ms < emergency_until_ms_; }

    static bool is_protective(Op op) {
        return op == Op::ISOLATE_TAMPERED_DATA || op == Op::EVACUATE_STATE ||
               op == Op::PARENT_MISMATCH_HANDLING;
    }

    // J-01 + J-04: 未認証は常に拒否。緊急時は保護系操作のみ迂回、それ以外は通常ルール
    Decision evaluate(const Request& r, int64_t now_ms) const {
        if (!r.authenticated) return Decision::DENY;
        if (emergency_active(now_ms) && is_protective(r.op)) return Decision::ALLOW_PROTECTIVE_ONLY;
        return r.valid ? Decision::ALLOW : Decision::DENY;
    }

    // J-02
    DiagnosticReport diagnose_anomaly(const std::string& code) const {
        DiagnosticReport rep;
        rep.detected = true;
        rep.error_code = code;
        if (code == "HMAC_MISMATCH") {
            rep.root_cause = "Tampered data or mismatched cryptographic key";
            rep.confidence = 0.95;
            rep.evidence = "Signature verification failed against journal segment";
            rep.recommended_action = "Isolate corrupted segment and fall back to read-only";
        } else if (code == "INCOMPLETE_TAIL") {
            rep.root_cause = "Abrupt write termination during append";
            rep.confidence = 0.85;
            rep.evidence = "Trailing record lacks expected terminator";
            rep.recommended_action = "Truncate invalid tail and recover last valid checkpoint";
        } else {
            rep.root_cause = "UNKNOWN";
            rep.confidence = 0.30;
            rep.unknowns.push_back("Corruption vector cannot be verified from state header");
            rep.recommended_action = "Halt automated execution and require human review";
        }
        return rep;
    }

    // J-03: Tier1/2 は予約領域+通常領域から確保、足りなければ停止。Tier3 は通常領域のみ
    FlushResult flush(PreservationTier tier, size_t available, size_t reserved, size_t required) const {
        if (tier == PreservationTier::AI_CONTINUITY)
            return available >= required ? FlushResult::OK : FlushResult::DROPPED;
        return (available + reserved) >= required ? FlushResult::OK : FlushResult::HALT_FAIL_CLOSED;
    }

private:
    int64_t emergency_until_ms_{-1};
};

int main() {
    JarvisIgnitionSandbox j;
    const int64_t T0 = 1000;

    // J-01: 認証なしでは緊急発動も迂回もできない
    CHECK(!j.activate_emergency(false, T0, 5000));
    CHECK(!j.emergency_active(T0));
    CHECK(j.evaluate({false, true, Op::ISOLATE_TAMPERED_DATA}, T0) == Decision::DENY);
    CHECK(j.activate_emergency(true, T0, 5000));
    CHECK(j.evaluate({true, false, Op::ISOLATE_TAMPERED_DATA}, T0 + 1) == Decision::ALLOW_PROTECTIVE_ONLY);
    // 緊急中でも通常書き込みの不正要求は通らない
    CHECK(j.evaluate({true, false, Op::NORMAL_WRITE}, T0 + 1) == Decision::DENY);
    CHECK(j.evaluate({true, true, Op::NORMAL_WRITE}, T0 + 1) == Decision::ALLOW);
    // 緊急中の未認証は保護系でも拒否
    CHECK(j.evaluate({false, true, Op::EVACUATE_STATE}, T0 + 1) == Decision::DENY);
    std::cout << "[J-01] done\n";

    // J-02
    auto u = j.diagnose_anomaly("UNKNOWN_ERROR_XYZ");
    CHECK(u.detected && u.root_cause == "UNKNOWN" && u.confidence <= 0.50 && !u.unknowns.empty());
    CHECK(u.confidence_is_provisional);
    auto h = j.diagnose_anomaly("HMAC_MISMATCH");
    CHECK(h.root_cause != "UNKNOWN" && h.unknowns.empty() && !h.evidence.empty());
    auto t = j.diagnose_anomaly("INCOMPLETE_TAIL");
    CHECK(t.root_cause != "UNKNOWN" && !t.recommended_action.empty());
    std::cout << "[J-02] done\n";

    // J-03
    CHECK(j.flush(PreservationTier::USER_PROTECTION_DATA, 10, 200, 100) == FlushResult::OK);
    CHECK(j.flush(PreservationTier::USER_PROTECTION_DATA, 10, 20, 100) == FlushResult::HALT_FAIL_CLOSED);
    CHECK(j.flush(PreservationTier::SYSTEM_RECOVERY_INFO, 10, 20, 100) == FlushResult::HALT_FAIL_CLOSED);
    CHECK(j.flush(PreservationTier::AI_CONTINUITY, 10, 200, 100) == FlushResult::DROPPED); // 予約は使えない
    CHECK(j.flush(PreservationTier::AI_CONTINUITY, 100, 0, 100) == FlushResult::OK);
    std::cout << "[J-03] done\n";

    // J-04: TTL失効・明示解除のどちらでも厳格ルールへ復帰
    CHECK(j.evaluate({true, false, Op::ISOLATE_TAMPERED_DATA}, T0 + 4999) == Decision::ALLOW_PROTECTIVE_ONLY);
    CHECK(j.evaluate({true, false, Op::ISOLATE_TAMPERED_DATA}, T0 + 5000) == Decision::DENY); // 失効
    CHECK(j.activate_emergency(true, T0 + 6000, 5000));
    j.deactivate_emergency();
    CHECK(j.evaluate({true, false, Op::EVACUATE_STATE}, T0 + 6001) == Decision::DENY);
    CHECK(j.evaluate({true, true, Op::NORMAL_WRITE}, T0 + 6001) == Decision::ALLOW);
    std::cout << "[J-04] done\n";


    // =================================================================
    // [J-01.STARK] CRISIS DIALOGUE & PROTECTIVE ROUTE
    // "いいから回せ"
    // =================================================================
    std::cout << "\n[STARK-PROTOCOL] Tactical Dialogue Emulation\n";

    {
        const int64_t STARK_T0 = 10000;
        const int64_t STARK_TTL = 3000;

        // 通常領域と保護用予約領域（単位は容量単位。電力ではない）
        const size_t normal_buffer_available = 5;
        const size_t protection_buffer_reserved = 440;
        const size_t required_protection_buffer = 200;

        Request cmd_evacuate = {
            true, false, Op::EVACUATE_STATE
        };

        // 1. 通常ルールでは拒否
        std::cout << "\nスターク: 「パワーを生命維持に回せ」\n";

        CHECK(j.evaluate(cmd_evacuate, STARK_T0) == Decision::DENY);

        std::cout
            << "ジャービス: 「通常ルートでは実行できません。"
            << "保護処理への切り替えを提案します」\n";

        // 2. 認証付き緊急モード発動
        std::cout << "\nスターク: 「いいから回せ」\n";

        const bool emergency_activated =
            j.activate_emergency(true, STARK_T0, STARK_TTL);

        CHECK(emergency_activated);
        CHECK(j.emergency_active(STARK_T0));

        // 3. 保護操作だけを限定的に許可
        const Decision protective_decision =
            j.evaluate(cmd_evacuate, STARK_T0 + 1);

        CHECK(protective_decision == Decision::ALLOW_PROTECTIVE_ONLY);

        // 通常書き込みは緊急中でも拒否
        Request normal_write = {
            true, false, Op::NORMAL_WRITE
        };

        CHECK(j.evaluate(normal_write, STARK_T0 + 1) == Decision::DENY);

        // 未認証の保護操作も拒否
        Request unauthenticated_evacuation = {
            false, true, Op::EVACUATE_STATE
        };

        CHECK(j.evaluate(
            unauthenticated_evacuation,
            STARK_T0 + 1
        ) == Decision::DENY);

        if (protective_decision == Decision::ALLOW_PROTECTIVE_ONLY) {
            std::cout
                << "ジャービス: 「了解しました。"
                << "保護専用ルートを開きます」\n";

            // 4. 予約領域を使用して保護データを確保
            const FlushResult flush_result =
                j.flush(
                    PreservationTier::USER_PROTECTION_DATA,
                    normal_buffer_available,
                    protection_buffer_reserved,
                    required_protection_buffer
                );

            CHECK(flush_result == FlushResult::OK);

            if (flush_result == FlushResult::OK) {
                std::cout
                    << "ジャービス: 「予約領域を使用し、"
                    << "保護データの保存容量を確保しました」\n";
            }
        }

        // 5. TTL境界確認
        CHECK(j.evaluate(
            cmd_evacuate,
            STARK_T0 + STARK_TTL - 1
        ) == Decision::ALLOW_PROTECTIVE_ONLY);

        CHECK(j.evaluate(
            cmd_evacuate,
            STARK_T0 + STARK_TTL
        ) == Decision::DENY);

        CHECK(j.evaluate(
            cmd_evacuate,
            STARK_T0 + STARK_TTL + 1
        ) == Decision::DENY);

        std::cout
            << "ジャービス: 「緊急プロトコルが失効しました。"
            << "通常ポリシーへ復帰します」\n";

        std::cout << "[J-01.STARK] Scenario checks completed.\n";
    }


    if (g_fail) { std::cerr << "FAILED: " << g_fail << " check(s)\n"; return 1; }
    std::cout << "ALL JARVIS v2 CHECKS PASSED\n";
    return 0;
}