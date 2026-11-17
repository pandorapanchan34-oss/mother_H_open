#include "mother_H/journal/monotonic_checkpoint_anchor.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <system_error>

using namespace mother_h::journal;

namespace {

class MemoryMonotonicCounter final : public v2::IMonotonicCounterV2 {
public:
    explicit MemoryMonotonicCounter(std::uint64_t initial = 0)
        : value_(initial) {}

    v2::AnchorStatus read(std::uint64_t& value_out) const noexcept override {
        value_out = value_;
        return v2::AnchorStatus::Ok;
    }

    v2::CounterAdvanceResult advance(std::uint64_t expected_current) noexcept override {
        if (value_ != expected_current) {
            return v2::CounterAdvanceResult::NotApplied;
        }
        if (value_ == (std::numeric_limits<std::uint64_t>::max)()) {
            return v2::CounterAdvanceResult::NotApplied;
        }
        ++value_;
        return v2::CounterAdvanceResult::Applied;
    }

    void force_set_for_attack_test(std::uint64_t v) noexcept { value_ = v; }

private:
    std::uint64_t value_{0};
};

CheckpointTrustedBinding make_binding(
    std::uint8_t id_seed = 0x11,
    std::uint8_t key_seed = 0xA5,
    std::uint64_t cnt_origin = 0,
    std::uint64_t gen_origin = 0,
    bool has_external_anchor = false
) {
    CheckpointTrustedBinding b{};
    b.trusted_anchor_id.fill(id_seed);
    b.master_mac_key.fill(key_seed);
    b.expected_counter_origin = cnt_origin;
    b.expected_generation_origin = gen_origin;
    b.has_external_monotonic_anchor = has_external_anchor;
    return b;
}

JournalHash make_hash(std::uint8_t seed) {
    JournalHash h{};
    for (std::size_t i = 0; i < h.size(); ++i) {
        h[i] = static_cast<std::uint8_t>(seed + i);
    }
    return h;
}

bool fail_step(const char* id, const char* step_msg, int& failures) {
    std::cerr << id << ": FAIL - " << step_msg << "\n";
    ++failures;
    return false;
}

bool flip_single_byte(const std::filesystem::path& path, std::streamoff offset) {
    std::fstream fs(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!fs.is_open()) return false;

    fs.seekg(offset);
    if (!fs) return false;

    char value = 0;
    fs.read(&value, 1);
    if (!fs) return false;

    value ^= static_cast<char>(0x01);

    fs.seekp(offset);
    if (!fs) return false;

    fs.write(&value, 1);
    fs.flush();

    const bool write_ok = static_cast<bool>(fs);
    fs.close();
    return write_ok && !fs.fail();
}

} // namespace

int main() {
    int failures = 0;
    std::error_code ec;

    const auto temp_dir = std::filesystem::temp_directory_path(ec);
    if (ec) {
        std::cerr << "FATAL: temp_directory_path failed: " << ec.message() << "\n";
        return 2;
    }

    const auto unique_suffix =
        std::chrono::steady_clock::now().time_since_epoch().count();

    const auto base_dir = temp_dir /
        ("mother_h_mca_unit_test_" + std::to_string(unique_suffix));

    ec.clear();
    const bool created = std::filesystem::create_directory(base_dir, ec);
    if (ec || !created) {
        std::cerr << "FATAL: create_directory failed: "
                  << (ec ? ec.message() : "directory already exists") << "\n";
        return 2;
    }

    // MCA-01
    do {
        const auto b = make_binding();
        CheckpointDigest g1{}, g1_repeat{}, g_cnt{}, g_gen{};
        if (!CheckpointDigestCalculator::compute_genesis_digest(b.trusted_anchor_id, 0, 0, g1) ||
            !CheckpointDigestCalculator::compute_genesis_digest(b.trusted_anchor_id, 0, 0, g1_repeat) ||
            !CheckpointDigestCalculator::compute_genesis_digest(b.trusted_anchor_id, 1, 0, g_cnt) ||
            !CheckpointDigestCalculator::compute_genesis_digest(b.trusted_anchor_id, 0, 1, g_gen)) {
            fail_step("MCA-01", "compute_genesis_digest returned false", failures);
            break;
        }
        if (g1 != g1_repeat || g1 == g_cnt || g1 == g_gen) {
            fail_step("MCA-01", "Genesis digest determinism or origin sensitivity failed", failures);
            break;
        }

        JournalCheckpoint s1{10, make_hash(0x10), 1};
        JournalCheckpoint s2{11, make_hash(0x10), 1};
        CheckpointDigest d1{}, d1_repeat{}, d2{};
        if (!CheckpointDigestCalculator::compute_state_digest(b.trusted_anchor_id, s1, g1, 0, 0, d1) ||
            !CheckpointDigestCalculator::compute_state_digest(b.trusted_anchor_id, s1, g1, 0, 0, d1_repeat) ||
            !CheckpointDigestCalculator::compute_state_digest(b.trusted_anchor_id, s2, g1, 0, 0, d2)) {
            fail_step("MCA-01", "compute_state_digest returned false", failures);
            break;
        }
        if (d1 != d1_repeat || d1 == d2) {
            fail_step("MCA-01", "State digest determinism or LSN sensitivity failed", failures);
            break;
        }

        std::array<std::uint8_t, 32> k_wal{}, k_latch{};
        if (!CheckpointDigestCalculator::derive_subkey(
                b.master_mac_key, "MH-CP-ANCHOR-WAL-V1", b.trusted_anchor_id, k_wal) ||
            !CheckpointDigestCalculator::derive_subkey(
                b.master_mac_key, "MH-POISON-LATCH-V1", b.trusted_anchor_id, k_latch) ||
            k_wal == k_latch) {
            fail_step("MCA-01", "Subkey domain separation failed", failures);
            break;
        }

        std::cout << "MCA-01: PASS - Deterministic genesis/state digest, sensitivity & subkey separation\n";
    } while (false);

    // MCA-02
    do {
        const auto latch_path = base_dir / "latch_02.bin";
        const auto b = make_binding();

        {
            FilePoisonLatchStore store(latch_path, b);
            if (store.initialize_clean(b.trusted_anchor_id) != AnchoredStoreStatus::Ok) {
                fail_step("MCA-02", "initialize_clean failed", failures);
                break;
            }
            bool poisoned = true;
            if (store.check_status(b.trusted_anchor_id, true, poisoned) != AnchoredStoreStatus::Ok || poisoned) {
                fail_step("MCA-02", "initial clean check failed", failures);
                break;
            }
        }

        {
            FilePoisonLatchStore store_reopen(latch_path, b);
            bool poisoned = true;
            if (store_reopen.check_status(b.trusted_anchor_id, true, poisoned) != AnchoredStoreStatus::Ok || poisoned) {
                fail_step("MCA-02", "clean state did not survive reopen", failures);
                break;
            }
        }

        {
            const auto latch_ok_path = base_dir / "latch_02_ok.bin";
            FilePoisonLatchStore store_ok(latch_ok_path, b);
            const PoisonLatchResult res = store_ok.latch_poisoned(b.trusted_anchor_id, 0x0042U);
            if (res.status != AnchoredStoreStatus::Poisoned || !res.is_poisoned ||
                !res.persisted || res.persistence_error != AnchoredStoreStatus::Ok) {
                fail_step("MCA-02", "successful poison persistence did not report persisted=true", failures);
                break;
            }
            FilePoisonLatchStore store_reopen(latch_ok_path, b);
            bool poisoned = false;
            if (store_reopen.check_status(b.trusted_anchor_id, true, poisoned) != AnchoredStoreStatus::Poisoned || !poisoned) {
                fail_step("MCA-02", "persisted poison state did not survive reopen", failures);
                break;
            }
        }

        if (!flip_single_byte(latch_path, 12)) {
            fail_step("MCA-02", "test setup tamper write failed", failures);
            break;
        }
        {
            FilePoisonLatchStore store_after_tamper(latch_path, b);
            bool poisoned = false;
            if (store_after_tamper.check_status(b.trusted_anchor_id, true, poisoned) != AnchoredStoreStatus::Poisoned || !poisoned) {
                fail_step("MCA-02", "tampered latch was not detected as Poisoned", failures);
                break;
            }
        }

        ec.clear();
        if (!std::filesystem::remove(latch_path, ec) || ec) {
            fail_step("MCA-02", "test setup file removal failed", failures);
            break;
        }
        {
            FilePoisonLatchStore store_after_delete(latch_path, b);
            bool poisoned = false;
            if (store_after_delete.check_status(b.trusted_anchor_id, true, poisoned) != AnchoredStoreStatus::Poisoned || !poisoned) {
                fail_step("MCA-02", "deleted latch was not detected as Poisoned", failures);
                break;
            }
        }

        {
            const auto unwriteable_path = base_dir / "non_existent_dir" / "latch_fail.bin";
            FilePoisonLatchStore store_fail(unwriteable_path, b);
            const PoisonLatchResult res = store_fail.latch_poisoned(b.trusted_anchor_id, 0x0101U);
            bool mem_poisoned = false;
            const auto chk = store_fail.check_status(b.trusted_anchor_id, false, mem_poisoned);
            if (res.status != AnchoredStoreStatus::Poisoned || !res.is_poisoned ||
                res.persisted || res.persistence_error != AnchoredStoreStatus::BackendUnavailable ||
                chk != AnchoredStoreStatus::Poisoned || !mem_poisoned) {
                fail_step("MCA-02", "persistence failure was not accurately reported via PoisonLatchResult", failures);
                break;
            }
        }

        std::cout << "MCA-02: PASS - PoisonLatchStore clean/poison persistence, tamper & deletion\n";
    } while (false);

    // MCA-03
    do {
        const auto wal_path = base_dir / "wal_03.bin";
        MemoryMonotonicCounter counter(0);
        const auto b = make_binding();
        FileMonotonicCheckpointAnchor anchor(wal_path, counter);

        if (anchor.provision(b) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-03", "provision failed", failures);
            break;
        }
        std::uint64_t raw_cnt = 999;
        if (counter.read(raw_cnt) != v2::AnchorStatus::Ok || raw_cnt != 0) {
            fail_step("MCA-03", "counter initial value is not 0", failures);
            break;
        }

        CheckpointAnchorObservation obs{};
        if (anchor.read_committed(b, obs) != AnchoredStoreStatus::Ok ||
            obs.committed_revision != 0 || obs.committed_lsn != 0 ||
            obs.committed_record_hash != JournalIntegrity::genesis_hash() ||
            obs.has_pending || obs.wal_sequence != 1) {
            fail_step("MCA-03", "initial read_committed state mismatch", failures);
            break;
        }

        JournalCheckpoint cur{0, JournalIntegrity::genesis_hash(), 0};
        JournalCheckpoint nxt{5, make_hash(0x21), 1};
        CheckpointDigest nxt_dig{};
        if (!CheckpointDigestCalculator::compute_state_digest(
                b.trusted_anchor_id, nxt, obs.committed_digest, 0, 0, nxt_dig)) {
            fail_step("MCA-03", "compute_state_digest failed", failures);
            break;
        }

        TransactionId txid{};
        if (anchor.prepare_advance(b, cur, obs.committed_digest, nxt, nxt_dig, txid) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-03", "prepare_advance failed", failures);
            break;
        }
        if (anchor.commit_advance(b, txid, 1, nxt_dig) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-03", "commit_advance failed", failures);
            break;
        }
        if (counter.read(raw_cnt) != v2::AnchorStatus::Ok || raw_cnt != 1) {
            fail_step("MCA-03", "counter did not advance to 1", failures);
            break;
        }

        CheckpointAnchorObservation obs2{};
        if (anchor.read_committed(b, obs2) != AnchoredStoreStatus::Ok ||
            obs2.committed_revision != 1 || obs2.committed_lsn != 5 ||
            obs2.committed_record_hash != nxt.record_hash ||
            obs2.committed_digest != nxt_dig ||
            obs2.has_pending || obs2.wal_sequence != 3) {
            fail_step("MCA-03", "post-commit read_committed state mismatch", failures);
            break;
        }

        std::cout << "MCA-03: PASS - Provision initial state & Prepare->Commit monotonic advance\n";
    } while (false);

    // MCA-04
    do {
        const auto wal_path = base_dir / "wal_04.bin";
        MemoryMonotonicCounter counter(0);
        const auto b = make_binding();
        FileMonotonicCheckpointAnchor anchor(wal_path, counter);

        if (anchor.provision(b) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-04", "provision failed", failures);
            break;
        }
        CheckpointAnchorObservation obs{};
        if (anchor.read_committed(b, obs) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-04", "read_committed failed", failures);
            break;
        }

        JournalCheckpoint cur{0, JournalIntegrity::genesis_hash(), 0};
        JournalCheckpoint nxt{10, make_hash(0x33), 1};
        CheckpointDigest nxt_dig{};
        if (!CheckpointDigestCalculator::compute_state_digest(
                b.trusted_anchor_id, nxt, obs.committed_digest, 0, 0, nxt_dig)) {
            fail_step("MCA-04", "compute_state_digest failed", failures);
            break;
        }

        TransactionId txid{};
        if (anchor.prepare_advance(b, cur, obs.committed_digest, nxt, nxt_dig, txid) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-04", "prepare_advance failed", failures);
            break;
        }
        if (anchor.abort_advance(b, txid, 0, obs.committed_digest) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-04", "abort_advance failed", failures);
            break;
        }

        std::uint64_t raw_cnt = 999;
        if (counter.read(raw_cnt) != v2::AnchorStatus::Ok || raw_cnt != 0) {
            fail_step("MCA-04", "counter changed after abort", failures);
            break;
        }

        if (anchor.abort_advance(b, txid, 0, obs.committed_digest) != AnchoredStoreStatus::Conflict ||
            anchor.commit_advance(b, txid, 1, nxt_dig) != AnchoredStoreStatus::Conflict) {
            fail_step("MCA-04", "replayed abort or commit after abort was not rejected", failures);
            break;
        }

        CheckpointAnchorObservation obs_after{};
        if (anchor.read_committed(b, obs_after) != AnchoredStoreStatus::Ok ||
            obs_after.committed_revision != 0 || obs_after.has_pending || obs_after.wal_sequence != 3) {
            fail_step("MCA-04", "post-abort state mismatch", failures);
            break;
        }

        std::cout << "MCA-04: PASS - Conditional Abort, counter invariance & single-use token enforcement\n";
    } while (false);

    // MCA-05
    do {
        const auto wal_path = base_dir / "wal_05.bin";
        MemoryMonotonicCounter counter(0);
        const auto b = make_binding();
        FileMonotonicCheckpointAnchor anchor(wal_path, counter);

        if (anchor.provision(b) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-05", "provision failed", failures);
            break;
        }

        {
            std::ofstream ofs(wal_path, std::ios::binary | std::ios::app);
            if (!ofs.is_open()) {
                fail_step("MCA-05", "failed to open WAL for partial append", failures);
                break;
            }
            std::array<char, 40> partial{};
            partial.fill(0x2A);
            ofs.write(partial.data(), partial.size());
            ofs.flush();
            const bool write_ok = static_cast<bool>(ofs);
            ofs.close();
            if (!write_ok || ofs.fail()) {
                fail_step("MCA-05", "failed to write partial tail bytes", failures);
                break;
            }
        }

        CheckpointAnchorObservation obs{};
        if (anchor.inspect_for_recovery(b, obs) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-05", "inspect_for_recovery failed on partial tail", failures);
            break;
        }
        ec.clear();
        const auto actual_size = std::filesystem::file_size(wal_path, ec);
        const auto expected_size = FileMonotonicCheckpointAnchor::kHeaderBytes +
                                   FileMonotonicCheckpointAnchor::kRecordBytes;
        if (ec || actual_size != expected_size) {
            fail_step("MCA-05", "WAL was not truncated back to valid record boundary", failures);
            break;
        }

        const auto tamper_offset = static_cast<std::streamoff>(
            FileMonotonicCheckpointAnchor::kHeaderBytes + 60);
        if (!flip_single_byte(wal_path, tamper_offset)) {
            fail_step("MCA-05", "failed to tamper full WAL record", failures);
            break;
        }
        if (anchor.inspect_for_recovery(b, obs) != AnchoredStoreStatus::AuthenticationFailed) {
            fail_step("MCA-05", "full-record HMAC tamper was not rejected with AuthenticationFailed", failures);
            break;
        }

        std::cout << "MCA-05: PASS - Partial tail truncation vs 1-bit flipped record HMAC tamper\n";
    } while (false);

    // MCA-06
    do {
        const auto wal_path = base_dir / "wal_06.bin";
        MemoryMonotonicCounter counter(0);
        const auto b = make_binding(0x11, 0xA5, 0, 0, /*has_external_anchor=*/false);
        FileMonotonicCheckpointAnchor anchor(wal_path, counter);

        if (anchor.provision(b) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-06", "provision failed", failures);
            break;
        }
        CheckpointAnchorObservation obs{};
        if (anchor.read_committed(b, obs) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-06", "read_committed failed", failures);
            break;
        }
        if (obs.assurance_level != RollbackAssuranceLevel::SoftwareOnly ||
            obs.snapshot_rollback_protected) {
            fail_step("MCA-06", "Observation did not report SoftwareOnly assurance boundary", failures);
            break;
        }

        JournalCheckpoint cur{0, JournalIntegrity::genesis_hash(), 0};
        JournalCheckpoint nxt{1, make_hash(0x44), 1};
        CheckpointDigest nxt_dig{};
        if (!CheckpointDigestCalculator::compute_state_digest(
                b.trusted_anchor_id, nxt, obs.committed_digest, 0, 0, nxt_dig)) {
            fail_step("MCA-06", "compute_state_digest failed", failures);
            break;
        }
        TransactionId txid{};
        if (anchor.prepare_advance(b, cur, obs.committed_digest, nxt, nxt_dig, txid) != AnchoredStoreStatus::Ok ||
            anchor.commit_advance(b, txid, 1, nxt_dig) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-06", "advance to revision 1 failed", failures);
            break;
        }

        counter.force_set_for_attack_test(0);
        if (anchor.inspect_for_recovery(b, obs) != AnchoredStoreStatus::RollbackDetected) {
            fail_step("MCA-06", "local counter rollback was not detected", failures);
            break;
        }

        std::cout << "MCA-06: PASS - Local counter rollback detected & SoftwareOnly boundary reported\n";
    } while (false);

    // MCA-07
    do {
        const auto wal_path = base_dir / "wal_07.bin";
        MemoryMonotonicCounter counter(0);
        const auto b_orig = make_binding(0x11, 0xA5, 0, 0);
        FileMonotonicCheckpointAnchor anchor(wal_path, counter);

        if (anchor.provision(b_orig) != AnchoredStoreStatus::Ok) {
            fail_step("MCA-07", "provision failed", failures);
            break;
        }

        CheckpointAnchorObservation obs{};
        const auto b_wrong_id  = make_binding(0x22, 0xA5, 0, 0);
        const auto b_wrong_cnt = make_binding(0x11, 0xA5, 99, 0);
        const auto b_wrong_gen = make_binding(0x11, 0xA5, 0, 77);
        const auto b_wrong_key = make_binding(0x11, 0x5A, 0, 0);

        if (anchor.inspect_for_recovery(b_wrong_id, obs)  != AnchoredStoreStatus::AuthenticationFailed ||
            anchor.inspect_for_recovery(b_wrong_cnt, obs) != AnchoredStoreStatus::AuthenticationFailed ||
            anchor.inspect_for_recovery(b_wrong_gen, obs) != AnchoredStoreStatus::AuthenticationFailed ||
            anchor.inspect_for_recovery(b_wrong_key, obs) != AnchoredStoreStatus::AuthenticationFailed) {
            fail_step("MCA-07", "Binding mismatch (ID/CounterOrigin/GenOrigin/Key) was not rejected", failures);
            break;
        }

        std::cout << "MCA-07: PASS - TrustedBinding ID, CounterOrigin, GenOrigin & MAC key mismatch rejected\n";
    } while (false);

    ec.clear();
    std::filesystem::remove_all(base_dir, ec);
    if (ec) {
        std::cerr << "CLEANUP: FAIL - " << ec.message() << "\n";
        ++failures;
    }

    std::cout << "\nFailures: " << failures << "\n";
    return failures == 0 ? 0 : 1;
}