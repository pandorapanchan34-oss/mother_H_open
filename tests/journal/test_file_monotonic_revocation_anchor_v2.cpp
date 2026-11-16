#include "mother_H/journal/monotonic_revocation_anchor_v2.hpp"
#include "mother_H/journal/kek_wrapped_key_store_v2.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using namespace mother_h::journal;
using namespace mother_h::journal::v2;

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::array<std::uint8_t, 12> random{};
        if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        static constexpr char hex[] = "0123456789abcdef";
        std::string suffix;
        for (const auto byte : random) {
            suffix.push_back(hex[byte >> 4U]);
            suffix.push_back(hex[byte & 0x0FU]);
        }
        path_ = std::filesystem::temp_directory_path() /
            ("mother_h_anchor_v2_" + suffix);
        if (!std::filesystem::create_directory(path_)) {
            throw std::runtime_error("could not create fixture directory");
        }
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

bool check(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "[FAIL] " << message << '\n';
    return false;
}

bool write_bytes(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes
) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    return static_cast<bool>(output);
}

std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

std::array<std::uint8_t, 32> digest(
    const std::vector<std::uint8_t>& bytes
) {
    std::array<std::uint8_t, 32> result{};
    unsigned int length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), result.data(), &length,
                   EVP_sha256(), nullptr) != 1 ||
        length != result.size()) {
        throw std::runtime_error("SHA-256 failed");
    }
    return result;
}

bool test_file_anchor_lifecycle() {
    TemporaryDirectory directory;
    const auto store_path = directory.path() / "store.bin";
    const auto wal_path = directory.path() / "anchor.wal";
    const auto counter_path = directory.path() / "counter.bin";
    const std::vector<std::uint8_t> initial_store{0x10, 0x20, 0x30};
    const std::vector<std::uint8_t> updated_store{0x41, 0x42, 0x43, 0x44};
    if (!check(write_bytes(store_path, initial_store), "initial store write failed")) {
        return false;
    }

    std::array<std::uint8_t, 32> mac_key{};
    mac_key.fill(0x5D);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0xA6);
    FileMonotonicCounterV2 counter(counter_path);
    if (!check(counter.provision(19) == AnchorStatus::Ok,
               "mock counter provision failed")) {
        return false;
    }

    AnchorSnapshot initial{};
    const DataKeyReference reference{"child-process-key", 1};
    {
        FileMonotonicRevocationAnchorV2 anchor(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(anchor.provision(19, 700, digest(initial_store)) ==
                       AnchorStatus::Ok,
                   "anchor provision failed") ||
            !check(anchor.snapshot(initial) == AnchorStatus::Ok &&
                       initial.counter == 19 && initial.generation == 700 &&
                       initial.counter_origin == 19 &&
                       initial.generation_origin == 700,
                   "initial snapshot did not preserve its configured origins")) {
            return false;
        }

        AnchorToken usage = 0;
        if (!check(anchor.acquire_usage(reference, initial, usage) ==
                       AnchorStatus::Ok &&
                       usage != 0,
                   "current snapshot usage lease was refused")) {
            return false;
        }
        AnchorToken blocked_update = 0;
        if (!check(anchor.prepare_update(
                       UpdateKind::Issue, reference, initial,
                       digest(updated_store), blocked_update) ==
                       AnchorStatus::Busy,
                   "exclusive update was admitted while a usage lease existed") ||
            !check(anchor.release_usage(usage) == AnchorStatus::Ok,
                   "usage lease release failed")) {
            return false;
        }

        AnchorToken update = 0;
        if (!check(anchor.prepare_update(
                       UpdateKind::Issue, reference, initial,
                       digest(updated_store), update) == AnchorStatus::Ok &&
                       update != 0,
                   "PREPARE was not persisted")) {
            return false;
        }
        if (!check(write_bytes(store_path, updated_store),
                   "candidate store replacement failed") ||
            !check(anchor.commit_update(update) == AnchorStatus::Ok,
                   "counter/COMMIT transition failed")) {
            return false;
        }
        AnchorSnapshot committed{};
        if (!check(anchor.snapshot(committed) == AnchorStatus::Ok &&
                       committed.counter == 20 &&
                       committed.generation == 701 &&
                       committed.store_digest == digest(updated_store) &&
                       committed.counter ==
                           committed.counter_origin +
                               (committed.generation -
                                committed.generation_origin),
                   "committed snapshot violated exact counter-generation mapping")) {
            return false;
        }
        const auto wal_size_before_checkpoint =
            std::filesystem::file_size(wal_path);
        if (!check(anchor.checkpoint() == AnchorStatus::Ok,
                   "stable WAL checkpoint failed")) {
            return false;
        }
        AnchorSnapshot checkpointed{};
        if (!check(anchor.snapshot(checkpointed) == AnchorStatus::Ok &&
                       checkpointed.counter == committed.counter &&
                       checkpointed.generation == committed.generation &&
                       checkpointed.store_digest == committed.store_digest &&
                       std::filesystem::file_size(wal_path) <
                           wal_size_before_checkpoint,
                   "checkpoint changed stable state or did not compact the WAL")) {
            return false;
        }
        AnchorToken stale = 0;
        if (!check(anchor.acquire_usage(reference, initial, stale) ==
                       AnchorStatus::StaleSnapshot &&
                       stale == 0,
                   "old snapshot acquired a lease after commit")) {
            return false;
        }
    }

    std::uint64_t counter_value = 0;
    if (!check(counter.read(counter_value) == AnchorStatus::Ok &&
                   counter_value == 20 &&
                   std::filesystem::file_size(counter_path) == 16,
               "mock counter stored more than its numeric value or is incorrect")) {
        return false;
    }

    {
        FileMonotonicRevocationAnchorV2 reloaded(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(reloaded.recover() == AnchorStatus::Ok,
                   "reloaded anchor recovery failed")) {
            return false;
        }
        AnchorSnapshot snapshot{};
        if (!check(reloaded.snapshot(snapshot) == AnchorStatus::Ok &&
                       snapshot.counter == 20 && snapshot.generation == 701,
                   "reloaded anchor did not preserve committed state")) {
            return false;
        }
    }

    const auto altered_store = std::vector<std::uint8_t>{0x41, 0x42, 0x45};
    if (!check(write_bytes(store_path, altered_store),
               "same-generation tamper fixture write failed")) {
        return false;
    }
    {
        FileMonotonicRevocationAnchorV2 tamper_check(
            store_path, wal_path, counter, mac_key, anchor_id);
        AnchorSnapshot ignored{};
        if (!check(tamper_check.snapshot(ignored) == AnchorStatus::StaleSnapshot,
                   "same-generation store tampering was accepted")) {
            return false;
        }
    }
    return true;
}

bool test_counter_advance_contract() {
    TemporaryDirectory directory;
    FileMonotonicCounterV2 counter(directory.path() / "counter.bin");
    if (!check(counter.provision(3) == AnchorStatus::Ok &&
                   counter.advance(3) == CounterAdvanceResult::Applied,
               "counter did not confirm a single increment")) {
        return false;
    }
    std::uint64_t value = 0;
    if (!check(counter.read(value) == AnchorStatus::Ok && value == 4 &&
                   counter.advance(3) ==
                       CounterAdvanceResult::Indeterminate &&
                   counter.read(value) == AnchorStatus::Ok && value == 4,
               "stale counter advance was retried or misclassified")) {
        return false;
    }
    FileMonotonicCounterV2 maximum(
        directory.path() / "maximum-counter.bin");
    const auto max_value = (std::numeric_limits<std::uint64_t>::max)();
    return check(maximum.provision(max_value) == AnchorStatus::Ok &&
                     maximum.advance(max_value) ==
                         CounterAdvanceResult::NotApplied,
                 "counter overflow was not rejected as NotApplied");
}

bool test_recovery_and_wal_authentication() {
    TemporaryDirectory directory;
    const auto store_path = directory.path() / "store.bin";
    const auto wal_path = directory.path() / "anchor.wal";
    FileMonotonicCounterV2 counter(directory.path() / "counter.bin");
    std::array<std::uint8_t, 32> mac_key{};
    mac_key.fill(0x39);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0x11);
    const std::vector<std::uint8_t> old_store{1, 2, 3};
    const std::vector<std::uint8_t> next_store{4, 5, 6};
    if (!check(write_bytes(store_path, old_store) &&
                   counter.provision(5) == AnchorStatus::Ok,
               "recovery fixture initialization failed")) {
        return false;
    }

    AnchorSnapshot old_snapshot{};
    {
        FileMonotonicRevocationAnchorV2 anchor(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(anchor.provision(5, 8, digest(old_store)) ==
                       AnchorStatus::Ok &&
                       anchor.snapshot(old_snapshot) == AnchorStatus::Ok,
                   "recovery anchor provision failed")) {
            return false;
        }
        AnchorToken transaction = 0;
        if (!check(anchor.prepare_update(
                       UpdateKind::Revoke, DataKeyReference{"recover", 1},
                       old_snapshot, digest(next_store), transaction) ==
                       AnchorStatus::Ok,
                   "recovery PREPARE failed")) {
            return false;
        }
    }
    if (!check(write_bytes(store_path, old_store),
               "old store restoration failed")) {
        return false;
    }
    {
        FileMonotonicRevocationAnchorV2 recovery(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(recovery.recover() == AnchorStatus::Ok,
                   "old-state PREPARE was not safely aborted")) {
            return false;
        }
    }
    std::uint64_t current = 0;
    if (!check(counter.read(current) == AnchorStatus::Ok && current == 5,
               "ABORT changed the monotonic counter")) {
        return false;
    }

    const auto wal_bytes = read_bytes(wal_path);
    if (wal_bytes.empty() || !write_bytes(store_path, next_store)) {
        return check(false, "could not prepare WAL authentication case");
    }
    std::vector<std::uint8_t> tampered_wal = wal_bytes;
    tampered_wal.back() ^= 0x80U;
    if (!check(write_bytes(wal_path, tampered_wal),
               "tampered WAL write failed")) {
        return false;
    }
    FileMonotonicRevocationAnchorV2 tamper_check(
        store_path, wal_path, counter, mac_key, anchor_id);
    AnchorSnapshot ignored{};
    const AnchorStatus status = tamper_check.snapshot(ignored);
    return check(status == AnchorStatus::AuthenticationFailed ||
                     status == AnchorStatus::Corrupt,
                 "modified WAL was accepted");
}

bool test_crash_recovery() {
    TemporaryDirectory directory;
    const auto store_path = directory.path() / "store.bin";
    const auto wal_path = directory.path() / "anchor.wal";
    FileMonotonicCounterV2 counter(directory.path() / "counter.bin");
    std::array<std::uint8_t, 32> mac_key{};
    mac_key.fill(0x71);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0x17);
    const DataKeyReference reference{"crash-recovery", 1};
    std::vector<std::uint8_t> store{0x01};
    if (!check(write_bytes(store_path, store) &&
                   counter.provision(30) == AnchorStatus::Ok,
               "crash fixture initialization failed")) {
        return false;
    }

    AnchorSnapshot snapshot{};
    {
        FileMonotonicRevocationAnchorV2 anchor(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(anchor.provision(30, 90, digest(store)) == AnchorStatus::Ok &&
                       anchor.snapshot(snapshot) == AnchorStatus::Ok,
                   "crash fixture anchor provision failed")) {
            return false;
        }
    }
    const auto genesis_wal = read_bytes(wal_path);
    const std::vector<std::uint8_t> installed{0x02, 0x03};
    {
        FileMonotonicRevocationAnchorV2 anchor(
            store_path, wal_path, counter, mac_key, anchor_id);
        AnchorToken token = 0;
        if (!check(anchor.prepare_update(
                       UpdateKind::Issue, reference, snapshot, digest(installed),
                       token) == AnchorStatus::Ok &&
                       write_bytes(store_path, installed),
                   "store-replacement crash stage was not created")) {
            return false;
        }
    }
    {
        FileMonotonicRevocationAnchorV2 recovery(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(recovery.recover() == AnchorStatus::Ok,
                   "recovery did not forward-complete durable store replacement")) {
            return false;
        }
        if (!check(recovery.snapshot(snapshot) == AnchorStatus::Ok &&
                       snapshot.counter == 31 && snapshot.generation == 91,
                   "forward recovery did not advance exact counter/generation")) {
            return false;
        }
    }

    const std::vector<std::uint8_t> installed_again{0x04, 0x05};
    {
        FileMonotonicRevocationAnchorV2 anchor(
            store_path, wal_path, counter, mac_key, anchor_id);
        AnchorToken token = 0;
        if (!check(anchor.prepare_update(
                       UpdateKind::Revoke, reference, snapshot,
                       digest(installed_again), token) == AnchorStatus::Ok &&
                       write_bytes(store_path, installed_again),
                   "second PREPARE failed")) {
            return false;
        }
    }
    if (!check(counter.advance(31) == CounterAdvanceResult::Applied,
               "counter-after-advance crash stage failed")) {
        return false;
    }
    {
        std::ofstream output(wal_path, std::ios::binary | std::ios::app);
        const char partial[] = {'M', 'H', 'V', '2', 0};
        output.write(partial, sizeof(partial));
        output.flush();
        if (!check(static_cast<bool>(output),
                   "partial COMMIT fixture write failed")) {
            return false;
        }
    }
    {
        FileMonotonicRevocationAnchorV2 recovery(
            store_path, wal_path, counter, mac_key, anchor_id);
        if (!check(recovery.recover() == AnchorStatus::Ok,
                   "valid partial COMMIT was not reconstructed")) {
            return false;
        }
        if (!check(recovery.snapshot(snapshot) == AnchorStatus::Ok &&
                       snapshot.counter == 32 && snapshot.generation == 92 &&
                       snapshot.store_digest == digest(installed_again),
                   "reconstructed COMMIT state is incorrect")) {
            return false;
        }
    }

    if (!check(write_bytes(wal_path, genesis_wal) &&
                   write_bytes(store_path, store),
               "old complete backup fixture restore failed")) {
        return false;
    }
    {
        FileMonotonicRevocationAnchorV2 rollback(
            store_path, wal_path, counter, mac_key, anchor_id);
        AnchorSnapshot ignored{};
        if (!check(rollback.snapshot(ignored) == AnchorStatus::RollbackDetected,
                   "old WAL backup was not detected against current counter")) {
            return false;
        }
    }
    return true;
}

bool child_hold_usage(
    const std::filesystem::path& store_path,
    const std::filesystem::path& wal_path,
    const std::filesystem::path& counter_path,
    const std::filesystem::path& ready_path,
    const std::filesystem::path& release_path
) {
    std::array<std::uint8_t, 32> key{};
    key.fill(0x63);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0x23);
    FileMonotonicCounterV2 counter(counter_path);
    FileMonotonicRevocationAnchorV2 anchor(
        store_path, wal_path, counter, key, anchor_id);
    AnchorSnapshot snapshot{};
    const DataKeyReference reference{"process-lock", 1};
    AnchorToken token = 0;
    if (anchor.snapshot(snapshot) != AnchorStatus::Ok ||
        anchor.acquire_usage(reference, snapshot, token) != AnchorStatus::Ok ||
        !write_bytes(ready_path, {0x01})) {
        return false;
    }
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        if (std::filesystem::exists(release_path)) {
            return anchor.release_usage(token) == AnchorStatus::Ok;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

bool child_crash_stage(
    const std::string& stage,
    const std::filesystem::path& store_path,
    const std::filesystem::path& wal_path,
    const std::filesystem::path& counter_path,
    const std::filesystem::path& ready_path,
    const std::filesystem::path& release_path
) {
    std::array<std::uint8_t, 32> key{};
    key.fill(0x74);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0x47);
    FileMonotonicCounterV2 counter(counter_path);
    FileMonotonicRevocationAnchorV2 anchor(
        store_path, wal_path, counter, key, anchor_id);
    AnchorSnapshot snapshot{};
    const DataKeyReference reference{"process-crash", 1};
    const std::vector<std::uint8_t> candidate{0x71, 0x72};
    AnchorToken transaction = 0;
    if (anchor.snapshot(snapshot) != AnchorStatus::Ok ||
        anchor.prepare_update(UpdateKind::Issue, reference, snapshot,
                              digest(candidate), transaction) !=
            AnchorStatus::Ok) {
        return false;
    }
    if (stage != "prepare" && !write_bytes(store_path, candidate)) return false;
    if (stage == "counter" &&
        counter.advance(snapshot.counter) != CounterAdvanceResult::Applied) {
        return false;
    }
    if (stage == "commit" && anchor.commit_update(transaction) != AnchorStatus::Ok) {
        return false;
    }
    if (!write_bytes(ready_path, {0x01})) return false;
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        if (std::filesystem::exists(release_path)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

#ifdef _WIN32
std::wstring quote_argument(const std::filesystem::path& value) {
    return L"\"" + value.wstring() + L"\"";
}
#endif

class ChildProcess {
public:
    bool start(
        const std::filesystem::path& executable,
        const std::vector<std::string>& arguments
    ) {
#ifdef _WIN32
        std::wstring command = quote_argument(executable);
        for (const auto& argument : arguments) {
            command += L" \"" + std::filesystem::path(argument).wstring() + L"\"";
        }
        std::vector<wchar_t> command_line(command.begin(), command.end());
        command_line.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        return CreateProcessW(executable.c_str(), command_line.data(), nullptr,
                              nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                              &startup, &process_) != 0;
#else
        process_ = ::fork();
        if (process_ == 0) {
            std::vector<char*> argv;
            argv.reserve(arguments.size() + 2U);
            argv.push_back(const_cast<char*>(executable.c_str()));
            std::vector<std::string> storage = arguments;
            for (auto& argument : storage) argv.push_back(argument.data());
            argv.push_back(nullptr);
            ::execv(executable.c_str(), argv.data());
            _exit(127);
        }
        return process_ > 0;
#endif
    }

    bool terminate() noexcept {
#ifdef _WIN32
        if (process_.hProcess == nullptr) return false;
        const bool terminated = TerminateProcess(process_.hProcess, 9) != 0;
        const bool waited =
            WaitForSingleObject(process_.hProcess, 5000) == WAIT_OBJECT_0;
        CloseHandle(process_.hThread);
        CloseHandle(process_.hProcess);
        process_ = {};
        return terminated && waited;
#else
        if (process_ <= 0) return false;
        const bool killed = ::kill(process_, SIGKILL) == 0;
        int status = 0;
        const bool waited =
            ::waitpid(process_, &status, 0) == process_ && WIFSIGNALED(status);
        process_ = -1;
        return killed && waited;
#endif
    }

    ~ChildProcess() {
#ifdef _WIN32
        if (process_.hProcess != nullptr) {
            TerminateProcess(process_.hProcess, 1);
            WaitForSingleObject(process_.hProcess, 5000);
            CloseHandle(process_.hThread);
            CloseHandle(process_.hProcess);
        }
#else
        if (process_ > 0) {
            ::kill(process_, SIGKILL);
            ::waitpid(process_, nullptr, 0);
        }
#endif
    }

private:
#ifdef _WIN32
    PROCESS_INFORMATION process_{};
#else
    pid_t process_{-1};
#endif
};

bool test_child_crash_recovery(const std::filesystem::path& executable) {
    const std::array<std::string, 4> stages{{
        "prepare", "replace", "counter", "commit"}};
    for (const auto& stage : stages) {
        TemporaryDirectory directory;
        const auto store_path = directory.path() / "store.bin";
        const auto wal_path = directory.path() / "anchor.wal";
        const auto counter_path = directory.path() / "counter.bin";
        const auto ready_path = directory.path() / "ready";
        const auto release_path = directory.path() / "release";
        const std::vector<std::uint8_t> old_store{0x61};
        const std::vector<std::uint8_t> new_store{0x71, 0x72};
        std::array<std::uint8_t, 32> key{};
        key.fill(0x74);
        std::array<std::uint8_t, 16> anchor_id{};
        anchor_id.fill(0x47);
        FileMonotonicCounterV2 counter(counter_path);
        if (!check(write_bytes(store_path, old_store) &&
                       counter.provision(3) == AnchorStatus::Ok,
                   "child-crash fixture setup failed")) {
            return false;
        }
        {
            FileMonotonicRevocationAnchorV2 anchor(
                store_path, wal_path, counter, key, anchor_id);
            if (!check(anchor.provision(3, 10, digest(old_store)) ==
                           AnchorStatus::Ok,
                       "child-crash anchor provision failed")) {
                return false;
            }
        }

        ChildProcess child;
        if (!child.start(executable, {
                "--crash-stage", stage, store_path.string(), wal_path.string(),
                counter_path.string(), ready_path.string(),
                release_path.string()})) {
            return check(false, "could not launch crash-stage child process");
        }
        bool ready = false;
        for (unsigned attempt = 0; attempt < 500; ++attempt) {
            if (std::filesystem::exists(ready_path)) {
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        FileMonotonicRevocationAnchorV2 contender(
            store_path, wal_path, counter, key, anchor_id);
        AnchorSnapshot while_pending{};
        const AnchorStatus concurrent_usage =
            contender.snapshot(while_pending);
        const bool update_excluded_usage = stage == "commit"
            ? concurrent_usage == AnchorStatus::Ok
            : concurrent_usage == AnchorStatus::Busy;
        if (!check(ready && update_excluded_usage && child.terminate(),
                   "crash-stage child did not reach termination barrier")) {
            return false;
        }
        FileMonotonicRevocationAnchorV2 recovery(
            store_path, wal_path, counter, key, anchor_id);
        if (!check(recovery.recover() == AnchorStatus::Ok,
                   "child-process crash state did not recover safely")) {
            return false;
        }
        AnchorSnapshot state{};
        if (!check(recovery.snapshot(state) == AnchorStatus::Ok,
                   "recovered child-process state is not usable")) {
            return false;
        }
        const bool before_counter_commit = stage == "prepare";
        if (!check(state.counter == (before_counter_commit ? 3U : 4U) &&
                       state.generation == (before_counter_commit ? 10U : 11U) &&
                       state.store_digest ==
                           digest(before_counter_commit ? old_store : new_store),
                   "crash-stage recovery selected the wrong committed state")) {
            return false;
        }
    }
    return true;
}

bool test_child_process_locking(const std::filesystem::path& executable) {
    TemporaryDirectory directory;
    const auto store_path = directory.path() / "store.bin";
    const auto wal_path = directory.path() / "anchor.wal";
    const auto counter_path = directory.path() / "counter.bin";
    const auto ready_path = directory.path() / "child.ready";
    const auto release_path = directory.path() / "child.release";
    const std::vector<std::uint8_t> store{0x51};
    std::array<std::uint8_t, 32> key{};
    key.fill(0x63);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0x23);
    FileMonotonicCounterV2 counter(counter_path);
    if (!check(write_bytes(store_path, store) &&
                   counter.provision(12) == AnchorStatus::Ok,
               "child-process fixture setup failed")) {
        return false;
    }
    {
        FileMonotonicRevocationAnchorV2 anchor(
            store_path, wal_path, counter, key, anchor_id);
        if (!check(anchor.provision(12, 4, digest(store)) == AnchorStatus::Ok,
                   "child-process anchor provision failed")) {
            return false;
        }
    }

#ifdef _WIN32
    std::wstring command = quote_argument(executable) +
        L" --hold-usage " + quote_argument(store_path) + L" " +
        quote_argument(wal_path) + L" " + quote_argument(counter_path) +
        L" " + quote_argument(ready_path) + L" " +
        quote_argument(release_path);
    std::vector<wchar_t> command_line(command.begin(), command.end());
    command_line.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), command_line.data(), nullptr,
                        nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process)) {
        return check(false, "could not launch usage child process");
    }
#else
    const pid_t process = ::fork();
    if (process == 0) {
        ::execl(executable.c_str(), executable.c_str(), "--hold-usage",
                store_path.c_str(), wal_path.c_str(), counter_path.c_str(),
                ready_path.c_str(), release_path.c_str(),
                static_cast<char*>(nullptr));
        _exit(127);
    }
    if (process < 0) return check(false, "could not fork usage child process");
#endif

    bool ready = false;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        if (std::filesystem::exists(ready_path)) {
            ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!ready) {
#ifdef _WIN32
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, INFINITE);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
#else
        ::kill(process, SIGKILL);
        ::waitpid(process, nullptr, 0);
#endif
        return check(false, "child did not acquire its usage lease");
    }

    FileMonotonicRevocationAnchorV2 parent(
        store_path, wal_path, counter, key, anchor_id);
    AnchorSnapshot snapshot{};
    AnchorToken blocked = 0;
    const bool lock_blocked_update =
        parent.snapshot(snapshot) == AnchorStatus::Busy ||
        parent.prepare_update(UpdateKind::Revoke,
            DataKeyReference{"process-lock", 2}, snapshot, digest({0x52}),
            blocked) == AnchorStatus::Busy;
    const bool signaled = write_bytes(release_path, {0x02});
#ifdef _WIN32
    const DWORD wait_result = WaitForSingleObject(process.hProcess, 5000);
    DWORD exit_code = 1;
    const bool child_ok = wait_result == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process.hProcess, &exit_code) &&
        exit_code == 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
#else
    int wait_status = 0;
    const bool waited = ::waitpid(process, &wait_status, 0) == process;
    const bool child_ok = waited && WIFEXITED(wait_status) &&
        WEXITSTATUS(wait_status) == 0;
#endif
    AnchorSnapshot after{};
    const bool lock_released =
        parent.snapshot(after) == AnchorStatus::Ok;
    if (!check(signaled && lock_blocked_update && child_ok && lock_released,
               "cross-process lease did not exclude and release update lock")) {
        return false;
    }

    const auto killed_ready = directory.path() / "killed.ready";
    const auto killed_release = directory.path() / "killed.release";
#ifdef _WIN32
    command = quote_argument(executable) +
        L" --hold-usage " + quote_argument(store_path) + L" " +
        quote_argument(wal_path) + L" " + quote_argument(counter_path) +
        L" " + quote_argument(killed_ready) + L" " +
        quote_argument(killed_release);
    command_line.assign(command.begin(), command.end());
    command_line.push_back(L'\0');
    PROCESS_INFORMATION killed_process{};
    if (!CreateProcessW(executable.c_str(), command_line.data(), nullptr,
                        nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &killed_process)) {
        return check(false, "could not launch forced-termination child");
    }
#else
    const pid_t killed_process = ::fork();
    if (killed_process == 0) {
        ::execl(executable.c_str(), executable.c_str(), "--hold-usage",
                store_path.c_str(), wal_path.c_str(), counter_path.c_str(),
                killed_ready.c_str(), killed_release.c_str(),
                static_cast<char*>(nullptr));
        _exit(127);
    }
    if (killed_process < 0) {
        return check(false, "could not fork forced-termination child");
    }
#endif
    bool killed_child_ready = false;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        if (std::filesystem::exists(killed_ready)) {
            killed_child_ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
#ifdef _WIN32
    bool killed = killed_child_ready &&
        TerminateProcess(killed_process.hProcess, 9) != 0 &&
        WaitForSingleObject(killed_process.hProcess, 5000) == WAIT_OBJECT_0;
    CloseHandle(killed_process.hThread);
    CloseHandle(killed_process.hProcess);
#else
    bool killed = killed_child_ready &&
        ::kill(killed_process, SIGKILL) == 0;
    int killed_status = 0;
    killed = killed && ::waitpid(killed_process, &killed_status, 0) ==
        killed_process && WIFSIGNALED(killed_status);
#endif
    AnchorSnapshot after_kill{};
    const bool os_released_lock =
        parent.snapshot(after_kill) == AnchorStatus::Ok;
    return check(killed && os_released_lock,
                 "forced process termination did not release OS lease");
}

bool test_v2_store_integration() {
    TemporaryDirectory directory;
    const auto store_path = directory.path() / "dek-store.bin";
    const auto wal_path = directory.path() / "anchor.wal";
    FileMonotonicCounterV2 counter(directory.path() / "counter.bin");
    std::array<std::uint8_t, 32> anchor_key{};
    anchor_key.fill(0x24);
    std::array<std::uint8_t, 16> anchor_id{};
    anchor_id.fill(0x42);
    std::array<std::uint8_t, 32> kek_key{};
    kek_key.fill(0x56);
    Aes256GcmMasterKekProvider kek(kek_key);
    FileMonotonicRevocationAnchorV2 anchor(
        store_path, wal_path, counter, anchor_key, anchor_id);
    KekWrappedDataEncryptionKeyStoreV2 store(store_path, kek, anchor);
    if (!check(counter.provision(80) == AnchorStatus::Ok &&
                   store.provision(80, 900) == KeyStatus::Ok,
               "V2 store provisioning failed")) {
        return false;
    }

    DataKeyReference reference{};
    std::vector<std::uint8_t> observed_dek;
    if (!check(store.generate_key("v2-store-key", reference) == KeyStatus::Ok &&
                   reference.version == 1 &&
                   store.with_key(reference, [&](const DataKeyMaterial& key) {
                       observed_dek = key.secret();
                       return true;
                   }) == KeyStatus::Ok &&
                   observed_dek.size() == DataKeyMaterial::kAes256KeyBytes,
               "V2 store did not generate and use a persisted key")) {
        return false;
    }

    FileMonotonicRevocationAnchorV2 second_anchor(
        store_path, wal_path, counter, anchor_key, anchor_id);
    KekWrappedDataEncryptionKeyStoreV2 second_store(
        store_path, kek, second_anchor);
    if (!check(second_store.load() == KeyStatus::Ok,
               "second V2 store instance failed to load")) {
        return false;
    }

    std::mutex gate_mutex;
    std::condition_variable gate_changed;
    bool entered = false;
    bool release_callback = false;
    std::atomic<KeyStatus> callback_status{KeyStatus::BackendUnavailable};
    std::thread worker([&] {
        callback_status.store(store.with_key(
            reference, [&](const DataKeyMaterial&) {
                std::unique_lock<std::mutex> lock(gate_mutex);
                entered = true;
                gate_changed.notify_all();
                gate_changed.wait(lock, [&] { return release_callback; });
                return true;
            }));
    });
    bool callback_entered = false;
    {
        std::unique_lock<std::mutex> lock(gate_mutex);
        callback_entered = gate_changed.wait_for(
            lock, std::chrono::seconds(5), [&] { return entered; });
    }
    if (!callback_entered) {
        {
            std::lock_guard<std::mutex> lock(gate_mutex);
            release_callback = true;
        }
        gate_changed.notify_all();
        worker.join();
        return check(false, "V2 store callback failed to acquire a usage lease");
    }
    const KeyStatus active_revoke = second_store.revoke_key(reference);
    {
        std::lock_guard<std::mutex> lock(gate_mutex);
        release_callback = true;
    }
    gate_changed.notify_all();
    worker.join();
    const KeyStatus committed_revoke = second_store.revoke_key(reference);
    bool stale_callback_called = false;
    const KeyStatus stale_use = store.with_key(
        reference, [&](const DataKeyMaterial&) {
            stale_callback_called = true;
            return true;
        });
    AnchorSnapshot snapshot{};
    const bool exact_advance =
        second_anchor.snapshot(snapshot) == AnchorStatus::Ok &&
        snapshot.counter == 82 && snapshot.generation == 902;
    return check(active_revoke == KeyStatus::BackendUnavailable &&
                     callback_status.load() == KeyStatus::Ok &&
                     committed_revoke == KeyStatus::Ok &&
                     stale_use == KeyStatus::BackendUnavailable &&
                     !stale_callback_called && exact_advance,
                 "V2 store did not enforce cross-instance lease/revoke ordering");
}

bool run_tests(const std::filesystem::path& executable) {
    std::cout << "[TEST] lifecycle\n";
    if (!test_file_anchor_lifecycle()) return false;
    std::cout << "[TEST] counter contract\n";
    if (!test_counter_advance_contract()) return false;
    std::cout << "[TEST] WAL recovery\n";
    if (!test_recovery_and_wal_authentication()) return false;
    std::cout << "[TEST] crash recovery\n";
    if (!test_crash_recovery()) return false;
    std::cout << "[TEST] child process\n";
    if (!test_child_process_locking(executable)) return false;
    std::cout << "[TEST] child crash recovery\n";
    if (!test_child_crash_recovery(executable)) return false;
    std::cout << "[TEST] V2 store integration\n";
    return test_v2_store_integration();
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 7 && std::string(argv[1]) == "--hold-usage") {
            return child_hold_usage(
                argv[2], argv[3], argv[4], argv[5], argv[6]) ? 0 : 1;
        }
        if (argc == 8 && std::string(argv[1]) == "--crash-stage") {
            return child_crash_stage(
                argv[2], argv[3], argv[4], argv[5], argv[6], argv[7])
                ? 0 : 1;
        }
#ifdef _WIN32
        std::wstring executable_buffer(32768, L'\0');
        const DWORD executable_length = GetModuleFileNameW(
            nullptr, executable_buffer.data(),
            static_cast<DWORD>(executable_buffer.size()));
        if (executable_length == 0 ||
            executable_length >= executable_buffer.size()) {
            std::cerr << "[FAIL] Could not resolve test executable path\n";
            return 1;
        }
        executable_buffer.resize(executable_length);
        const std::filesystem::path executable(executable_buffer);
#else
        const std::filesystem::path executable =
            std::filesystem::absolute(argv[0]);
#endif
        if (!run_tests(executable)) return 1;
        std::cout << "[PASS] V2 file anchor lifecycle and recovery checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
