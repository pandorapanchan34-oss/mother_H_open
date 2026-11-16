#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace mother_h::journal;
using namespace mother_h::policy;
using namespace mother_h::resource;

constexpr std::size_t kFuzzIterations = 10000;
constexpr std::size_t kEncodedFactSize = JournalFeedbackEngine::kEncodedFactSize;
constexpr std::uint32_t kProfileOpId = 42;
constexpr std::uint64_t kProfileTarget = 144;

class TestKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x5AU));
        return KeyStatus::Ok;
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (reference != reference_) return KeyStatus::NotFound;
        out = KeyMaterial(reference_, std::vector<std::uint8_t>(32, 0x5AU));
        return KeyStatus::Ok;
    }

    KeyStatus rotate_key(const std::string&, KeyReference&) noexcept override {
        return KeyStatus::InvalidRequest;
    }

    KeyStatus revoke_key(const KeyReference&) noexcept override {
        return KeyStatus::InvalidRequest;
    }

private:
    KeyReference reference_{"jour-008-test", 1};
};

struct FuzzCase {
    std::string name;
    std::string payload;
    FeedbackStatus expected;
};

const char* status_name(FeedbackStatus status) {
    switch (status) {
    case FeedbackStatus::Ingested: return "Ingested";
    case FeedbackStatus::IntegrityRejected: return "IntegrityRejected";
    case FeedbackStatus::InvalidPayload: return "InvalidPayload";
    case FeedbackStatus::CounterOverflow: return "CounterOverflow";
    case FeedbackStatus::InvalidFact: return "InvalidFact";
    case FeedbackStatus::ResourceRejected: return "ResourceRejected";
    case FeedbackStatus::InternalError: return "InternalError";
    }
    return "Unknown";
}

void write_u32(std::string& payload, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        const auto shift = static_cast<unsigned int>(24U - i * 8U);
        payload[offset + i] = static_cast<char>((value >> shift) & 0xFFU);
    }
}

bool make_signed_record(
    std::uint64_t lsn,
    const std::string& payload,
    const JournalHash& previous_hash,
    const ISecureKeyProvider& keys,
    JournalRecord& record,
    JournalHash& record_hash
) {
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-13T00:00:00.000000000Z";
    record.payload = payload;
    const IntegrityResult sealed =
        JournalIntegrity::seal(record, lsn, previous_hash, keys);
    if (!sealed) return false;
    record_hash = sealed.record_hash;
    return true;
}

bool same_estimate(const FeedbackEstimate& lhs, const FeedbackEstimate& rhs) {
    return lhs.status == rhs.status &&
        lhs.op_id == rhs.op_id &&
        lhs.target_structure.decimal_digits == rhs.target_structure.decimal_digits &&
        lhs.target_structure.parity == rhs.target_structure.parity &&
        lhs.target_structure.is_perfect_square == rhs.target_structure.is_perfect_square &&
        lhs.attempts == rhs.attempts &&
        lhs.successes == rhs.successes &&
        lhs.success_rate == rhs.success_rate &&
        lhs.avg_successful_steps == rhs.avg_successful_steps &&
        lhs.avg_time_us == rhs.avg_time_us;
}

int fail_case(
    std::size_t index,
    const FuzzCase& test_case,
    FeedbackStatus expected,
    FeedbackStatus actual
) {
    std::fprintf(
        stderr,
        "[FAIL] case=%zu name=%s length=%zu expected=%s actual=%s\n",
        index,
        test_case.name.c_str(),
        test_case.payload.size(),
        status_name(expected),
        status_name(actual)
    );
    return 1;
}

bool add_seed_record(
    JournalFeedbackEngine& engine,
    const ISecureKeyProvider& keys,
    std::uint64_t& next_lsn,
    JournalHash& previous_hash,
    const JournalFeedbackFact& fact
) {
    JournalRecord record;
    JournalHash record_hash{};
    const std::string payload = JournalFeedbackEngine::encode_fact_payload(fact);
    if (!make_signed_record(
            next_lsn, payload, previous_hash, keys, record, record_hash)) {
        return false;
    }
    const FeedbackIngestResult result = engine.ingest_record(record, keys);
    if (result.status != FeedbackStatus::Ingested) return false;
    previous_hash = record_hash;
    ++next_lsn;
    return true;
}

}  // namespace

int main() {
    TestKeyProvider keys;
    ResourceGuard resources(ResourceLimits{
        1024,
        128,
        16U * 1024U * 1024U,
        10020,
        16,
        16,
        1000000000,
        1000000000
    });
    JournalFeedbackEngine engine(resources);

    std::uint64_t next_lsn = 1;
    JournalHash previous_hash = JournalIntegrity::genesis_hash();
    if (!add_seed_record(
            engine, keys, next_lsn, previous_hash,
            JournalFeedbackFact{kProfileOpId, kProfileTarget, true, 10, 1000, 0}) ||
        !add_seed_record(
            engine, keys, next_lsn, previous_hash,
            JournalFeedbackFact{kProfileOpId, kProfileTarget, false, 40, 3000, 23}) ||
        !add_seed_record(
            engine, keys, next_lsn, previous_hash,
            JournalFeedbackFact{kProfileOpId, kProfileTarget, true, 30, 2000, 0})) {
        std::fprintf(stderr, "[TEST_INVALID] Failed to seed the feedback engine\n");
        return 2;
    }

    const auto seed_estimate = engine.estimate(kProfileOpId, kProfileTarget, 1);
    if (seed_estimate.status != QueryStatus::Ready ||
        seed_estimate.attempts != 3 || seed_estimate.successes != 2) {
        std::fprintf(stderr, "[TEST_INVALID] Seed profile is not ready for comparison\n");
        return 2;
    }

    std::vector<FuzzCase> cases;
    cases.reserve(kFuzzIterations);
    auto add_case = [&cases](
        std::string name,
        std::string payload,
        FeedbackStatus expected
    ) {
        cases.push_back(FuzzCase{
            std::move(name), std::move(payload), expected
        });
    };

    add_case("empty", "", FeedbackStatus::InvalidPayload);

    std::string short_payload(kEncodedFactSize - 1, '\0');
    short_payload.replace(0, 4, "MHF1");
    add_case("short-valid-header", std::move(short_payload), FeedbackStatus::InvalidPayload);

    std::string long_payload(kEncodedFactSize + 1, '\0');
    long_payload.replace(0, 4, "MHF1");
    add_case("long-valid-header", std::move(long_payload), FeedbackStatus::InvalidPayload);

    std::string max_length_payload(128, '\0');
    max_length_payload.replace(0, 4, "MHF1");
    add_case("128-bytes", std::move(max_length_payload), FeedbackStatus::InvalidPayload);

    const std::string zero_fact = JournalFeedbackEngine::encode_fact_payload(
        JournalFeedbackFact{0, 0, true, 0, 0, 0});
    for (std::size_t i = 0; i < 4; ++i) {
        std::string damaged_header = zero_fact;
        damaged_header[i] = static_cast<char>(
            static_cast<unsigned char>(damaged_header[i]) ^ 0x01U);
        add_case(
            "header-byte-" + std::to_string(i),
            std::move(damaged_header),
            FeedbackStatus::InvalidPayload
        );
    }

    std::string flag_two = JournalFeedbackEngine::encode_fact_payload(
        JournalFeedbackFact{1, 144, true, 1, 1, 0});
    flag_two[16] = static_cast<char>(2);
    add_case("success-flag-2", std::move(flag_two), FeedbackStatus::InvalidPayload);

    std::string flag_255 = JournalFeedbackEngine::encode_fact_payload(
        JournalFeedbackFact{1, 144, true, 1, 1, 0});
    flag_255[16] = static_cast<char>(0xFFU);
    add_case("success-flag-255", std::move(flag_255), FeedbackStatus::InvalidPayload);

    add_case(
        "normal-flag-one-zero-op-id",
        JournalFeedbackEngine::encode_fact_payload(
            JournalFeedbackFact{0, 144, true, 1, 1, 0}),
        FeedbackStatus::InvalidFact
    );
    add_case(
        "normal-flag-zero-zero-op-id",
        JournalFeedbackEngine::encode_fact_payload(
            JournalFeedbackFact{0, 144, false, 1, 1, 1}),
        FeedbackStatus::InvalidFact
    );

    const std::size_t boundary_offsets[] = {
        4, 7, 8, 15, 16, 17, 24, 25, 32, 33, 36
    };
    for (const std::size_t offset : boundary_offsets) {
        std::string changed_boundary = zero_fact;
        changed_boundary[offset] = static_cast<char>(
            static_cast<unsigned char>(changed_boundary[offset]) ^ 0x01U);
        add_case(
            "field-boundary-byte-" + std::to_string(offset),
            std::move(changed_boundary),
            FeedbackStatus::InvalidFact
        );
    }

    std::mt19937 random_engine(0x4A4F5552U);
    std::uniform_int_distribution<unsigned int> random_byte(0, 255);
    std::uniform_int_distribution<std::size_t> random_length(0, 128);
    const std::size_t random_start = cases.size();
    while (cases.size() < kFuzzIterations) {
        const std::size_t random_case_index = cases.size() - random_start;
        if (random_case_index % 2 == 0) {
            std::string shaped(kEncodedFactSize, '\0');
            for (char& byte : shaped) {
                byte = static_cast<char>(random_byte(random_engine));
            }
            shaped.replace(0, 4, "MHF1");
            write_u32(shaped, 4, 0);
            shaped[16] = static_cast<char>(random_case_index % 4 == 0 ? 0 : 1);
            add_case(
                "random-valid-shape",
                std::move(shaped),
                FeedbackStatus::InvalidFact
            );
        } else {
            const std::size_t length = random_length(random_engine);
            std::string random_payload(length, '\0');
            for (char& byte : random_payload) {
                byte = static_cast<char>(random_byte(random_engine));
            }
            if (length == kEncodedFactSize) random_payload[0] = 'X';
            add_case(
                "random-bytes",
                std::move(random_payload),
                FeedbackStatus::InvalidPayload
            );
        }
    }

    std::size_t invalid_payload_count = 0;
    std::size_t invalid_fact_count = 0;
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const FuzzCase& test_case = cases[i];
        JournalRecord record;
        JournalHash record_hash{};
        if (!make_signed_record(
                next_lsn, test_case.payload, previous_hash, keys, record, record_hash)) {
            std::fprintf(
                stderr,
                "[TEST_INVALID] case=%zu name=%s length=%zu could not be sealed\n",
                i,
                test_case.name.c_str(),
                test_case.payload.size()
            );
            return 2;
        }

        const auto stats_before = engine.stats();
        const FeedbackEstimate estimate_before =
            engine.estimate(kProfileOpId, kProfileTarget, 1);
        const FeedbackIngestResult result = engine.ingest_record(record, keys);
        if (result.status == FeedbackStatus::ResourceRejected) {
            return fail_case(
                i, test_case, test_case.expected, result.status
            );
        }
        if (result.status != test_case.expected) {
            return fail_case(
                i, test_case, test_case.expected, result.status
            );
        }
        if (result.integrity_status != IntegrityStatus::Ok) {
            std::fprintf(
                stderr,
                "[FAIL] case=%zu name=%s length=%zu expected=IntegrityStatus::Ok actual=%u\n",
                i,
                test_case.name.c_str(),
                test_case.payload.size(),
                static_cast<unsigned int>(result.integrity_status)
            );
            return 1;
        }
        if (engine.stats().size() != stats_before.size() ||
            engine.stats() != stats_before) {
            std::fprintf(
                stderr,
                "[FAIL] case=%zu name=%s length=%zu expected=unchanged profiles (%zu) actual=%zu\n",
                i,
                test_case.name.c_str(),
                test_case.payload.size(),
                stats_before.size(),
                engine.stats().size()
            );
            return 1;
        }
        if (!same_estimate(
                estimate_before,
                engine.estimate(kProfileOpId, kProfileTarget, 1))) {
            std::fprintf(
                stderr,
                "[FAIL] case=%zu name=%s length=%zu expected=unchanged estimate actual=changed\n",
                i,
                test_case.name.c_str(),
                test_case.payload.size()
            );
            return 1;
        }

        if (result.status == FeedbackStatus::InvalidPayload) {
            ++invalid_payload_count;
        } else if (result.status == FeedbackStatus::InvalidFact) {
            ++invalid_fact_count;
        }
        previous_hash = record_hash;
        ++next_lsn;
    }

    JournalRecord valid_next_record;
    JournalHash valid_next_hash{};
    const std::string valid_next_payload =
        JournalFeedbackEngine::encode_fact_payload(
            JournalFeedbackFact{kProfileOpId, kProfileTarget, true, 5, 500, 0});
    if (!make_signed_record(
            next_lsn,
            valid_next_payload,
            previous_hash,
            keys,
            valid_next_record,
            valid_next_hash)) {
        std::fprintf(stderr, "[TEST_INVALID] Could not seal the post-fuzz valid record\n");
        return 2;
    }

    const FeedbackIngestResult valid_next_result =
        engine.ingest_record(valid_next_record, keys);
    if (valid_next_result.status != FeedbackStatus::Ingested ||
        valid_next_result.integrity_status != IntegrityStatus::Ok) {
        std::fprintf(
            stderr,
            "[FAIL] post-fuzz lsn=%llu expected=Ingested actual=%s\n",
            static_cast<unsigned long long>(next_lsn),
            status_name(valid_next_result.status)
        );
        return 1;
    }

    const FeedbackEstimate final_estimate =
        engine.estimate(kProfileOpId, kProfileTarget, 1);
    if (final_estimate.status != QueryStatus::Ready ||
        final_estimate.attempts != 4 ||
        final_estimate.successes != 3) {
        std::fprintf(stderr, "[FAIL] valid next-LSN record did not update the profile\n");
        return 1;
    }

    std::printf(
        "[PASS] JOUR-008 iterations=%zu InvalidPayload=%zu InvalidFact=%zu next_lsn=%llu\n",
        cases.size(),
        invalid_payload_count,
        invalid_fact_count,
        static_cast<unsigned long long>(next_lsn)
    );
    return 0;
}
