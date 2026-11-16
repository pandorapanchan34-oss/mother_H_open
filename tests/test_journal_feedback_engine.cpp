#include "mother_H/policy/journal_feedback_engine.hpp"
#include "mother_H/resource/resource_guard.hpp"

#include <cassert>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace mother_h::journal;
using namespace mother_h::policy;
using namespace mother_h::resource;

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
    KeyReference reference_{"feedback-test", 1};
};

void check(bool condition) {
    assert(condition);
}

JournalRecord make_record(
    std::uint64_t lsn,
    const JournalFeedbackFact& fact,
    const JournalHash& previous_hash,
    const ISecureKeyProvider& keys
) {
    JournalRecord record;
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-04T03:12:45.123000000Z";
    record.payload = JournalFeedbackEngine::encode_fact_payload(fact);
    const IntegrityResult sealed =
        JournalIntegrity::seal(record, lsn, previous_hash, keys);
    check(static_cast<bool>(sealed));
    return record;
}
}  // namespace

int main() {
    TestKeyProvider keys;
    ResourceGuard resources(ResourceLimits{
        512, 128, 8192, 8, 4, 4, 10000, 1000000
    });
    JournalFeedbackEngine engine(resources);
    const JournalHash genesis = JournalIntegrity::genesis_hash();
    const JournalFeedbackFact successful_first{7, 144, true, 10, 1000, 0};
    const JournalFeedbackFact failed{7, 144, false, 40, 3000, 23};
    const JournalFeedbackFact successful_second{7, 144, true, 30, 2000, 0};

    check(engine.stats().empty());
    check(engine.predict_success_rate(7, 144) == 0.20);
    const auto no_data = engine.estimate(7, 144);
    check(no_data.status == QueryStatus::NoData);
    check(!no_data.success_rate.has_value());
    check(engine.estimate(0, 144).status == QueryStatus::InvalidQuery);
    check(engine.estimate(7, 0).status == QueryStatus::InvalidQuery);
    check(engine.estimate(7, 144, 0).status == QueryStatus::InvalidQuery);

    JournalRecord first = make_record(1, successful_first, genesis, keys);
    check(static_cast<bool>(engine.ingest_record(first, keys)));
    check(engine.predict_success_rate(7, 144) == 0.20);
    const auto one_sample = engine.estimate(7, 144);
    check(one_sample.status == QueryStatus::InsufficientSamples);
    check(one_sample.attempts == 1);
    check(one_sample.successes == 1);
    check(!one_sample.success_rate.has_value());
    check(one_sample.target_structure.decimal_digits == 3);
    check(one_sample.target_structure.parity == TargetParity::Even);
    check(one_sample.target_structure.is_perfect_square);

    const IntegrityResult first_verified =
        JournalIntegrity::verify(first, 1, genesis, keys);
    JournalRecord tampered = make_record(2, failed, first_verified.record_hash, keys);
    tampered.payload[20] ^= 0x01;
    const auto rejected = engine.ingest_record(tampered, keys);
    check(rejected.status == FeedbackStatus::IntegrityRejected);
    check(rejected.integrity_status == IntegrityStatus::HmacMismatch);
    check(engine.stats().size() == 1);
    check(engine.stats().begin()->second.attempts == 1);
    check(engine.estimate(7, 144).attempts == 1);
    ResourceUsage after_tamper_usage;
    check(resources.usage(after_tamper_usage) == ResourceStatus::Ok);
    check(after_tamper_usage.records == 1);

    JournalRecord second = make_record(2, failed, first_verified.record_hash, keys);
    check(static_cast<bool>(
        engine.ingest_record(second, keys)));
    check(engine.predict_success_rate(7, 144) == 0.20);
    check(engine.estimate(7, 144).status == QueryStatus::InsufficientSamples);

    const IntegrityResult second_verified =
        JournalIntegrity::verify(second, 2, first_verified.record_hash, keys);
    JournalRecord third =
        make_record(3, successful_second, second_verified.record_hash, keys);
    check(static_cast<bool>(
        engine.ingest_record(third, keys)));

    const auto profiles = engine.stats();
    const auto& profile = profiles.begin()->second;
    check(profile.attempts == 3);
    check(profile.successes == 2);
    check(profile.total_steps_used == 80);
    check(profile.successful_steps_used == 40);
    check(profile.avg_steps_on_success() == 20);
    check(profile.total_time_us == 6000);
    check(profile.failure_codes.at(23) == 1);
    check(engine.predict_success_rate(7, 144) == (2.0 / 3.0));
    const auto ready = engine.estimate(7, 144);
    check(ready.status == QueryStatus::Ready);
    check(ready.attempts == 3);
    check(ready.successes == 2);
    check(ready.success_rate.has_value());
    check(*ready.success_rate == (2.0 / 3.0));
    check(*ready.success_rate != 0.20);
    check(engine.estimate(7, 144, 4).status ==
          QueryStatus::InsufficientSamples);

    ResourceGuard inconsistent_resources(ResourceLimits{
        512, 128, 4096, 4, 2, 2, 1000, 100000
    });
    JournalFeedbackEngine inconsistent_profile_engine(inconsistent_resources);
    JournalRecord consistent_record = make_record(1, successful_first, genesis, keys);
    check(static_cast<bool>(
        inconsistent_profile_engine.ingest_record(consistent_record, keys)));
    check(inconsistent_profile_engine.corrupt_profile_for_test(7, 144));
    const auto inconsistent_estimate =
        inconsistent_profile_engine.estimate(7, 144, 1);
    check(inconsistent_estimate.status == QueryStatus::InconsistentProfile);
    check(!inconsistent_estimate.success_rate.has_value());

    ResourceGuard lsn_resources(ResourceLimits{
        512, 128, 4096, 4, 2, 2, 1000, 100000
    });
    JournalFeedbackEngine lsn_engine(lsn_resources);
    JournalRecord out_of_order = make_record(2, successful_first, genesis, keys);
    check(lsn_engine.ingest_record(out_of_order, keys).status ==
          FeedbackStatus::IntegrityRejected);
    check(lsn_engine.stats().empty());
    JournalRecord first_lsn = make_record(1, successful_first, genesis, keys);
    check(static_cast<bool>(lsn_engine.ingest_record(first_lsn, keys)));
    check(lsn_engine.estimate(7, 144).status ==
          QueryStatus::InsufficientSamples);

    const auto stats_size_before_queries = engine.stats().size();
    const auto attempts_before_queries = profile.attempts;
    const auto successes_before_queries = profile.successes;
    (void)engine.estimate(7, 144);
    check(engine.stats().size() == stats_size_before_queries);
    check(profile.attempts == attempts_before_queries);
    check(profile.successes == successes_before_queries);
    const IntegrityResult third_verified =
        JournalIntegrity::verify(third, 3, second_verified.record_hash, keys);
    JournalRecord fourth =
        make_record(4, successful_first, third_verified.record_hash, keys);
    check(static_cast<bool>(engine.ingest_record(fourth, keys)));
    check(engine.stats().begin()->second.attempts == 4);

    JournalFeedbackEngine invalid_payload_engine(resources);
    JournalRecord malformed;
    malformed.lsn = 1;
    malformed.timestamp_utc = "2026-11-04T03:12:45.123000000Z";
    malformed.payload = "not-a-feedback-fact";
    const IntegrityResult malformed_seal =
        JournalIntegrity::seal(malformed, 1, genesis, keys);
    check(static_cast<bool>(malformed_seal));
    check(invalid_payload_engine.ingest_record(malformed, keys).status ==
          FeedbackStatus::InvalidPayload);
    check(invalid_payload_engine.stats().empty());
    JournalRecord after_malformed =
        make_record(2, successful_first, malformed_seal.record_hash, keys);
    check(static_cast<bool>(invalid_payload_engine.ingest_record(after_malformed, keys)));
    check(invalid_payload_engine.stats().begin()->second.attempts == 1);

    JournalFeedbackEngine capped_engine(resources);
    const JournalFeedbackFact inconsistent_success{8, 221, true, 4, 50, 23};
    JournalRecord inconsistent = make_record(
        1, inconsistent_success, genesis, keys);
    check(capped_engine.ingest_record(inconsistent, keys).status ==
          FeedbackStatus::InvalidFact);
    check(capped_engine.stats().empty());
    check(capped_engine.estimate(8, 221).status == QueryStatus::NoData);

    ResourceGuard profile_limited_resources(ResourceLimits{
        512, 128, 4096, 4, 1, 1, 1000, 100000
    });
    JournalFeedbackEngine profile_limited_engine(profile_limited_resources);
    JournalRecord profile_first = make_record(1, successful_first, genesis, keys);
    check(static_cast<bool>(
        profile_limited_engine.ingest_record(profile_first, keys)));
    const auto profile_first_verified =
        JournalIntegrity::verify(profile_first, 1, genesis, keys);
    const JournalFeedbackFact other_profile{8, 221, true, 4, 50, 0};
    JournalRecord profile_second = make_record(
        2, other_profile, profile_first_verified.record_hash, keys);
    const auto profile_rejected =
        profile_limited_engine.ingest_record(profile_second, keys);
    check(profile_rejected.status == FeedbackStatus::ResourceRejected);
    check(profile_rejected.resource_status == ResourceStatus::LimitExceeded);
    check(profile_limited_engine.stats().size() == 1);
    ResourceUsage profile_limited_usage;
    check(profile_limited_resources.usage(profile_limited_usage) ==
          ResourceStatus::Ok);
    check(profile_limited_usage.records == 1);

    ResourceGuard failure_limited_resources(ResourceLimits{
        512, 128, 4096, 4, 1, 1, 1000, 100000
    });
    JournalFeedbackEngine failure_limited_engine(failure_limited_resources);
    JournalRecord failure_first = make_record(1, successful_first, genesis, keys);
    check(static_cast<bool>(
        failure_limited_engine.ingest_record(failure_first, keys)));
    const auto failure_first_verified =
        JournalIntegrity::verify(failure_first, 1, genesis, keys);
    JournalRecord failure_second = make_record(
        2, failed, failure_first_verified.record_hash, keys);
    check(static_cast<bool>(
        failure_limited_engine.ingest_record(failure_second, keys)));
    const auto failure_second_verified =
        JournalIntegrity::verify(
            failure_second, 2, failure_first_verified.record_hash, keys);
    const JournalFeedbackFact another_failure{7, 144, false, 5, 600, 24};
    JournalRecord failure_third = make_record(
        3, another_failure, failure_second_verified.record_hash, keys);
    const auto failure_rejected =
        failure_limited_engine.ingest_record(failure_third, keys);
    check(failure_rejected.status == FeedbackStatus::ResourceRejected);
    check(failure_rejected.resource_status == ResourceStatus::LimitExceeded);
    check(failure_limited_engine.stats().begin()->second.attempts == 2);
    check(failure_limited_engine.stats().begin()->second.failure_codes.size() == 1);
    ResourceUsage failure_limited_usage;
    check(failure_limited_resources.usage(failure_limited_usage) ==
          ResourceStatus::Ok);
    check(failure_limited_usage.records == 2);
    check(failure_limited_usage.failure_code_entries == 1);

    ResourceGuard record_limited_resources(ResourceLimits{
        512, 128, 4096, 1, 1, 1, 1000, 100000
    });
    JournalFeedbackEngine record_limited_engine(record_limited_resources);
    JournalRecord record_first = make_record(1, successful_first, genesis, keys);
    check(static_cast<bool>(record_limited_engine.ingest_record(record_first, keys)));
    const auto record_first_verified =
        JournalIntegrity::verify(record_first, 1, genesis, keys);
    JournalRecord record_second = make_record(
        2, failed, record_first_verified.record_hash, keys);
    const auto record_rejected =
        record_limited_engine.ingest_record(record_second, keys);
    check(record_rejected.status == FeedbackStatus::ResourceRejected);
    check(record_rejected.resource_status == ResourceStatus::LimitExceeded);
    check(record_limited_engine.stats().begin()->second.attempts == 1);
    ResourceUsage record_limited_usage;
    check(record_limited_resources.usage(record_limited_usage) ==
          ResourceStatus::Ok);
    check(record_limited_usage.records == 1);

    ResourceGuard boundary_resources(ResourceLimits{
        512, 128, 4096, 2, 2, 2, 1000, 100000
    });
    JournalFeedbackEngine boundary_engine(boundary_resources);
    const std::uint64_t maximum_target =
        (std::numeric_limits<std::uint64_t>::max)();
    const JournalFeedbackFact boundary_fact{
        9, maximum_target, true, 1, 1, 0
    };
    JournalRecord boundary_record =
        make_record(1, boundary_fact, genesis, keys);
    check(static_cast<bool>(boundary_engine.ingest_record(boundary_record, keys)));
    const auto boundary_estimate =
        boundary_engine.estimate(9, maximum_target, 1);
    check(boundary_estimate.status == QueryStatus::Ready);
    check(boundary_estimate.target_structure.decimal_digits == 20);
    check(boundary_estimate.target_structure.parity == TargetParity::Odd);
    check(!boundary_estimate.target_structure.is_perfect_square);

    return 0;
}
