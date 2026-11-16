#include "mother_H/journal/journal_integrity.hpp"

#include <cassert>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace mother_h::journal;

class TestKeyProvider final : public ISecureKeyProvider {
public:
    KeyStatus current_signing_key(KeyMaterial& out) const noexcept override {
        if (status_ != KeyStatus::Ok) return status_;
        out = KeyMaterial(
            reference_, std::vector<std::uint8_t>(secret_size_, 0x5AU));
        return KeyStatus::Ok;
    }

    KeyStatus verification_key(
        const KeyReference& reference,
        KeyMaterial& out
    ) const noexcept override {
        if (status_ != KeyStatus::Ok) return status_;
        if (reference != reference_) return KeyStatus::NotFound;
        out = KeyMaterial(
            reference_, std::vector<std::uint8_t>(secret_size_, 0x5AU));
        return KeyStatus::Ok;
    }

    KeyStatus rotate_key(
        const std::string&,
        KeyReference&
    ) noexcept override {
        return KeyStatus::InvalidRequest;
    }

    KeyStatus revoke_key(const KeyReference& reference) noexcept override {
        if (reference != reference_) return KeyStatus::NotFound;
        status_ = KeyStatus::Revoked;
        return KeyStatus::Ok;
    }

    void set_status(KeyStatus status) noexcept { status_ = status; }
    void set_secret_size(std::size_t size) noexcept { secret_size_ = size; }

private:
    KeyReference reference_{"atomicity-test", 1};
    std::size_t secret_size_{32};
    KeyStatus status_{KeyStatus::Ok};
};

void check(bool condition) {
    assert(condition);
}

bool same_record(const JournalRecord& left, const JournalRecord& right) {
    return left.lsn == right.lsn &&
        left.timestamp_utc == right.timestamp_utc &&
        left.key == right.key &&
        left.previous_record_hash == right.previous_record_hash &&
        left.payload == right.payload &&
        left.hmac_sha256 == right.hmac_sha256;
}

JournalRecord make_record(std::uint64_t lsn = 7) {
    JournalRecord record;
    record.lsn = lsn;
    record.timestamp_utc = "2026-11-04T11:55:01.042000000Z";
    record.key = KeyReference{"preexisting-key", 12};
    record.previous_record_hash.fill(0x31U);
    record.payload = std::string("payload\0with-binary", 19);
    record.hmac_sha256.fill(0x72U);
    return record;
}

void expect_failure_unchanged(
    JournalRecord record,
    const ISecureKeyProvider& provider,
    const JournalHash& previous_hash,
    IntegrityStatus expected_status
) {
    const JournalRecord before = record;
    const IntegrityResult result =
        JournalIntegrity::seal(record, record.lsn, previous_hash, provider);
    check(result.status == expected_status);
    check(same_record(record, before));
}

}  // namespace

int main() {
    TestKeyProvider keys;
    const JournalHash previous_hash = [] {
        JournalHash value{};
        value.fill(0xA7U);
        return value;
    }();

    keys.set_status(KeyStatus::BackendUnavailable);
    expect_failure_unchanged(
        make_record(), keys, previous_hash,
        IntegrityStatus::KeyProviderUnavailable);

    keys.set_status(KeyStatus::Ok);
    JournalRecord revoked_record = make_record();
    check(keys.revoke_key(KeyReference{"atomicity-test", 1}) == KeyStatus::Ok);
    expect_failure_unchanged(
        revoked_record, keys, previous_hash, IntegrityStatus::KeyRevoked);

    keys.set_status(KeyStatus::Ok);
    JournalRecord malformed = make_record();
    malformed.timestamp_utc = "not-a-canonical-utc-timestamp";
    expect_failure_unchanged(
        malformed, keys, previous_hash, IntegrityStatus::InvalidTimestamp);

    keys.set_secret_size(16);
    expect_failure_unchanged(
        make_record(), keys, previous_hash,
        IntegrityStatus::InvalidKeyReference);

    keys.set_secret_size(32);
    JournalRecord successful = make_record();
    const JournalRecord before_success = successful;
    const IntegrityResult sealed =
        JournalIntegrity::seal(successful, successful.lsn, previous_hash, keys);
    check(static_cast<bool>(sealed));
    check(successful.lsn == before_success.lsn);
    check(successful.timestamp_utc == before_success.timestamp_utc);
    check(successful.payload == before_success.payload);
    check(successful.key == KeyReference{"atomicity-test", 1});
    check(successful.previous_record_hash == previous_hash);
    check(successful.hmac_sha256 != before_success.hmac_sha256);

    const IntegrityResult verified = JournalIntegrity::verify(
        successful, successful.lsn, previous_hash, keys);
    check(static_cast<bool>(verified));
    check(verified.record_hash == sealed.record_hash);

    return 0;
}
