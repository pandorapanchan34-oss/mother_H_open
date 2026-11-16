# ResourceGuard v0.1

## Responsibility

`mother_h::resource::ResourceGuard` is an independent, fail-closed resource
accounting layer. It does not execute or cancel work and is not a substitute
for Journal authentication, HMAC, LSN, or hash-chain validation. Its limits
cannot be changed by Policy or learned feedback.

## Limits

`ResourceLimits` requires positive, explicit values for all fields. A zero
value is invalid; it never means unlimited.

| Field | Meaning |
|---|---|
| `max_record_bytes` | Largest individual record accepted by a reservation |
| `max_payload_bytes` | Largest payload within an individual record |
| `max_total_input_bytes` | Cumulative input bytes |
| `max_records` | Cumulative records |
| `max_profiles` | Maximum distinct profile identifiers |
| `max_failure_codes_per_profile` | Maximum distinct failure-code identifiers per profile |
| `max_steps` | Cumulative step budget |
| `max_elapsed_time_us` | Cumulative elapsed-time budget in microseconds |

## API

- `check_input_sizes`, `check_record_count`, `check_profile`,
  `check_failure_code`, `check_total_input_bytes`, `check_steps`, and
  `check_elapsed_time_us` perform non-consuming checks.
- `reserve` atomically validates and consumes all requested dimensions.
  Record bytes, payload bytes, total input bytes, and record count may be
  combined with profile/failure-code tracking, steps, and elapsed time.
- `consume_input`, `consume_record_count`, `consume_profile`,
  `consume_failure_code`, `consume_steps`, and `consume_elapsed_time_us`
  are focused reservation helpers.
- `usage` returns a consistent usage snapshot. `remaining_steps` and
  `remaining_time_us` provide remaining budgets.
- `reset_usage` explicitly clears usage and tracked profile identifiers.
- `status` reports invalid limits or inconsistent internal usage.

Input size checks are intended to run before allocating or reading a record.
Time is supplied by the caller as elapsed microseconds; the guard does not
select a clock, measure time, interrupt work, or guarantee a deadline.

All `OpExecutor::execute` entry points require a `ResourceGuard` and reserve
the request's full step and time budgets before invoking operators. This is
conservative: early completion does not refund unused capacity. Operators are
cooperative, so synchronous calls cannot be forcibly interrupted.

`JournalFeedbackEngine` requires a guard at construction. Ingest accounts the
record's declared size before HMAC verification. After authentication and
Fact validation, it atomically reserves record, byte, step, time, profile, and
failure-code budgets before committing statistics. Failed authentication does
not consume guard usage. The caller must keep the guard alive for the engine's
lifetime. This occurs after a `JournalRecord` object already exists and does
not replace a bounded reader that checks file size before reading. Feedback
statistics are in-memory only; a newly constructed engine does not have
persistent deduplication or anti-rollback state.

## Status and fail-closed behavior

`ResourceStatus` values are `Ok`, `LimitExceeded`, `InvalidLimits`,
`InvalidRequest`, `IntegerOverflow`, and `InternalError`. Invalid limits,
zero consumption requests, malformed reservations, limit exceedance,
arithmetic overflow, allocation/lock failures, and inconsistent state do not
consume the requested resources.

## Overflow and atomicity

For every counter, the implementation checks `requested > UINT64_MAX - current`
before addition, then checks the configured remaining limit. A reservation
validates every scalar budget and profile/failure-code capacity before
committing counters. Profile insertion is rolled back if failure-code
allocation fails. Counter changes occur only after validation and required
tracking allocations succeed.

## Thread safety

All checks, reservations, snapshots, and resets are serialized with an
internal mutex. A check followed later by a separate consume is not a
reservation and can race with another caller; use `reserve` to make the check
and consumption atomic.

## Not implemented

- No file-reader, JournalRecoveryPolicy, or DynamicPolicyEngine integration.
- No automatic clock, cancellation, memory/RSS measurement, or streaming I/O.
- The guard accounts for declared limits and identifiers; it cannot prove
  callers reported actual allocation/input sizes.
- Limits are immutable after construction; changing them requires creating a
  new guard and explicitly transferring policy at a higher layer.

## Future integration

Callers should check individual record/payload size before reading or
allocating. Existing Executor and Feedback integrations reserve through this
guard; future file-reader and recovery integrations must preserve the same
separation and treat all non-`Ok` statuses as refusal. Journal integrity
verification remains a separate prerequisite. Policy may request work, but it
cannot raise these guard limits.
