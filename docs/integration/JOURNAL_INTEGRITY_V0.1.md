# Mother_H Journal Integrity Contract v0.1

## Scope

This is a Mother_H-owned authentication and verification contract. It does not
replace or modify the imported Phase 13.2 Journal, and it does not yet provide a
filesystem journal or a production key/checkpoint backend.

## Key lifecycle

`ISecureKeyProvider` supplies the current signing key, resolves a specific
`key_id`/version for verification, rotates a key, and revokes a key. Rotation
creates a never-reused signing version; previous versions remain available for
verification until explicitly revoked. Revocation prevents further key
retrieval, including historical verification. Production providers must keep
their storage and lifecycle operations outside this header and return explicit
status values on failure.

`KeyMaterial` is move-only and uses OpenSSL `OPENSSL_cleanse` on its owned byte
buffer before clearing it. This prevents ordinary compiler optimization from
eliminating the wipe, but cannot erase provider-side copies, library internals,
or copies made elsewhere. No production secure store or platform-specific
memory-locking guarantee is provided.

## Authenticated record format

`JournalIntegrity` authenticates a deterministic binary representation:

1. Domain separator `MOTHER_H_JOURNAL_RECORD` including its terminating NUL.
2. Format version, LSN, and key version as big-endian integers.
3. Length-prefixed ASCII key ID and canonical UTC timestamp.
4. The 32-byte previous-record hash.
5. Length-prefixed binary payload.

The timestamp is required to be UTC with exactly nanosecond precision:
`YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`. Offsets, alternate precision, invalid dates,
and leap seconds are rejected rather than normalized. The HMAC-SHA256 covers
all fields above. The chain hash is SHA-256 over the canonical representation
followed by the HMAC. The first record links to the all-zero genesis hash.
HMAC and hash comparisons use OpenSSL's constant-time comparison routine.

`seal()` stages all changes in a temporary record and publishes them only
after key lookup, format validation, HMAC generation, and record-hash
generation succeed. Its commit is a statically enforced nothrow move
assignment. Failure leaves every caller-owned record field unchanged.

## External rollback anchor

`IJournalCheckpointStore` must be backed by storage independent of the Journal.
The safe `verify_chain_and_advance` overload requires a verified
`JournalStorageIdentity` and asks the checkpoint backend to attest that its
canonical backing object and rollback/trust domain are independent. Same
canonical storage, same rollback domain, missing identity, unverified identity,
or an unavailable attestation fails closed before loading the checkpoint. The
legacy overload is retained for source compatibility, but has no storage
identity and therefore always fails closed.

The identity is not a path string. A production Journal adapter must resolve
the actual backend/object identity and normalize aliases such as symbolic and
hard links; the checkpoint backend must compare that against its own canonical
identity and reject shared objects and shared snapshot/restore domains. A
different pathname or file alone is insufficient if both can be rolled back
by the same disk image, backup, administrator, or storage control plane.

This is a trust-boundary contract, not an independence guarantee implemented
by the current code. `IJournalCheckpointStore` defaults to `Unverified`; no
production identity resolver, checkpoint backend, or external trust anchor
exists yet. A backend that cannot establish independent storage and rollback
domains must return `Unverified` or `BackendUnavailable`, and recovery is
rejected. Provisioning the trusted genesis checkpoint is an external
deployment responsibility. Once isolation is attested, recovery requires the
complete Journal starting at LSN 1, verifies every record and the checkpoint's
LSN/hash pair, then atomically advances the anchor. A Journal shorter than the
anchor or with a different hash at the anchored LSN is rejected. Callers must
durably persist Journal records before advancing the external checkpoint.

## Current validation and limitations

`tests/journal/test_journal_integrity.cpp` exercises key rotation and retired
key verification, revocation, tampering, ordering, chain linkage, rollback,
checkpoint failures, timestamp validation, and provider failures using
in-memory test doubles. `test_journal_integrity_atomicity.cpp` checks full
record immutability on seal failures and successful publication.
`test_journal_checkpoint_isolation.cpp` checks fail-closed behavior for missing
or unverified identity, same canonical storage (including aliases), shared
rollback domains, and unavailable checkpoint backends. These are contract
tests with test doubles; they do not prove a production backend's attestation.

The contract is not yet wired into the existing Phase 13.2 persistence path.
There is no production key store, external checkpoint implementation,
serialized on-disk framing, atomic journal append, or recovery integration.
Those are required before this contract can be treated as an operational
Journal protection system.
