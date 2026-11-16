# Domain A License Manifest

- Status: Proposed — provenance and scope review pending
- License: Apache License 2.0
- Repository: mother_H_open
- Manifest date: 2026-11-16

## 1. Purpose

This document identifies the project-authored files proposed for
Domain A licensing in the public mother_H_open repository.

Domain A represents the publicly released Mother_H security core,
its public contracts, specifications, tests, and supporting
project configuration.

## 2. Proposed Domain A files

The following 97 files are proposed for release under
the Apache License, Version 2.0:

- `.gitignore`
- `CMakeLists.txt`
- `CMakePresets.json`
- `docs/ADR_ARCH_001_OPEN_CORE_AND_PRIVACY_BOUNDARY.md`
- `docs/ADR_AUTH_001_EPHEMERAL_KEY_MODEL.md`
- `docs/integration/JOURNAL_INTEGRITY_V0.1.md`
- `docs/integration/RESOURCE_GUARD_V0.1.md`
- `docs/PANKUNN_OS_MANIFESTO_v0.5.md`
- `docs/THIRD_PARTY_LICENSES.md`
- `include/mother_H/auth/external_access_governance.hpp`
- `include/mother_H/auth/file_transactional_registry_store.hpp`
- `include/mother_H/common/numeric.hpp`
- `include/mother_H/common/types.hpp`
- `include/mother_H/core/op_executor.hpp`
- `include/mother_H/core/op_registry.hpp`
- `include/mother_H/core/phase13_4_state_policy.hpp`
- `include/mother_H/core/policy_engine.hpp`
- `include/mother_H/fsm/fsm_engine.hpp`
- `include/mother_H/fsm/fsm_types.hpp`
- `include/mother_H/fsm/fsm_validator.hpp`
- `include/mother_H/integration/event_journal.hpp`
- `include/mother_H/integration/fsm_journal_coordinator.hpp`
- `include/mother_H/integration/fsm_journal_recovery.hpp`
- `include/mother_H/journal/journal_integrity.hpp`
- `include/mother_H/journal/journal_recovery_policy.hpp`
- `include/mother_H/journal/kek_wrapped_key_store.hpp`
- `include/mother_H/journal/kek_wrapped_key_store_v2.hpp`
- `include/mother_H/journal/monotonic_revocation_anchor_v2.hpp`
- `include/mother_H/journal/secure_key_provider.hpp`
- `include/mother_H/numeric.hpp`
- `include/mother_H/op_interface.hpp`
- `include/mother_H/op0_guard.hpp`
- `include/mother_H/op3_fermat.hpp`
- `include/mother_H/op4_tensor.hpp`
- `include/mother_H/op5_torus.hpp`
- `include/mother_H/operators/op_interface.hpp`
- `include/mother_H/operators/op0_guard.hpp`
- `include/mother_H/operators/op3_fermat.hpp`
- `include/mother_H/operators/op4_tensor.hpp`
- `include/mother_H/operators/op5_torus.hpp`
- `include/mother_H/policy/journal_feedback_engine.hpp`
- `include/mother_H/resource/resource_guard.hpp`
- `include/mother_H/storage/file_journal_checkpoint_store.hpp`
- `include/mother_H/storage/journal_recovery_adapter.hpp`
- `include/mother_H/verification/factor_verifier.hpp`
- `README.md`
- `src/main.cpp`
- `tests/core/test_dynamic_policy_engine.cpp`
- `tests/core/test_op_executor.cpp`
- `tests/core/test_op_registry.cpp`
- `tests/core/test_policy_engine.cpp`
- `tests/integration/test_dynamic_policy_execution.cpp`
- `tests/integration/test_mother_h_fsm_policy_contracts.cpp`
- `tests/journal/test_file_monotonic_revocation_anchor_v2.cpp`
- `tests/journal/test_jour_008_fact_decoder_fuzz.cpp`
- `tests/journal/test_jour_010_crypto_shredding.cpp`
- `tests/journal/test_journal_checkpoint_isolation.cpp`
- `tests/journal/test_journal_integrity.cpp`
- `tests/journal/test_journal_integrity_atomicity.cpp`
- `tests/journal/test_kek_wrapped_key_store.cpp`
- `tests/mother_h_fsm_test_support.hpp`
- `tests/numeric/test_numeric_boundaries.cpp`
- `tests/operators/test_op0_guard.cpp`
- `tests/operators/test_op3_fermat.cpp`
- `tests/operators/test_op4_tensor.cpp`
- `tests/operators/test_op5_torus.cpp`
- `tests/policy/test_auth_008_009_external_access_governance.cpp`
- `tests/policy/test_dynamic_policy_invariants.cpp`
- `tests/policy/test_feedback_and_keystore_tsan_concurrency.cpp`
- `tests/policy/test_feedback_replay_atomicity_generalized.cpp`
- `tests/resource/test_res_001_resource_guard_exception_safety.cpp`
- `tests/resource/test_res_002_resource_guard_batch_atomicity.cpp`
- `tests/resource/test_res_bench_scale.cpp`
- `tests/storage/test_checkpoint_isolation_rejections.cpp`
- `tests/storage/test_checkpoint_rollback_boundary.cpp`
- `tests/storage/test_checkpoint_storage_independence.cpp`
- `tests/storage/test_contract_a_atomic_commit.cpp`
- `tests/storage/test_cp01_a_persistence.cpp`
- `tests/storage/test_cp01_b_corruption.cpp`
- `tests/storage/test_cp01_c_immutability.cpp`
- `tests/storage/test_cp02_recovery_truncate.cpp`
- `tests/storage/test_feedback_engine_resume.cpp`
- `tests/storage/test_file_checkpoint_fail_closed.cpp`
- `tests/storage/test_journal_recovery_adapter.cpp`
- `tests/test_apocalypse_chaos.cpp`
- `tests/test_jarvis_ignition_v2.cpp`
- `tests/test_journal_checkpoint_backend_fail_closed.cpp`
- `tests/test_journal_feedback_engine.cpp`
- `tests/test_journal_recovery_policy.cpp`
- `tests/test_mega_chaos_stress.cpp`
- `tests/test_mother_h_fsm_history.cpp`
- `tests/test_mother_h_fsm_parent.cpp`
- `tests/test_mother_h_fsm_security.cpp`
- `tests/test_mother_h_fsm_transition.cpp`
- `tests/test_process_killer_chaos.cpp`
- `tests/test_real_chaos.cpp`
- `tests/test_resource_guard.cpp`

This manifest itself is also a project-authored Domain A document
and is intended to be licensed under Apache License 2.0.

## 3. License boundary

The Apache License 2.0 applies only to project-authored material
identified as Domain A in this manifest.

The presence of a file in this list does not relicense third-party
material contained in or referenced by that file. Such material
remains subject to its original license and applicable notices.

Third-party dependencies, including OpenSSL and Boost, retain
their respective licenses. See:

- `LICENSE`
- `NOTICE`
- `docs/THIRD_PARTY_LICENSES.md`

The `LICENSE` file contains the official Apache License 2.0 text.
The `NOTICE` file provides project attribution and scope information.

## 4. Provenance and exclusions

Before this manifest is accepted, each listed file must be checked
for authorship, provenance, embedded third-party material, and
domain classification.

Files containing third-party-origin material must retain the
applicable original license and notices. If a file cannot be
appropriately classified as Domain A, it must be excluded or
separated before publication.

The concrete SIGNX implementation remains outside this declaration
unless and until its implementation and threat model have been
reviewed and its domain classification has been explicitly approved.

Files outside this manifest are not automatically licensed under
Apache License 2.0 merely because they are present in the repository.

Future additions require an explicit provenance and license review
before being added to Domain A.

## 5. No security-completion claim

This license manifest defines a publication and licensing boundary.
It does not certify implementation correctness, security completeness,
production readiness, or completion of Mother_H Phase 1.

## 6. Acceptance

This manifest remains Proposed until the listed files have been
reviewed and the repository owner explicitly approves the final scope.
