# Windows UCRT64 Debug Build / CTest Verification

- Verification date: 2026-11-17 (JST)
- Project: `mother_H_open`
- Project path: `G:\マイドライブ\mother_H_open`
- Platform: Windows
- Generator: Ninja
- Toolchain: MSYS2 UCRT64
- C++ compiler: GCC 16.2.0 (`C:\msys64\ucrt64\bin\g++.exe`)
- Build type: Debug
- OpenSSL: 3.6.4
- Boost: 1.92.0

## Result

**Build: PASS**

- Command: `cmake --build --preset default --parallel`
- Exit code: `0`
- Generated executable files observed: `51`

**CTest: PASS**

- Command: `ctest --preset default`
- Tests registered/executed: `60`
- Passed: `60`
- Failed: `0`
- Total test time: `93.45 seconds`
- Final result: `100% tests passed, 0 tests failed out of 60`

## Test list

All 60 tests passed:

1. apocalypse_chaos
2. jarvis_ignition_v2
3. journal_checkpoint_backend_fail_closed
4. journal_feedback_engine
5. journal_recovery_policy
6. mega_chaos_stress
7. mother_h_fsm_history
8. mother_h_fsm_parent
9. mother_h_fsm_security
10. mother_h_fsm_transition
11. process_killer_chaos
12. real_chaos
13. resource_guard
14. dynamic_policy_engine
15. op_executor
16. op_registry
17. policy_engine
18. dynamic_policy_execution
19. mother_h_fsm_policy_contracts
20. file_monotonic_revocation_anchor_v2
21. jour_008_fact_decoder_fuzz
22. jour_010_crypto_shredding
23. journal_checkpoint_isolation
24. journal_integrity
25. journal_integrity_atomicity
26. kek_wrapped_key_store
27. numeric_boundaries
28. op0_guard
29. op3_fermat
30. op4_tensor
31. op5_torus
32. auth_008_009_external_access_governance
33. dynamic_policy_invariants
34. feedback_and_keystore_tsan_concurrency
35. feedback_replay_atomicity_generalized
36. res_001_C1
37. res_001_C2
38. res_001_C3
39. res_001_C4
40. res_001_C5
41. res_001_C6
42. res_001_C7
43. res_002_BATCH_OK
44. res_002_LIMIT_EXACT
45. res_002_LIMIT_PLUS_ONE
46. res_002_OVERFLOW
47. res_002_ATOMICITY_THIRD_FAILURE
48. res_002_EMPTY_BATCH
49. res_bench_scale
50. checkpoint_isolation_rejections
51. checkpoint_rollback_boundary
52. checkpoint_storage_independence
53. test_contract_a_atomic_commit
54. cp01_a_persistence
55. cp01_b_corruption
56. cp01_c_immutability
57. cp02_recovery_truncate
58. feedback_engine_resume
59. file_checkpoint_fail_closed
60. journal_recovery_adapter

## Environment and configuration notes

- The default preset specifies Debug and Ninja.
- CMake required explicit UCRT64 compiler, Ninja, OpenSSL and Boost paths in this environment.
- OpenSSL include and crypto library paths were explicitly supplied to CMake.
- CMake configuration and generation completed successfully after those paths were supplied.
- The project is configured as C++ only; CMake reported that the manually supplied `CMAKE_C_COMPILER` variable was unused.

## Warnings observed

The build completed successfully, but the following compiler warnings appeared and remain review items:

- `STARTUPINFOA`: missing-field-initializers in chaos/stress test sources.
- `JournalCheckpoint`: class-memaccess warning for `std::memset` in `tests/storage/test_cp01_b_corruption.cpp`.

No warning was treated as a test failure in this Debug run. No source changes were made to address these warnings during this verification.

## Change and repository notes

- The three previously approved additions to `_assert_enabled_targets` in `CMakeLists.txt` are:
  - `test_journal_checkpoint_backend_fail_closed`
  - `test_op_registry`
  - `test_op5_torus`
- No C++ source, test source, or header files were changed during this build/test run.
- `git status` could not be used because this project directory is not a Git repository.
- This report records the observed build and test result; it is not a complete source audit.

## Scope limitation

This result confirms a successful Windows MSYS2 UCRT64 Debug build and 60/60 CTest run for this configuration.

It does **not** establish that all security requirements are satisfied, that all supported platforms have passed, or that Mother_H Security Plan v0.5 Phase 1 is complete.
