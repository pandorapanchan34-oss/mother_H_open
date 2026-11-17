cmake_minimum_required(VERSION 3.16)
project(mother_H VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(MOTHER_H_WERROR "Treat warnings as errors on GCC and Clang" OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
find_package(Boost 1.70 REQUIRED CONFIG)

add_library(mother_h_core INTERFACE)
target_include_directories(mother_h_core INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_compile_features(mother_h_core INTERFACE cxx_std_17)
target_link_libraries(mother_h_core INTERFACE
    OpenSSL::Crypto
    Threads::Threads
    Boost::boost
)

add_executable(mother_H_engine src/main.cpp)
target_link_libraries(mother_H_engine PRIVATE mother_h_core)

include(CTest)
if(BUILD_TESTING)
    set(MOTHER_H_TEST_SOURCES
        tests/test_apocalypse_chaos.cpp
        tests/test_jarvis_ignition_v2.cpp
        tests/test_journal_checkpoint_backend_fail_closed.cpp
        tests/test_journal_feedback_engine.cpp
        tests/test_journal_recovery_policy.cpp
        tests/test_mega_chaos_stress.cpp
        tests/test_mother_h_fsm_history.cpp
        tests/test_mother_h_fsm_parent.cpp
        tests/test_mother_h_fsm_security.cpp
        tests/test_mother_h_fsm_transition.cpp
        tests/test_process_killer_chaos.cpp
        tests/test_real_chaos.cpp
        tests/test_resource_guard.cpp
        tests/core/test_dynamic_policy_engine.cpp
        tests/core/test_op_executor.cpp
        tests/core/test_op_registry.cpp
        tests/core/test_policy_engine.cpp
        tests/integration/test_dynamic_policy_execution.cpp
        tests/integration/test_mother_h_fsm_policy_contracts.cpp
        tests/journal/test_file_monotonic_revocation_anchor_v2.cpp
        tests/journal/test_jour_008_fact_decoder_fuzz.cpp
        tests/journal/test_jour_010_crypto_shredding.cpp
        tests/journal/test_journal_checkpoint_isolation.cpp
        tests/journal/test_journal_integrity.cpp
        tests/journal/test_journal_integrity_atomicity.cpp
        tests/journal/test_kek_wrapped_key_store.cpp
        tests/numeric/test_numeric_boundaries.cpp
        tests/operators/test_op0_guard.cpp
        tests/operators/test_op3_fermat.cpp
        tests/operators/test_op4_tensor.cpp
        tests/operators/test_op5_torus.cpp
        tests/policy/test_auth_008_009_external_access_governance.cpp
        tests/policy/test_dynamic_policy_invariants.cpp
        tests/policy/test_feedback_and_keystore_tsan_concurrency.cpp
        tests/policy/test_feedback_replay_atomicity_generalized.cpp
        tests/resource/test_res_001_resource_guard_exception_safety.cpp
        tests/resource/test_res_002_resource_guard_batch_atomicity.cpp
        tests/resource/test_res_bench_scale.cpp
        tests/storage/test_checkpoint_isolation_rejections.cpp
        tests/storage/test_checkpoint_rollback_boundary.cpp
        tests/storage/test_checkpoint_storage_independence.cpp
        tests/storage/test_contract_a_atomic_commit.cpp
        tests/storage/test_cp01_a_persistence.cpp
        tests/storage/test_cp01_b_corruption.cpp
        tests/storage/test_cp01_c_immutability.cpp
        tests/storage/test_cp02_recovery_truncate.cpp
        tests/storage/test_feedback_engine_resume.cpp
        tests/storage/test_file_checkpoint_fail_closed.cpp
        tests/storage/test_journal_recovery_adapter.cpp
    )

    set(MOTHER_H_TEST_TARGETS)
    foreach(_source IN LISTS MOTHER_H_TEST_SOURCES)
        get_filename_component(_target "${_source}" NAME_WE)
        add_executable("${_target}" "${_source}")
        target_link_libraries("${_target}" PRIVATE mother_h_core)
        list(APPEND MOTHER_H_TEST_TARGETS "${_target}")

        string(REGEX REPLACE "^test_" "" _test_name "${_target}")
        if(_target STREQUAL "test_contract_a_atomic_commit")
            set(_test_name "${_target}")
        endif()

        if(_target STREQUAL "test_res_001_resource_guard_exception_safety")
            foreach(_case C1 C2 C3 C4 C5 C6 C7)
                add_test(NAME "res_001_${_case}"
                    COMMAND "${_target}" "--case=${_case}")
            endforeach()
        elseif(_target STREQUAL "test_res_002_resource_guard_batch_atomicity")
            foreach(_case BATCH_OK LIMIT_EXACT LIMIT_PLUS_ONE OVERFLOW
                          ATOMICITY_THIRD_FAILURE EMPTY_BATCH)
                add_test(NAME "res_002_${_case}"
                    COMMAND "${_target}" "--case=${_case}")
            endforeach()
        else()
            add_test(NAME "${_test_name}" COMMAND "${_target}")
        endif()
    endforeach()

    # MinGW runtime DLLs: make them available to every CTest test.
    if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        get_filename_component(_mother_h_compiler_bin
            "${CMAKE_CXX_COMPILER}" DIRECTORY
        )
        string(REPLACE ";" "\\;" _mother_h_test_path
            "${_mother_h_compiler_bin};$ENV{PATH}"
        )
        get_property(_mother_h_ctest_names DIRECTORY PROPERTY TESTS)
        if(_mother_h_ctest_names)
            set_tests_properties(${_mother_h_ctest_names}
                PROPERTIES ENVIRONMENT "PATH=${_mother_h_test_path}"
            )
        endif()
    endif()
    set_tests_properties(
        jarvis_ignition_v2
        real_chaos
        process_killer_chaos
        mega_chaos_stress
        apocalypse_chaos
        PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    set_tests_properties(
        jour_008_fact_decoder_fuzz
        kek_wrapped_key_store
        file_monotonic_revocation_anchor_v2
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        feedback_and_keystore_tsan_concurrency
        PROPERTIES TIMEOUT 180
    )

    target_compile_definitions(test_mother_h_fsm_security PRIVATE
        MOTHER_H_FSM_ENABLE_TEST_FAULT_INJECTION
        MOTHER_H_FSM_ENABLE_TEST_INSPECTOR
    )
    target_compile_definitions(test_jour_010_crypto_shredding PRIVATE
        MOTHER_H_TEST_BUILD
    )
    target_compile_definitions(test_res_001_resource_guard_exception_safety PRIVATE
        MOTHER_H_TEST_BUILD
        MOTHER_H_RESOURCE_GUARD_FAILURE_CODE_SET=::InjectedFailureCodeSet
    )
    target_compile_definitions(test_res_002_resource_guard_batch_atomicity PRIVATE
        MOTHER_H_TEST_BUILD
    )
    target_compile_definitions(test_res_bench_scale PRIVATE
        MOTHER_H_TEST_BUILD
    )
    target_compile_definitions(test_dynamic_policy_invariants PRIVATE
        MOTHER_H_TEST_BUILD
    )
    foreach(_target IN ITEMS
            test_journal_feedback_engine
            test_dynamic_policy_engine
            test_feedback_replay_atomicity_generalized
            test_feedback_and_keystore_tsan_concurrency
            test_auth_008_009_external_access_governance)
        target_compile_definitions("${_target}" PRIVATE MOTHER_H_TEST_BUILD)
    endforeach()

    if(WIN32)
        target_link_libraries(test_kek_wrapped_key_store PRIVATE crypt32)
    endif()

    set(_strict_warning_targets
        test_op0_guard
        test_op3_fermat
        test_op4_tensor
        test_op5_torus
        test_op_registry
        test_policy_engine
        test_op_executor
        test_journal_integrity
        test_journal_integrity_atomicity
        test_journal_checkpoint_isolation
        test_journal_recovery_policy
        test_journal_feedback_engine
        test_jour_008_fact_decoder_fuzz
        test_jour_010_crypto_shredding
        test_kek_wrapped_key_store
        test_file_monotonic_revocation_anchor_v2
        test_resource_guard
        test_mother_h_fsm_policy_contracts
        test_jarvis_ignition_v2
        test_dynamic_policy_engine
        test_dynamic_policy_invariants
        test_dynamic_policy_execution
        test_mother_h_fsm_transition
        test_mother_h_fsm_history
        test_mother_h_fsm_parent
        test_mother_h_fsm_security
        test_journal_checkpoint_backend_fail_closed
    )
    set(_assert_enabled_targets
        test_policy_engine
        test_op_executor
        test_op5_torus
        test_op_registry
        test_journal_integrity
        test_journal_integrity_atomicity
        test_journal_checkpoint_isolation
        test_journal_recovery_policy
        test_journal_feedback_engine
        test_resource_guard
        test_mother_h_fsm_policy_contracts
        test_jarvis_ignition_v2
        test_mother_h_fsm_transition
        test_mother_h_fsm_history
        test_mother_h_fsm_parent
        test_mother_h_fsm_security
        test_journal_checkpoint_backend_fail_closed
        test_dynamic_policy_engine
        test_dynamic_policy_invariants
        test_dynamic_policy_execution
        test_checkpoint_isolation_rejections
    )

    foreach(_target IN ITEMS mother_H_engine ${MOTHER_H_TEST_TARGETS})
        if(MSVC)
            target_compile_options("${_target}" PRIVATE /W4 /WX)
        else()
            target_compile_options("${_target}" PRIVATE -Wall -Wextra -Wpedantic)
            if(MOTHER_H_WERROR)
                target_compile_options("${_target}" PRIVATE -Werror)
            endif()
        endif()
    endforeach()

    foreach(_target IN LISTS _strict_warning_targets)
        if(MSVC)
            target_compile_options("${_target}" PRIVATE /W4 /WX)
        else()
            target_compile_options("${_target}" PRIVATE -Wall -Wextra -Wpedantic -Werror)
        endif()
    endforeach()

    foreach(_target IN ITEMS
            test_op0_guard
            test_op3_fermat
            test_op4_tensor
            test_op5_torus
            test_op_registry
            test_policy_engine
            test_op_executor
            test_mother_h_fsm_policy_contracts
            test_jarvis_ignition_v2
            test_dynamic_policy_engine
            test_dynamic_policy_invariants
            test_dynamic_policy_execution
            test_mother_h_fsm_transition
            test_mother_h_fsm_history
            test_mother_h_fsm_parent
            test_mother_h_fsm_security)
        if(NOT MSVC)
            target_compile_options("${_target}" PRIVATE -Wno-unused-parameter)
        endif()
    endforeach()

    foreach(_target IN LISTS _assert_enabled_targets)
        if(MSVC)
            target_compile_options("${_target}" PRIVATE /UNDEBUG)
        else()
            target_compile_options("${_target}" PRIVATE -UNDEBUG)
        endif()
    endforeach()
endif()
# Monotonic Checkpoint Anchor & Poison Latch Unit Tests (MCA-01..07)
add_executable(test_monotonic_checkpoint_anchor_unit
    tests/journal/test_monotonic_checkpoint_anchor_unit.cpp
)
target_include_directories(test_monotonic_checkpoint_anchor_unit PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(test_monotonic_checkpoint_anchor_unit PRIVATE cxx_std_17)
if(MINGW)
    target_link_libraries(test_monotonic_checkpoint_anchor_unit PRIVATE crypto)
elseif(OpenSSL_FOUND)
    target_link_libraries(test_monotonic_checkpoint_anchor_unit PRIVATE OpenSSL::Crypto)
endif()
if(MSVC)
    target_compile_options(test_monotonic_checkpoint_anchor_unit PRIVATE /W4 /WX)
else()
    target_compile_options(test_monotonic_checkpoint_anchor_unit PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_test(NAME monotonic_checkpoint_anchor_unit COMMAND test_monotonic_checkpoint_anchor_unit)
# =====================================================================
# =====================================================================
# Enforce assertions (-UNDEBUG / /UNDEBUG) across ALL test executables
# even in Release / RelWithDebInfo builds (MOTHER_H_ENFORCE_TEST_ASSERTIONS_IN_RELEASE)
# =====================================================================
if(BUILD_TESTING)
    get_property(_all_dir_targets DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_t IN LISTS _all_dir_targets)
        get_target_property(_t_type "${_t}" TYPE)
        if(_t_type STREQUAL "EXECUTABLE")
            if(MSVC)
                target_compile_options("${_t}" PRIVATE /UNDEBUG)
            else()
                target_compile_options("${_t}" PRIVATE -UNDEBUG)
            endif()
            if(WIN32)
                target_link_libraries("${_t}" PRIVATE crypt32)
            endif()
        endif()
    endforeach()
endif()