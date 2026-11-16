#include "mother_H/core/phase13_4_state_policy.hpp"

#include <iostream>

int main() {
    const bool valid_transition = mb::cqs13_4::TransitionPolicyGuard::is_fsm_allowed(
        mb::cqs13_4::EventState::HELD,
        mb::cqs13_4::EventState::READY);
    std::cout << "[MOTHER_H] Independent FSM and Journal interfaces\n";
    std::cout << (valid_transition ? "[PASS] " : "[FAIL] ")
              << "HELD -> READY policy\n";
    std::cout << "[INFO] Authenticated Journal writes require an explicit key provider "
                 "and record sink.\n";
    return valid_transition ? 0 : 1;
}
