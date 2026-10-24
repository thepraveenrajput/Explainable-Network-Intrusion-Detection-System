#include <cassert>
#include <iostream>
#include "version.hpp"

int main() {
    assert(intrusion_xai::is_cpp17_supported());
    assert(intrusion_xai::get_engine_version() == "1.0.0");
    std::cout << "[PASSED] C++17 Smoke Test passed successfully." << std::endl;
    return 0;
}
