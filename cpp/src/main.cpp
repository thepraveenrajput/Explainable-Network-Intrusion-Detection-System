#include <iostream>
#include "version.hpp"

int main() {
    std::cout << "Intrusion XAI C++17 Inference Engine v" << intrusion_xai::get_engine_version() << std::endl;
    if (intrusion_xai::is_cpp17_supported()) {
        std::cout << "[SUCCESS] C++17 standard verified under Apple Clang." << std::endl;
        return 0;
    } else {
        std::cerr << "[ERROR] Compiler does not meet C++17 standard requirements." << std::endl;
        return 1;
    }
}
