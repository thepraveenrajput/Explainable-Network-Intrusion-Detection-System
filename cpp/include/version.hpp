#pragma once

#include <string>

namespace intrusion_xai {

inline std::string get_engine_version() {
    return "1.0.0";
}

inline bool is_cpp17_supported() {
#if __cplusplus >= 201703L
    return true;
#else
    return false;
#endif
}

} // namespace intrusion_xai
