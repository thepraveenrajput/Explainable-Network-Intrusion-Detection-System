cmake_minimum_required(VERSION 3.16)
project(IntrusionXAICppEngine VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warning flags
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

include_directories(include)

# Source files for core engine
file(GLOB_RECURSE ENGINE_SOURCES "src/*.cpp")

# Main inference executable (used for command-line/subprocess predictions)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
    add_executable(cpp_inference_engine ${ENGINE_SOURCES})
endif()

# Unit tests
file(GLOB_RECURSE TEST_SOURCES "tests/*.cpp")
# Exclude main.cpp when building test binary if needed
list(FILTER ENGINE_SOURCES EXCLUDE REGEX ".*main\\.cpp$")

add_executable(cpp_tests ${TEST_SOURCES} ${ENGINE_SOURCES})

enable_testing()
add_test(NAME CppEngineUnitTests COMMAND cpp_tests)
