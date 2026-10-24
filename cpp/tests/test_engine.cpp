#include <cassert>
#include <cmath>
#include <iostream>
#include <limits>
#include <vector>
#include "tree_engine.hpp"
#include "version.hpp"

void test_version_and_standard() {
    assert(intrusion_xai::is_cpp17_supported());
    assert(intrusion_xai::get_engine_version() == "1.0.0");
    std::cout << "[PASSED] test_version_and_standard\n";
}

void test_synthetic_tree_evaluation() {
    // Construct a synthetic 3-node decision tree:
    // Root (0): Feature 0 <= 5.0 -> Left (1: Leaf, class 0), Right (2: Leaf, class 1)
    std::string json_tree = R"({
        "feature_count": 2,
        "feature_names": ["Feature_A", "Feature_B"],
        "nodes": [
            {
                "node_id": 0,
                "is_leaf": false,
                "feature_index": 0,
                "threshold": 5.0,
                "left_child": 1,
                "right_child": 2,
                "predicted_class": 0,
                "probabilities": [0.5, 0.5]
            },
            {
                "node_id": 1,
                "is_leaf": true,
                "feature_index": -1,
                "threshold": 0.0,
                "left_child": -1,
                "right_child": -1,
                "predicted_class": 0,
                "probabilities": [1.0, 0.0]
            },
            {
                "node_id": 2,
                "is_leaf": true,
                "feature_index": -1,
                "threshold": 0.0,
                "left_child": -1,
                "right_child": -1,
                "predicted_class": 1,
                "probabilities": [0.0, 1.0]
            }
        ]
    })";

    intrusion_xai::DecisionTreeEngine engine;
    // Save to temp file to test load_from_json
    std::ofstream tmp_file("cpp/build/tmp_tree.json");
    tmp_file << json_tree;
    tmp_file.close();

    bool ok = engine.load_from_json("cpp/build/tmp_tree.json");
    assert(ok);
    assert(engine.feature_count == 2);
    assert(engine.node_count == 3);

    // Test Left traversal (3.0 <= 5.0) -> Class 0
    std::vector<double> sample_left = {3.0, 10.0};
    auto res_left = engine.predict(sample_left);
    assert(res_left.predicted_class == 0);
    assert(res_left.leaf_node_id == 1);
    assert(res_left.threat_score == 0.0);

    // Test Right traversal (8.0 > 5.0) -> Class 1
    std::vector<double> sample_right = {8.0, 10.0};
    auto res_right = engine.predict(sample_right);
    assert(res_right.predicted_class == 1);
    assert(res_right.leaf_node_id == 2);
    assert(res_right.threat_score == 1.0);

    std::cout << "[PASSED] test_synthetic_tree_evaluation\n";
}

void test_input_validation() {
    intrusion_xai::DecisionTreeEngine engine;
    engine.load_from_json("cpp/build/tmp_tree.json");

    // 1. Wrong feature size (expected 2, provided 1)
    bool threw_size = false;
    try {
        engine.predict({1.0});
    } catch (const std::invalid_argument&) {
        threw_size = true;
    }
    assert(threw_size);

    // 2. NaN validation
    bool threw_nan = false;
    try {
        engine.predict({std::numeric_limits<double>::quiet_NaN(), 1.0});
    } catch (const std::invalid_argument&) {
        threw_nan = true;
    }
    assert(threw_nan);

    // 3. Inf validation
    bool threw_inf = false;
    try {
        engine.predict({1.0, std::numeric_limits<double>::infinity()});
    } catch (const std::invalid_argument&) {
        threw_inf = true;
    }
    assert(threw_inf);

    std::cout << "[PASSED] test_input_validation\n";
}

int main() {
    std::cout << "=== Running C++17 Unit Tests ===\n";
    test_version_and_standard();
    test_synthetic_tree_evaluation();
    test_input_validation();
    std::cout << "=== All C++17 Tests Passed Successfully ===\n";
    return 0;
}
