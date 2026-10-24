#pragma once

#include <cmath>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace intrusion_xai {

struct TreeNode {
    int node_id = -1;
    bool is_leaf = false;
    int feature_index = -1;
    std::string feature_name;
    double threshold = 0.0;
    int left_child = -1;
    int right_child = -1;
    int predicted_class = 0;
    std::vector<double> probabilities;
};

struct PredictionResult {
    int predicted_class = 0;
    double threat_score = 0.0;
    std::vector<double> probabilities;
    int leaf_node_id = -1;
};

class DecisionTreeEngine {
public:
    int feature_count = 0;
    int node_count = 0;
    std::vector<std::string> feature_names;
    std::vector<TreeNode> nodes;

    DecisionTreeEngine() = default;

    bool load_from_json(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open model file: " + filepath);
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string json_str = buffer.str();

        return parse_tree_json(json_str);
    }

    PredictionResult predict(const std::vector<double>& features) const {
        if (nodes.empty()) {
            throw std::runtime_error("Decision tree model is empty or not loaded.");
        }

        // 1. Strict validation: check feature vector size
        if (static_cast<int>(features.size()) != feature_count) {
            std::ostringstream oss;
            oss << "Feature count mismatch: expected " << feature_count
                << ", but received " << features.size();
            throw std::invalid_argument(oss.str());
        }

        // 2. Strict validation: check non-finite values (NaN / Inf)
        for (size_t i = 0; i < features.size(); ++i) {
            if (std::isnan(features[i])) {
                std::ostringstream oss;
                oss << "Invalid input: feature at index " << i
                    << " (" << (i < feature_names.size() ? feature_names[i] : "unknown")
                    << ") is NaN.";
                throw std::invalid_argument(oss.str());
            }
            if (std::isinf(features[i])) {
                std::ostringstream oss;
                oss << "Invalid input: feature at index " << i
                    << " (" << (i < feature_names.size() ? feature_names[i] : "unknown")
                    << ") is Infinite.";
                throw std::invalid_argument(oss.str());
            }
        }

        // 3. Deterministic Tree Traversal
        int current_id = 0;
        while (current_id >= 0 && current_id < static_cast<int>(nodes.size())) {
            const TreeNode& node = nodes[current_id];
            if (node.is_leaf) {
                PredictionResult res;
                res.predicted_class = node.predicted_class;
                res.probabilities = node.probabilities;
                res.threat_score = (node.probabilities.size() > 1) ? node.probabilities[1] : (node.predicted_class == 1 ? 1.0 : 0.0);
                res.leaf_node_id = node.node_id;
                return res;
            }

            int f_idx = node.feature_index;
            if (f_idx < 0 || f_idx >= static_cast<int>(features.size())) {
                throw std::runtime_error("Invalid feature index in tree traversal.");
            }

            // scikit-learn convention: <= threshold goes to left child, > goes to right child
            if (features[f_idx] <= node.threshold) {
                current_id = node.left_child;
            } else {
                current_id = node.right_child;
            }
        }

        throw std::runtime_error("Traversal failed to terminate at a valid leaf node.");
    }

private:
    // Helper extracting string between delimiters
    static std::string extract_value(const std::string& block, const std::string& key) {
        size_t pos = block.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = block.find(':', pos);
        if (pos == std::string::npos) return "";
        pos++;
        while (pos < block.size() && (block[pos] == ' ' || block[pos] == '\t' || block[pos] == '\n' || block[pos] == '\r')) {
            pos++;
        }
        if (pos >= block.size()) return "";

        size_t end_pos;
        if (block[pos] == '"') {
            pos++;
            end_pos = block.find('"', pos);
            return (end_pos != std::string::npos) ? block.substr(pos, end_pos - pos) : "";
        } else if (block[pos] == '[') {
            end_pos = block.find(']', pos);
            return (end_pos != std::string::npos) ? block.substr(pos, end_pos - pos + 1) : "";
        } else {
            end_pos = block.find_first_of(",}\n\r", pos);
            return (end_pos != std::string::npos) ? block.substr(pos, end_pos - pos) : block.substr(pos);
        }
    }

    bool parse_tree_json(const std::string& json_str) {
        nodes.clear();
        feature_names.clear();

        // 1. Parse feature count
        std::string fc_str = extract_value(json_str, "feature_count");
        if (!fc_str.empty()) {
            feature_count = std::stoi(fc_str);
        }

        // 2. Parse feature names
        size_t fn_pos = json_str.find("\"feature_names\"");
        if (fn_pos != std::string::npos) {
            size_t start_arr = json_str.find('[', fn_pos);
            size_t end_arr = json_str.find(']', start_arr);
            if (start_arr != std::string::npos && end_arr != std::string::npos) {
                std::string names_block = json_str.substr(start_arr + 1, end_arr - start_arr - 1);
                size_t p = 0;
                while ((p = names_block.find('"', p)) != std::string::npos) {
                    size_t closing = names_block.find('"', p + 1);
                    if (closing != std::string::npos) {
                        feature_names.push_back(names_block.substr(p + 1, closing - p - 1));
                        p = closing + 1;
                    } else break;
                }
            }
        }

        // If feature_count was not explicitly given, derive from names
        if (feature_count == 0) {
            feature_count = static_cast<int>(feature_names.size());
        }

        // 3. Parse nodes array
        size_t nodes_pos = json_str.find("\"nodes\"");
        if (nodes_pos == std::string::npos) return false;

        size_t current = json_str.find('{', nodes_pos);
        while (current != std::string::npos) {
            size_t end_node = json_str.find('}', current);
            if (end_node == std::string::npos) break;

            std::string node_block = json_str.substr(current, end_node - current + 1);

            TreeNode node;
            std::string id_str = extract_value(node_block, "node_id");
            if (!id_str.empty()) node.node_id = std::stoi(id_str);

            std::string leaf_str = extract_value(node_block, "is_leaf");
            node.is_leaf = (leaf_str == "true" || leaf_str == "1");

            std::string feat_idx_str = extract_value(node_block, "feature_index");
            if (!feat_idx_str.empty()) node.feature_index = std::stoi(feat_idx_str);

            node.feature_name = extract_value(node_block, "feature_name");

            std::string thresh_str = extract_value(node_block, "threshold");
            if (!thresh_str.empty()) node.threshold = std::stod(thresh_str);

            std::string lc_str = extract_value(node_block, "left_child");
            if (!lc_str.empty()) node.left_child = std::stoi(lc_str);

            std::string rc_str = extract_value(node_block, "right_child");
            if (!rc_str.empty()) node.right_child = std::stoi(rc_str);

            std::string cls_str = extract_value(node_block, "predicted_class");
            if (!cls_str.empty()) node.predicted_class = std::stoi(cls_str);

            std::string prob_str = extract_value(node_block, "probabilities");
            if (!prob_str.empty() && prob_str.front() == '[' && prob_str.back() == ']') {
                std::string inner = prob_str.substr(1, prob_str.size() - 2);
                std::stringstream pss(inner);
                std::string item;
                while (std::getline(pss, item, ',')) {
                    try {
                        node.probabilities.push_back(std::stod(item));
                    } catch (...) {}
                }
            }

            nodes.push_back(node);
            current = json_str.find('{', end_node + 1);
        }

        node_count = static_cast<int>(nodes.size());
        return !nodes.empty();
    }
};

} // namespace intrusion_xai
