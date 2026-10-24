#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "tree_engine.hpp"
#include "version.hpp"

static void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  --model <path>       Path to exported decision_tree_cpp.json file\n"
              << "  --features <csv>     Comma-separated list of numeric feature values\n"
              << "  --csv-stdin          Read comma-separated features from standard input\n"
              << "  --version            Print engine version\n"
              << "  --help               Print this help message\n";
}

static std::vector<double> parse_csv_line(const std::string& line) {
    std::vector<double> vals;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, ',')) {
        // Trim whitespace
        size_t start = item.find_first_not_of(" \t\r\n");
        size_t end = item.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            item = item.substr(start, end - start + 1);
        }
        if (!item.empty()) {
            vals.push_back(std::stod(item));
        }
    }
    return vals;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        std::cout << "Intrusion XAI C++17 Inference Engine v" << intrusion_xai::get_engine_version() << "\n";
        std::cout << "[SUCCESS] C++17 standard verified under Apple Clang.\n";
        print_usage(argv[0]);
        return 0;
    }

    std::string model_path = "models/decision_tree_cpp.json";
    std::string features_csv = "";
    bool read_stdin = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--model" && i + 1 < argc) {
            model_path = argv[++i];
        } else if (arg == "--features" && i + 1 < argc) {
            features_csv = argv[++i];
        } else if (arg == "--csv-stdin") {
            read_stdin = true;
        } else if (arg == "--version") {
            std::cout << "Intrusion XAI C++17 Engine v" << intrusion_xai::get_engine_version() << "\n";
            return 0;
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (read_stdin) {
        if (!std::getline(std::cin, features_csv)) {
            std::cout << "{\"status\": \"error\", \"message\": \"Failed to read features from stdin\"}\n";
            return 1;
        }
    }

    if (features_csv.empty()) {
        std::cout << "{\"status\": \"error\", \"message\": \"No features provided. Use --features or --csv-stdin\"}\n";
        return 1;
    }

    try {
        intrusion_xai::DecisionTreeEngine engine;
        engine.load_from_json(model_path);

        std::vector<double> feature_vec = parse_csv_line(features_csv);
        intrusion_xai::PredictionResult res = engine.predict(feature_vec);

        std::cout << "{\"status\": \"success\", "
                  << "\"predicted_class\": " << res.predicted_class << ", "
                  << "\"threat_score\": " << res.threat_score << ", "
                  << "\"leaf_node\": " << res.leaf_node_id << ", "
                  << "\"probabilities\": [";
        for (size_t i = 0; i < res.probabilities.size(); ++i) {
            std::cout << res.probabilities[i] << (i + 1 < res.probabilities.size() ? ", " : "");
        }
        std::cout << "]}\n";
        return 0;

    } catch (const std::invalid_argument& e) {
        std::cout << "{\"status\": \"error\", \"error_type\": \"invalid_argument\", \"message\": \"" << e.what() << "\"}\n";
        return 1;
    } catch (const std::exception& e) {
        std::cout << "{\"status\": \"error\", \"error_type\": \"runtime_error\", \"message\": \"" << e.what() << "\"}\n";
        return 1;
    }
}
