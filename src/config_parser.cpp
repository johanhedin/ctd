
#include <iostream>

#include "config_parser.hpp"

#include "yaml-cpp/yaml.h"

namespace ctd {

static std::optional<Config::Main> parse_main(const YAML::Node& main_node) {
    Config::Main main;

    if (!main_node) {
        std::cerr << "Error: Node 'main' missing." << std::endl;
        return std::nullopt;
    }

    if (!main_node.IsMap()) {
        std::cerr << "Error at line " << main_node.Mark().line+1 <<
                     ": Node 'main' is not of kind Mapping." << std::endl;
        return std::nullopt;
    }

    const auto& tag_mappings_file_node = main_node["tag_mappings_file"];
    if (tag_mappings_file_node) {
        if (!tag_mappings_file_node.IsScalar()) {
            std::cerr << "Error at line " << tag_mappings_file_node.Mark().line+1 <<
                         ": Node 'main.tag_mappings_file' is not of kind Scalar." << std::endl;
            return std::nullopt;
        }

        main.tag_mappings_file = tag_mappings_file_node.as<std::string>();
    }

    return main;
}


std::optional<Config> parse_config(const std::string& cfg_file) {
    using std::cerr, std::endl;
    Config config;

    try {
        const auto& root = YAML::LoadFile(cfg_file);

        auto main = parse_main(root["main"]);
        if (!main) return std::nullopt;
        config.main = *main;
    }  catch (YAML::BadFile& e) {
        cerr << "Error: " << e.msg << endl;
        return std::nullopt;
    } catch (YAML::Exception& e) {
        cerr << "Error at line " << e.mark.line+1 << ": " << e.msg << endl;
        return std::nullopt;
    } catch (...) {
        cerr << "Error: Unhandled exception while parsing config file: " << cfg_file << endl;
        return std::nullopt;
    }

    return config;
}

}
