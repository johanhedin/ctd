
#include <regex>
#include <algorithm>
#include <iostream>
#include <sstream>

#include "config_parser.hpp"

#include "yaml-cpp/yaml.h"

namespace ctd {

static std::optional<int> parse_syslog_level(const std::string& str) {
    auto iter = level_map.find(str);
    if (iter == level_map.end()) return std::nullopt;

    return iter->second;
} // parse_syslog_level


static std::optional<int> parse_syslog_facility(const std::string& str) {
    auto iter = facility_map.find(str);
    if (iter == facility_map.end()) return std::nullopt;

    return iter->second;
} // parse_syslog_facility


static std::optional<std::size_t> parse_byte_value(const std::string& str) {
    const std::regex re_bytes("^(\\d+)[ ]*[B]{0,1}$");
    const std::regex re_kib("^(\\d+)[ ]*KiB$");
    const std::regex re_mib("^(\\d+)[ ]*MiB$");
    const std::regex re_gib("^(\\d+)[ ]*GiB$");
    const std::regex re_kb("^(\\d+)[ ]*kB$");
    const std::regex re_mb("^(\\d+)[ ]*MB$");
    const std::regex re_gb("^(\\d+)[ ]*GB$");
    std::smatch      match;
    std::size_t      multiplier = 1;

    if (std::regex_search(str, match, re_bytes) && match.size() > 1) {
        multiplier = 1;
    } else if (std::regex_search(str, match, re_kib) && match.size() > 1) {
        multiplier = 1024;
    } else if (std::regex_search(str, match, re_mib) && match.size() > 1) {
        multiplier = 1024 * 1024;
    } else if (std::regex_search(str, match, re_gib) && match.size() > 1) {
        multiplier = 1024 * 1024 *1024;
    } else if (std::regex_search(str, match, re_kb) && match.size() > 1) {
        multiplier = 1000;
    } else if (std::regex_search(str, match, re_mb) && match.size() > 1) {
        multiplier = 1000 * 1000;
    } else if (std::regex_search(str, match, re_gb) && match.size() > 1) {
        multiplier = 1000 * 1000 *1000;
    } else {
        // Invalid format
        return std::nullopt;
    }

    return (std::stoul(match.str(1)) * multiplier);
} // parse_byte_value


static bool ip_addr_valid(const std::string &addr) {
    const std::regex ipv4("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    const std::regex ipv6("^\\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\]$");
    std::smatch match;

    if (std::regex_search(addr, match, ipv4)) return true;
    if (std::regex_search(addr, match, ipv6)) return true;

    return false;
}


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

    const auto& listen_node = main_node["listen"];
    if (listen_node) {
        if (!listen_node.IsSequence()) {
            std::cerr << "Error at line " << listen_node.Mark().line+1 <<
                         ": Node 'main.listen' is not of kind Sequence." << std::endl;
            return std::nullopt;
        }

        for (const auto &item : listen_node) {
            Config::Listen l;

            l.addr = item["addr"].as<std::string>("");
            if (l.addr == "") {
                std::cerr << "Error at line " << item.Mark().line+1 <<
                             ": Node 'addr' missing." << std::endl;
                return std::nullopt;
            }
            if (!ip_addr_valid(l.addr)) {
                std::cerr << "Error at line " << item.Mark().line+1 <<
                             ": Value is not an IPv4 or IPv6 address." << std::endl;
                return std::nullopt;
            }
            l.port = item["port"].as<int>(-1);
            if (l.port == -1) {
                std::cerr << "Error at line " << item.Mark().line+1 <<
                             ": Node 'port' missing or missformatted." << std::endl;
                return std::nullopt;
            }

            l.https = item["https"].as<bool>(false);
            if (l.https) {
                l.cert = item["cert"].as<std::string>("");
                if (l.cert == "") {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                ": Node 'cert' missing." << std::endl;
                    return std::nullopt;
                }
                l.key  = item["key"].as<std::string>("");
                if (l.key == "") {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                ": Node 'key' missing." << std::endl;
                    return std::nullopt;
                }
            }

            // Check if l is a duplicate
            for (const auto &a : main.listen) {
                if (l.addr == a.addr && l.port == a.port) {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                 ": Addr/port pair repeated." << std::endl;
                    return std::nullopt;
                }

                if (l.addr == "0.0.0.0" && l.port == a.port && a.addr != "[::]") {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                 ": Port is already configured." << std::endl;
                    return std::nullopt;
                }

                if (l.addr == "[::]" && l.port == a.port && a.addr != "0.0.0.0") {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                 ": Port is already configured." << std::endl;
                    return std::nullopt;
                }

                if (a.addr == "0.0.0.0" && l.port == a.port && l.addr != "[::]") {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                 ": Port is already configured." << std::endl;
                    return std::nullopt;
                }

                if (a.addr == "[::]" && l.port == a.port && l.addr != "0.0.0.0") {
                    std::cerr << "Error at line " << item.Mark().line+1 <<
                                 ": Port is already configured." << std::endl;
                    return std::nullopt;
                }
            }

            main.listen.push_back(l);
        }
    }

    return main;
} // parse_main


static std::optional<Config::Logging> parse_logging(const YAML::Node& logging_node) {
    Config::Logging logging;

    if (!logging_node) {
        std::cerr << "Error: Node 'logging' missing." << std::endl;
        return std::nullopt;
    }
    if (!logging_node.IsMap()) {
        std::cerr << "Error at line " << logging_node.Mark().line+1 <<
                     ": Node 'logging' is not of kind Mapping." << std::endl;
        return std::nullopt;
    }

    const auto& level_node = logging_node["level"];
    if (!level_node.IsDefined()) {
        std::cerr << "Error: Node 'logging.level' missing." << std::endl;
        return std::nullopt;
    }
    if (!level_node.IsScalar()) {
        std::cerr << "Error at line " << level_node.Mark().line+1 <<
                     ": Node 'logging.level' is not of kind Scalar." << std::endl;
        return std::nullopt;
    }
    auto level = parse_syslog_level(level_node.as<std::string>());
    if (!level) {
        std::cerr << "Error at line " << level_node.Mark().line+1 <<
                     ": Invalid value for node 'logging.level'." << std::endl;
        return std::nullopt;
    }
    logging.level = *level;

    const auto& stdout_node = logging_node["stdout"];
    if (stdout_node.IsDefined()) {
        if (!stdout_node.IsMap()) {
            std::cerr << "Error at line " << stdout_node.Mark().line+1 <<
                         ": Node 'logging.stdout' is not of kind Mapping." << std::endl;
            return std::nullopt;
        }

        const auto& activate_node = stdout_node["activate"];
        if (!activate_node.IsDefined()) {
            std::cerr << "Error: Node 'logging.stdout.activate' missing." << std::endl;
            return std::nullopt;
        }
        if (!activate_node.IsScalar()) {
            std::cerr << "Error at line " << activate_node.Mark().line+1 <<
                            ": Node 'logging.stdout.activate' is not of kind Scalar." << std::endl;
            return std::nullopt;
        }

        logging.stdout.active = activate_node.as<bool>();
        logging.stdout.configured = true;
    }

    const auto& syslog_node = logging_node["syslog"];
    if (syslog_node.IsDefined()) {
        if (!syslog_node.IsMap()) {
            std::cerr << "Error at line " << syslog_node.Mark().line+1 <<
                         ": Node 'logging.syslog' is not of kind Mapping." << std::endl;
            return std::nullopt;
        }

        const auto& activate_node = syslog_node["activate"];
        if (!activate_node.IsDefined()) {
            std::cerr << "Error: Node 'logging.syslog.activate' missing." << std::endl;
            return std::nullopt;
        }
        if (!activate_node.IsScalar()) {
            std::cerr << "Error at line " << activate_node.Mark().line+1 <<
                         ": Node 'logging.syslog.activate' is not of kind Scalar." << std::endl;
            return std::nullopt;
        }
        logging.syslog.active = activate_node.as<bool>();

        const auto& facility_node = syslog_node["facility"];
        if (!facility_node.IsDefined()) {
            std::cerr << "Error: Node 'logging.syslog.facility' missing." << std::endl;
            return std::nullopt;
        }
        if (!facility_node.IsScalar()) {
            std::cerr << "Error at line " << facility_node.Mark().line+1 <<
                         ": Node 'logging.syslog.facility' is not of kind Scalar." << std::endl;
            return std::nullopt;
        }
        auto facility = parse_syslog_facility(facility_node.as<std::string>());
        if (!facility) {
            std::cerr << "Error at line " << facility_node.Mark().line+1 <<
                         ": Invalid value for 'logging.syslog.facility'." << std::endl;
            return std::nullopt;
        }
        logging.syslog.facility = *facility;

        logging.syslog.configured = true;
    }

    YAML::Node logging_file = logging_node["file"];
    if (logging_file.IsDefined()) {
        if (!logging_file.IsMap()) {
            std::cerr << "Error at line " << logging_file.Mark().line+1 <<
                        ": Node 'logging.file' is not of kind Mapping." << std::endl;
            return std::nullopt;
        }

        YAML::Node active = logging_file["activate"];
        if (!active.IsDefined()) {
            std::cerr << "Error: Node 'logging.file.activate' missing." << std::endl;
            return std::nullopt;
        } else if (!active.IsScalar()) {
            std::cerr << "Error at line " << active.Mark().line+1 <<
                            ": Node 'logging.file.activate' is not of kind Scalar." << std::endl;
            return std::nullopt;
        }
        logging.file.active = active.as<bool>();

        YAML::Node file_dir = logging_file["dir"];
        if (!file_dir.IsDefined()) {
            std::cerr << "Error: Node 'logging.file.dir' missing." << std::endl;
            return std::nullopt;
        } else if (!file_dir.IsScalar()) {
            std::cerr << "Error at line " << file_dir.Mark().line+1 <<
                         ": Node 'logging.file.dir' is not of kind Scalar." << std::endl;
            return std::nullopt;
        }

        logging.file.dir = file_dir.Scalar();
        logging.file.configured = true;

        // TODO: Parse periodicity
        //YAML::Node file_periodicity = logging_file["periodicity"];

        YAML::Node file_size = logging_file["size"];
        if (file_size.IsDefined()) {
            if (!file_size.IsScalar()) {
                std::cerr << "Error at line " << file_size.Mark().line+1 <<
                             ": Node 'logging.file.size' is not of kind Scalar." << std::endl;
                return std::nullopt;
            }

            auto bytes = parse_byte_value(file_size.Scalar());
            if (bytes) {
                logging.file.size = *bytes;
            } else {
                std::cerr << "Error at line " << file_size.Mark().line+1 <<
                                ": Invalid format for node 'logging.file.size'." << std::endl;
                return std::nullopt;
            }
        }

        YAML::Node file_max_files = logging_file["max_files"];
        if (file_max_files.IsDefined()) {
            if (!file_max_files.IsScalar()) {
                std::cerr << "Error at line " << file_max_files.Mark().line+1 <<
                            ": Node 'logging.file.max_files' is not of kind Scalar." << std::endl;
                return std::nullopt;
            }

            logging.file.max_files = file_max_files.as<std::size_t>();
        }

        YAML::Node file_max_size = logging_file["max_size"];
        if (file_max_size.IsDefined()) {
            if (!file_max_size.IsScalar()) {
                std::cerr << "Error at line " << file_max_size.Mark().line+1 <<
                            ": Node 'logging.file.max_size' is not of kind Scalar." << std::endl;
                return std::nullopt;
            }

            auto bytes = parse_byte_value(file_max_size.Scalar());
            if (bytes) {
                logging.file.max_size = *bytes;
            } else {
                std::cerr << "Error at line " << file_max_size.Mark().line+1 <<
                                ": Invalid format for node 'logging.file.max_size'." << std::endl;
                return std::nullopt;
            }
        }
    }

    if (!logging.stdout && !logging.syslog && !logging.file) {
        std::cerr << "Error: At least one log output must be configured." << std::endl;
        return std::nullopt;
    }

    if (!logging.stdout.active && !logging.syslog.active && !logging.file.active) {
        std::cerr << "Error: At least one log output must be active." << std::endl;
        return std::nullopt;
    }

    return logging;
} // parse_logging


//
// Public interface functions below
//

std::optional<Config> parse_config(const std::string& cfg_file) noexcept {
    Config config;

    try {
        const auto& root = YAML::LoadFile(cfg_file);

        auto main = parse_main(root["main"]);
        if (!main) return std::nullopt;
        config.main = *main;

        auto logging = parse_logging(root["logging"]);
        if (!logging) return std::nullopt;
        config.logging = *logging;
    }  catch (YAML::BadFile& e) {
        std::cerr << "Error: " << e.msg << std::endl;
        return std::nullopt;
    } catch (YAML::Exception& e) {
        std::cerr << "Error at line " << e.mark.line+1 << ": " << e.msg << std::endl;
        return std::nullopt;
    } catch (...) {
        std::cerr << "Error: Unhandled exception while parsing config file: " << cfg_file << std::endl;
        return std::nullopt;
    }

    return config;
} // parse_config


void dump_config(const Config& config) noexcept {
    std::cout << "main:" << std::endl;
    std::cout << "    tag_mappings_file = " << (config.main.tag_mappings_file.empty() ? "<none>":config.main.tag_mappings_file) << std::endl;
    /*
    if (!config.main.listen.empty()) {
        std::cout << "    listen =";
        bool first = true;
        for (const auto& a : config.main.listen) {
            std::cout << (first ? " ":",") << a.first << ":" << a.second;
            first = false;
        }
        std::cout << std::endl;
    }
    */
    if (!config.main.listen.empty()) {
        std::cout << "    listen:" << std::endl;
        int i = 0;
        for (const auto& a : config.main.listen) {
            std::cout << "        " << i << ":" << std::endl;
            std::cout << "            addr = " << a.addr << std::endl;
            std::cout << "            port = " << a.port << std::endl;
            std::cout << "            https = " << (a.https?"yes":"no") << std::endl;
            if (a.https) {
                std::cout << "            cert = " << a.cert << std::endl;
                std::cout << "            key = " << a.key << std::endl;
            }
            i++;
        }
    }
    std::cout << "logging:" << std::endl;
    std::cout << "    level = " << config.logging.levelName() << std::endl;
    if (config.logging.stdout) {
        std::cout << "    stdout:" << std::endl;
        std::cout << "        activated = " << (config.logging.stdout.active ? "yes":"no") << std::endl;
    }
    if (config.logging.syslog) {
        std::cout << "    syslog:" << std::endl;
        std::cout << "        activated = " << (config.logging.syslog.active ? "yes":"no") << std::endl;
        std::cout << "        facility = " << config.logging.syslog.facilityName() << std::endl;
    }
    if (config.logging.file) {
        std::cout << "    file:" << std::endl;
        std::cout << "        activated = " << (config.logging.file.active ? "yes":"no") << std::endl;
        std::cout << "        dir = " << config.logging.file.dir << std::endl;
        std::cout << "        periodicity = " << config.logging.file.periodicity << std::endl;
        std::cout << "        size = " << config.logging.file.size << std::endl;
        std::cout << "        max_files = " << config.logging.file.max_files << std::endl;
        std::cout << "        max_size = " << config.logging.file.max_size << std::endl;
    }
    /*
    std::cout << "    inputs:" << std::endl;
    for (const auto& input : config.inputs) {
        std::cout << "        " << input.name << ":" << std::endl;
        std::cout << "            dir = " << input.dir << std::endl;
        std::cout << "            id = " << (input.id.empty() ? "<none>":input.id) << std::endl;
        std::cout << "            log_level = " << input.logLevelName() << std::endl;
        if (input.residue) {
            std::cout << "            residue:" << std::endl;
            std::cout << "                dir = " << input.residue.dir << std::endl;
            std::cout << "                max_files = " << input.residue.max_files << std::endl;
            std::cout << "                max_size = " << input.residue.max_size << std::endl;
        }
    }
    */
} // dump_config

} // namespace ctd
