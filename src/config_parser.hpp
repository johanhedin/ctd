
#ifndef CONFIG_PARSER_HPP
#define CONFIG_PARSER_HPP

#include <string>
#include <optional>

#include "config.hpp"

namespace ctd {
std::optional<Config> parse_config(const std::string& cfg_file);
}

#endif // CONFIG_PARSER_HPP
