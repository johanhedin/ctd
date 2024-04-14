#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <vector>
#include <utility>

namespace ctd {
class Config {
// Classes
public:
    class Main {
    public:
        Main() = default;

        std::string tag_mappings_file{};
        std::vector<std::pair<std::string, int>> listen{};
    };

public:
    Config() = default;

    Main main;
};
}

#endif // CONFIG_HPP
