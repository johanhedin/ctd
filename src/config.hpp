#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <syslog.h>

#include <string>
#include <vector>
#include <utility>
#include <map>

namespace ctd {

// ctd use the same names and values for log levels as syslog, but only a
// subset
static const std::map<std::string, int> level_map = {
    //{ "alert",   LOG_ALERT },
    { "crit",    LOG_CRIT },
    { "debug",   LOG_DEBUG },
    //{ "emerg",   LOG_EMERG },
    { "err",     LOG_ERR },
    //{ "error",   LOG_ERR },     // DEPRECATED
    { "info",    LOG_INFO },
    //{ "notice",  LOG_NOTICE },
    //{ "panic",   LOG_EMERG },   // DEPRECATED
    //{ "warn",    LOG_WARNING }, // DEPRECATED
    { "warning", LOG_WARNING }
};

// ctd use the same names and values for facilities as syslog
static const std::map<std::string, int> facility_map = {
    { "auth",     LOG_AUTH },
    { "authpriv", LOG_AUTHPRIV },
    { "cron",     LOG_CRON },
    { "daemon",   LOG_DAEMON },
    { "ftp",      LOG_FTP },
    { "kern",     LOG_KERN },
    { "lpr",      LOG_LPR },
    { "mail",     LOG_MAIL },
    { "news",     LOG_NEWS },
    //{ "security", LOG_AUTH },  // DEPRECATED
    { "syslog",   LOG_SYSLOG },
    { "user",     LOG_USER },
    { "uucp",     LOG_UUCP },
    { "local0",   LOG_LOCAL0 },
    { "local1",   LOG_LOCAL1 },
    { "local2",   LOG_LOCAL2 },
    { "local3",   LOG_LOCAL3 },
    { "local4",   LOG_LOCAL4 },
    { "local5",   LOG_LOCAL5 },
    { "local6",   LOG_LOCAL6 },
    { "local7",   LOG_LOCAL7 }
};

class Config {
public:
    class Main {
    public:
        Main() = default;

        std::string tag_mappings_file{};
        std::vector<std::pair<std::string, int>> listen{};
    };

    class Logging {
    public:
        class Stdout {
        public:
            Stdout() = default;
            explicit operator bool() const noexcept { return configured; }

            bool configured{false};
            bool active{false};
        };
        class Syslog {
        public:
            Syslog() = default;
            explicit operator bool() const noexcept { return configured; }
            const std::string& facilityName() const {
                static const std::string unknown{"unknown"};
                auto iter = facility_map.begin();
                while (iter != facility_map.end()) {
                    if (facility == iter->second) return iter->first;
                    ++iter;
                }
                return unknown;
            }

            bool configured{false};
            bool active{false};
            int  facility{-1};
        };
        class File {
        public:
            File() = default;
            explicit operator bool() const noexcept { return configured; }

            bool         configured{false};
            bool         active{false};
            std::string  dir{};
            std::size_t  periodicity{3600};           // 3600 seconds in an hour
            std::size_t  size{32 * 1024 * 1024};      // 32MiB
            std::size_t  max_files{4};                // 4 files
            std::size_t  max_size{128 * 1024 * 1024}; // 128MiB
        };

    public:
        Logging() = default;

        const std::string& levelName() const {
            static const std::string unknown{"unknown"};
            auto iter = level_map.begin();
            while (iter != level_map.end()) {
                if (level == iter->second) return iter->first;
                ++iter;
            }
            return unknown;
        }

        int    level{-1};
        Stdout stdout;
        Syslog syslog;
        File   file;
    };

public:
    Config() = default;

    Main    main;
    Logging logging;
};
}

#endif // CONFIG_HPP
