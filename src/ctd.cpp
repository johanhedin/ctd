
#include <iostream>
#include <thread>
#include <chrono>

#include "argparse/argparse.hpp"
#include "config.hpp"
#include "config_parser.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/syslog_sink.h"

static const std::string VERSION_STR{"0.99rc1"};

void worker_function(const std::string& arg) {
    using namespace std::chrono_literals;

    std::cout << "Working on arg: " << arg << "..."  << std::endl;
    std::this_thread::sleep_for(2000ms);
    std::cout << "Done." << std::endl;
}

int main(int argc, char** argv) {
    // Create argparse instance
    argparse::ArgumentParser program("ctd", VERSION_STR);

    // Configure argparse instance
    program.add_description("A template daemon");
    program.add_argument("-c", "--config-file")
        .help("configuration file. Defaults to /etc/ctd/ctd.yaml if not set")
        .metavar("FILE");
    program.add_argument("--validate")
        .help("validate the config file and then exit")
        .flag();

    // Parse
    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << program;
        return 1;
    } catch (...) {
        std::cerr << "Error: Unhandled exception while parsing command line arguments." << std::endl;
        return 2;
    }

    // Extract arguments given
    std::string cfg_file = program.is_used("-c") ? program.get<std::string>("-c") : "/etc/ctd/ctd.yaml";

    if (program["--validate"] == true) {
        std::cout << "Validating config file: " << cfg_file << "..." << std::endl;
        auto config = ctd::parse_config(cfg_file);
        if (!config) return 3;

        return 0;
    }

    std::cout << "Parsing config file: " << cfg_file << "..." << std::endl;
    auto config = ctd::parse_config(cfg_file);
    if (!config) return 3;

    std::cout << "config.main.tag_mappings_file=" << config->main.tag_mappings_file << std::endl;

    std::string item{"one"};
    std::thread worker(worker_function, item);
    worker.join();

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(spdlog::level::trace);

    auto syslog_sink = std::make_shared<spdlog::sinks::syslog_sink_mt>("ctd", 0, LOG_USER, false);
    syslog_sink->set_level(spdlog::level::trace);

    spdlog::logger logger("", {console_sink, syslog_sink});
    logger.set_level(spdlog::level::trace);

    logger.trace("Trace, trace!");
    logger.debug("Debug, debug!");
    logger.info("Info, info!");
    logger.warn("Warn, warn!");
    logger.error("Error, error!");
    logger.critical("Critical, critical!");

    auto net_logger = std::make_shared<spdlog::logger>("net", syslog_sink);
    auto hw_logger  = std::make_shared<spdlog::logger>("hw",  syslog_sink);
    auto db_logger  = std::make_shared<spdlog::logger>("db",  syslog_sink); 

    net_logger->info("Logging from the net logger!");
    db_logger->warn("Logging from the db logger!");

    return 0;
}
