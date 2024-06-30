
#include <iostream>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

#include "argparse/argparse.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/syslog_sink.h"

#include "config.hpp"
#include "config_parser.hpp"

// REST server candidates:
//   - https://github.com/pistacheio/pistache
//   - https://github.com/oatpp/oatpp

static const std::string VERSION_STR{"0.99rc1"};


void worker_function(const std::string& item, std::mutex& m, std::condition_variable& cv, bool& run) {
    using namespace std::chrono_literals;

    while (true) {
        std::cout << "Worker " << item << " doing work..." << std::endl;

        std::unique_lock<std::mutex> lock(m);
        cv.wait_for(lock, 1000ms, [&run](){ return !run; });
        if (!run) break;
    }

    std::cout << "Worker " << item << " stopped."  << std::endl;
}


int main(int argc, char** argv) {
    // Create argparse instance
    argparse::ArgumentParser program("ctd", VERSION_STR);

    // Configure argparse instance
    program.add_description("A template daemon");
    program.add_argument("-c", "--config-file")
        .help("configuration file to use. Defaults to /etc/ctd/ctd.yaml if not set")
        .metavar("FILE");
    program.add_argument("--validate")
        .help("validates the config file and exits")
        .flag();
    program.add_argument("--dump")
        .help("dumps the config file to stdout and exits")
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
        auto config = ctd::parse_config(cfg_file);
        if (!config) return 3;
        std::cout << "Config file: " << cfg_file << " is valid." << std::endl;
        return 0;
    }

    if (program["--dump"] == true) {
        auto config = ctd::parse_config(cfg_file);
        if (!config) return 3;
        ctd::dump_config(*config);
        return 0;
    }

    std::cout << "Parsing config file: " << cfg_file << "..." << std::endl;
    auto config = ctd::parse_config(cfg_file);
    if (!config) return 3;

    std::cout << "config.main.tag_mappings_file=" << config->main.tag_mappings_file << std::endl;

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

    std::string item1{"one"};
    std::string item2{"two"};

    std::mutex m;
    std::condition_variable cv;
    bool run{true};

    std::thread worker1(worker_function, item1, std::ref(m), std::ref(cv), std::ref(run));
    std::thread worker2(worker_function, item2, std::ref(m), std::ref(cv), std::ref(run));

    {
        std::unique_lock<std::mutex> lock(m);
        std::cout << "Main program sleeping for 5s..." << std::endl;
    }
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(5000ms);

    std::cout << "Signaling thread to stop..." << std::endl;
    {
        std::lock_guard<std::mutex> lock(m);
        run = false;
    }
    cv.notify_all();

    worker1.join();
    worker2.join();

    std::cout << "ctd stopped." << std::endl;

    return 0;
}
