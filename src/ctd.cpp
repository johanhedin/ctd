
#include <unistd.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <csignal>
#include <functional>
#include <utility>
#include <algorithm>

#include "argparse/argparse.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/syslog_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include "httplib.h"

#include "nlohmann/json.hpp"

#include "config.hpp"
#include "config_parser.hpp"

// REST server candidates:
//   - https://github.com/pistacheio/pistache
//   - https://github.com/oatpp/oatpp
//   - https://github.com/yhirose/cpp-httplib

// JSON handling:
//   - https://github.com/nlohmann/json

// How to use spdlog
//   - https://www.youtube.com/watch?v=p2U0VvILysg

// Make it possible to have a lambda as a signal handler (assign a lambda to
// the global variable shutdown_handler)
std::function<void(int)> shutdown_handler;
void signal_handler(int signal) { shutdown_handler(signal); }

static const std::string PROGRAM_NAME_STR{"ctd"};
static const std::string PROGRAM_VERSION_STR{"0.99rc1"};
static const std::string DEFAULT_CFG_FILE{"/etc/ctd/ctd.yaml"};


void worker_function(const std::string& item, std::mutex& m, std::condition_variable& cv, bool& run, spdlog::logger &logger) {
    using namespace std::chrono_literals;

    while (true) {
        logger.info("Worker {} is doing work...", item);

        std::unique_lock<std::mutex> lock(m);
        cv.wait_for(lock, 1000ms, [&run](){ return !run; });
        if (!run) break;
    }

    logger.info("Worker {} stopped.", item);
}


int main(int argc, char** argv) {
    std::string cfg_file{DEFAULT_CFG_FILE};

    // Create and configure argparse instance
    argparse::ArgumentParser parser(PROGRAM_NAME_STR, PROGRAM_VERSION_STR);
    parser.add_description("A template daemon");
    parser.add_argument("-c", "--config-file").metavar("FILE")
        .help(std::string() + "configuration file to use. Defaults to "  + DEFAULT_CFG_FILE + " if not set");
    parser.add_argument("--validate").flag()
        .help("validates the config file and exits");
    parser.add_argument("--dump").flag()
        .help("dumps the current config to stdout and exits");

    // Parse command line arguments
    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    } catch (...) {
        std::cerr << "Error: Unhandled exception while parsing command line arguments." << std::endl;
        return 2;
    }

    // Extract config file, if set
    if (auto cf = parser.present("-c")) {
        cfg_file = *cf;
    }

    // Parse config file. Stop if it is invalid
    auto config = ctd::parse_config(cfg_file);
    if (!config) return 3;

    if (parser["--validate"] == true) {
        // If here, we know that the config file is valid. Just write a heads up and exit
        std::cerr << "Config file: " << cfg_file << " is valid." << std::endl;
        return 0;
    }

    if (parser["--dump"] == true) {
        ctd::dump_config(*config);
        return 0;
    }

    // Config file is now parsed and has correct syntax. Setup logging
    try {
        auto logger = std::make_shared<spdlog::logger>("main");
        auto lvl{spdlog::level::info};

        switch (config->logging.level) {
            case LOG_DEBUG:   lvl = spdlog::level::debug;    break;
            case LOG_INFO:    lvl = spdlog::level::info;     break;
            case LOG_WARNING: lvl = spdlog::level::warn;     break;
            case LOG_ERR:     lvl = spdlog::level::err;      break;
            case LOG_CRIT:    lvl = spdlog::level::critical; break;
            default:          lvl = spdlog::level::info;
        }
        logger->set_level(lvl);

        if (config->logging.stdout && config->logging.stdout.active) {
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_level(spdlog::level::debug);
            logger->sinks().push_back(console_sink);
        }

        if (config->logging.syslog && config->logging.syslog.active) {
            auto syslog_sink = std::make_shared<spdlog::sinks::syslog_sink_mt>(PROGRAM_NAME_STR, 0, config->logging.syslog.facility, false);
            syslog_sink->set_level(spdlog::level::debug);
            logger->sinks().push_back(syslog_sink);
        }

        if (config->logging.file && config->logging.file.active) {
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                config->logging.file.dir + "/main.log",
                config->logging.file.size,
                config->logging.file.max_files
            );
            file_sink->set_level(spdlog::level::debug);
            logger->sinks().push_back(file_sink);
        }

        spdlog::set_default_logger(logger);
        spdlog::flush_every(std::chrono::seconds(5));
    } catch (...) {
        std::cerr << "Error: Unhandled exception while setting up logging.";
        return 4;
    }

    // Logging is now setup. All printouts from now on will be via the log

    // Test the log
    spdlog::debug("Debug, debug!");
    spdlog::info("Info, info!");
    spdlog::warn("Warn, warn!");
    spdlog::error("Error, error!");
    spdlog::critical("Critical, critical!");
    spdlog::info(" ");

    spdlog::info("Starting...");

    // SIGTERM and SIGINT handling for stopping the daemon
    bool run{true};
    std::mutex run_mutex;
    std::condition_variable run_cv;

    shutdown_handler = [&](int) -> void {
        spdlog::info("Signal caught. Stopping...");
        {
            std::unique_lock<std::mutex> lock(run_mutex);
            run = false;
        }
        run_cv.notify_one();
    };

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);


    /*
    std::string item1{"one"};
    std::string item2{"two"};

    std::mutex m;
    std::condition_variable cv;
    bool thread_run{true};

    std::thread worker1(worker_function, item1, std::ref(m), std::ref(cv), std::ref(thread_run), std::ref(logger));
    std::thread worker2(worker_function, item2, std::ref(m), std::ref(cv), std::ref(thread_run), std::ref(logger));

    {
        std::unique_lock<std::mutex> lock(m);
        std::cout << "Main program sleeping for 5s..." << std::endl;
    }
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(5000ms);

    std::cout << "Signaling thread to stop..." << std::endl;
    {
        std::lock_guard<std::mutex> lock(m);
        thread_run = false;
    }
    cv.notify_all();

    worker1.join();
    worker2.join();
    */

    using json = nlohmann::json;
    json dict = {
        { "status", true },
        { "version", PROGRAM_VERSION_STR }
    };

    auto srv_pre_routing_handler = [](const auto &req, auto &res) {
        std::string remote_addr = req.remote_addr;
        size_t colon_pos = remote_addr.find(':');
        if (colon_pos != remote_addr.npos) {
            remote_addr = "[" + remote_addr + "]";
        }
        spdlog::info("Incoming REST request from {}:{}.", remote_addr, req.remote_port);
        if (req.has_header("X-Ctd-Auth")) {
            res.status = httplib::StatusCode::Unauthorized_401;
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    };
    auto srv_logger = [](const auto&, const auto&) {
        spdlog::info("Logging from httplib...");
    };
    auto hi_handler = [](const httplib::Request &, httplib::Response &res) {
        res.status = httplib::StatusCode::Accepted_202;
        res.set_content("Hi there!\n", "text/plain");
    };
    auto api_handler = [&dict](const httplib::Request &, httplib::Response &res) {
        res.set_content(dict.dump(4) + "\n", "application/json");
    };
    auto root_handler = [](const httplib::Request &, httplib::Response &res) {
        json json_res = {
            { "version", PROGRAM_VERSION_STR }
        };
        res.set_content(json_res.dump(4) + "\n", "application/json");
    };

    if (!config->main.listen.empty()) {
        spdlog::info("Starting REST server...");
    }

    std::vector<std::pair<std::shared_ptr<httplib::Server>, std::thread>> servers;
    for (auto &l : config->main.listen) {
        auto s = std::make_shared<httplib::Server>();
        s->set_logger(srv_logger);
        s->set_pre_routing_handler(srv_pre_routing_handler);
        s->Get("/", root_handler);
        s->Get("/hi", hi_handler);
        s->Get("/api", api_handler);
        auto host = l.first;
        auto port = l.second;

        std::thread t([s, host, port]{
            spdlog::info("REST server listening on {}:{}.", host, port);
            auto tmp_host = host;
            tmp_host.erase(std::remove(tmp_host.begin(), tmp_host.end(), '['), tmp_host.end());
            tmp_host.erase(std::remove(tmp_host.begin(), tmp_host.end(), ']'), tmp_host.end());
            auto ret = s->listen(tmp_host, port);
            if (ret == true) {
                spdlog::info("REST server stopped listening on {}:{}.", host, port);
            } else {
                spdlog::error("Listen on {}:{} failed.", host, port);
            }
        });

        s->wait_until_ready();
        if (s->is_running()) {
            servers.push_back({std::move(s), std::move(t)});
        } else {
            t.join();
        }
    }

    if (!servers.empty()) {
        spdlog::info("REST server started. Listening on {} address{}.", servers.size(), servers.size() > 1 ? "es":"");
    }

    // This is the main loop. Just wait until the stop_cv is signaled from
    // the shutdown handler
    spdlog::info("Running. Stop with SIGINT or SIGTERM.");
    {
        std::unique_lock<std::mutex> lock(run_mutex);
        run_cv.wait(lock, [&run]{ return !run; });
    }

    if (!servers.empty()) {
        spdlog::info("Stopping REST server...");
        for (auto &s : servers) {
            s.first->stop();
            if (s.second.joinable()) s.second.join();
        }
        spdlog::info("REST server stopped.");
    }

    spdlog::info("Stopped.");

    return 0;
}
