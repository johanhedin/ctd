
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <csignal>
#include <functional>
#include <utility>
#include <algorithm>
#include <deque>

#include "argparse/argparse.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/syslog_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include "httplib.h"

#include "nlohmann/json.hpp"

#include "config.hpp"
#include "config_parser.hpp"

// REST server candidates (besides cpp-httplib):
//   - https://github.com/pistacheio/pistache
//   - https://github.com/oatpp/oatpp

// ACME client candidate:
//   - https://github.com/jmccl/acme-lw

// How to use spdlog
//   - https://www.youtube.com/watch?v=p2U0VvILysg

// CSV parser candidates
//   - https://github.com/ashaduri/csv-parser

// Make it possible to have a lambda as a signal handler (assign a lambda to
// the global variable signal_callback before registering signal_handler)
static std::function<void(int)> signal_callback = nullptr;
static void signal_handler(int signal) { signal_callback(signal); }


static const std::string PROGRAM_NAME_STR{"ctd"};
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
static const std::string PROGRAM_VERSION_STR{"0.99rc1.tls"};
#else
static const std::string PROGRAM_VERSION_STR{"0.99rc1"};
#endif
static const std::string DEFAULT_CFG_FILE{"/etc/ctd/ctd.yaml"};


int main(int argc, char** argv) {
    std::string cfg_file{DEFAULT_CFG_FILE};

    // Create and configure argparse instance
    argparse::ArgumentParser parser(PROGRAM_NAME_STR, PROGRAM_VERSION_STR);
    parser.add_description("A small skeleton daemon.");
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

    // Extract name of config file, if set
    if (auto cf = parser.present("-c")) {
        cfg_file = *cf;
    }

    // Parse config file. Stop if it is invalid. Relevant errors have been written
    // to stderr during parsing.
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
    spdlog::debug("Testing debug: debug");
    spdlog::info("Testing info: info");
    spdlog::warn("Testing warn: warn");
    spdlog::error("Testing error: error");
    spdlog::critical("Testing critical: critical");
    spdlog::info(" ");

    spdlog::info("{} version {} starting...", PROGRAM_NAME_STR, PROGRAM_VERSION_STR);

    // Signal handling. We use a mutex protected deque to "send" the signals to
    // the main thread (see further down). SIGINT/SIGTERM have priority.
    std::deque<int> sq;
    std::mutex sq_mutex;
    std::condition_variable sq_cv;
    signal_callback = [&](int signal) -> void {
        spdlog::info("Signal {} caught. Pushing to signal queue.", signal);
        {
            std::unique_lock<std::mutex> l{sq_mutex};
            if (signal == SIGTERM || signal == SIGINT) {
                sq.push_front(signal);
            } else {
                sq.push_back(signal);
            }
        }
        sq_cv.notify_one();
    };
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGHUP,  signal_handler);

    using json = nlohmann::json;
    json dict = {
        { "status", true },
        { "version", PROGRAM_VERSION_STR }
    };

    auto srv_pre_routing_handler = [](const httplib::Request &req, httplib::Response &res) -> httplib::Server::HandlerResponse {
        std::string remote_addr = req.remote_addr;
        std::string local_addr  = req.local_addr;
        if (remote_addr.find(':') != remote_addr.npos) remote_addr = "[" + remote_addr + "]";
        if (local_addr.find(':')  != local_addr.npos)  local_addr  = "[" + local_addr  + "]";

        spdlog::debug("Incoming REST request to {}:{} from {}:{}.", local_addr, req.local_port, remote_addr, req.remote_port);
        if (req.has_header("X-Ctd-Auth")) {
            res.status = httplib::StatusCode::Unauthorized_401;
            return httplib::Server::HandlerResponse::Handled;
        }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (req.ssl != nullptr) {
            // Look here for example of how to get client cert: https://github.com/yhirose/cpp-httplib/pull/165
            std::string c;
            std::string o;
            std::string ou;
            std::string cn;

            auto peer_cert = SSL_get_peer_certificate(req.ssl);
            if (peer_cert != nullptr) {
                auto sn_obj = X509_get_subject_name(peer_cert);
                if (sn_obj != nullptr) {
                    int len;
                    char tmp_str[128];

                    len = X509_NAME_get_text_by_NID(sn_obj, NID_countryName, tmp_str, sizeof(tmp_str));
                    if (len > 0) c.assign(tmp_str, len);

                    len = X509_NAME_get_text_by_NID(sn_obj, NID_organizationName, tmp_str, sizeof(tmp_str));
                    if (len > 0) o.assign(tmp_str, len);

                    len = X509_NAME_get_text_by_NID(sn_obj, NID_organizationalUnitName, tmp_str, sizeof(tmp_str));
                    if (len > 0) ou.assign(tmp_str, len);

                    len = X509_NAME_get_text_by_NID(sn_obj, NID_commonName, tmp_str, sizeof(tmp_str));
                    if (len > 0) cn.assign(tmp_str, len);
                }

                X509_free(peer_cert);

                spdlog::debug("Client certificate info: C={}, O={}, OU={}, CN={}", c, o, ou, cn);
            }
        }
#endif

        return httplib::Server::HandlerResponse::Unhandled;
    };
    auto hi_handler = [](const httplib::Request &, httplib::Response &res) {
        res.status = httplib::StatusCode::Accepted_202;
        res.set_content("Hi there!\n", "text/plain");
    };
    auto api_handler = [&dict](const httplib::Request &req, httplib::Response &res) {
        auto host = req.get_header_value("Host");
        spdlog::debug("Incoming request for /api. Host = {}", host);
        res.set_content(dict.dump(4) + "\n", "application/json");
    };
    auto root_handler = [](const httplib::Request &, httplib::Response &res) {
        json json_res = {
            { "version", PROGRAM_VERSION_STR }
        };
        res.set_content(json_res.dump(4) + "\n", "application/json");
    };

    class Srv {
    public:
        Srv(const ctd::Config::Listen &l, const std::string &ca) :
            addr(l.addr), port(l.port), https(l.https), cert(l.cert), key(l.key), ca(ca) {};
        Srv() = default;
        std::shared_ptr<httplib::Server> s{nullptr};
        std::thread                      t{};
        std::string                      addr{};
        int                              port{-1};
        bool                             https{false};
        std::string                      cert{};
        std::string                      key{};
        std::string                      ca{};
    };
    std::vector<Srv> servers;

    // Function for staring the REST server and listen to all configured
    // addresses.
    auto start_rest_server = [&]() {
        for (const auto &l : config->main.listen) {
            Srv srv(l, config->main.client_ca);

            if (srv.https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
                // Check if file f is readable
                auto readable = [](const std::string &f) -> bool { std::ifstream fs(f); return fs.good(); };

                if (!readable(srv.cert)) {
                    spdlog::warn("Unable to read cert file {}. Skipping listen on {}:{} with https.", srv.cert, srv.addr, srv.port);
                    continue;
                }
                if (!readable(srv.key)) {
                    spdlog::warn("Unable to read key file {}. Skipping listen on {}:{} with https.", srv.key, srv.addr, srv.port);
                    continue;
                }

                if (!srv.ca.empty() && !readable(srv.ca)) {
                    spdlog::warn("Unable to read client CA file {}. Skipping listen on {}:{} with https.", srv.ca, srv.addr, srv.port);
                    continue;
                }
                srv.s = std::make_shared<httplib::SSLServer>(srv.cert.c_str(), srv.key.c_str(), srv.ca.empty() ? nullptr:srv.ca.c_str());
#else
                spdlog::error("https requested for {}:{} but https support is not compiled in. Skipping.", srv.addr, srv.port);
                continue;
#endif
            } else {
                srv.s = std::make_shared<httplib::Server>();
            }
            srv.s->set_pre_routing_handler(srv_pre_routing_handler);
            srv.s->Get("/", root_handler);
            srv.s->Get("/hi", hi_handler);
            srv.s->Get("/api", api_handler);

            srv.t = std::thread([](std::shared_ptr<httplib::Server> s, std::string addr, int port, bool https){
                auto tmp_host = addr;
                tmp_host.erase(std::remove(tmp_host.begin(), tmp_host.end(), '['), tmp_host.end());
                tmp_host.erase(std::remove(tmp_host.begin(), tmp_host.end(), ']'), tmp_host.end());
                auto ret = s->listen(tmp_host, port);
                if (ret == true) {
                    spdlog::info("REST server stopped listening on {}:{}.", addr, port);
                } else {
                    if (https) {
                        spdlog::error("Listen on {}:{} with https failed. Check address, port, cert file and/or key file.", addr, port);
                    } else {
                        spdlog::error("Listen on {}:{} with http failed. Check address and/or port.", addr, port);
                    }
                }
            }, srv.s, srv.addr, srv.port, srv.https);

            srv.s->wait_until_ready();
            if (srv.s->is_running()) {
                spdlog::info("REST server listening on {}:{} with {}.", srv.addr, srv.port, srv.https?"https":"http");
                servers.push_back(std::move(srv));
            } else {
                srv.t.join();
            }
        }
    };

    // Function for stopping the REST server.
    auto stop_rest_server = [&]() {
        for (auto &s : servers) {
            s.s->stop();
            if (s.t.joinable()) s.t.join();
        }

        servers.clear();
    };

    if (!config->main.listen.empty()) {
        spdlog::info("Starting REST server...");
        start_rest_server();
        if (servers.size() > 0) {
            spdlog::info("REST server started. Listening on {} address{}.", servers.size(), servers.size() == 1 ? "":"es");
        } else {
            spdlog::warn("Failed to start REST server.");
        }
    }

    spdlog::info("Running. Stop with SIGINT or SIGTERM.");

    // Main loop. Pops signals from the signal queue and act accordingly. Do
    // regular bookkeeping every 10-ish second
    bool run{true};
    while (run) {
        using namespace std::chrono_literals;
        std::unique_lock<std::mutex> l{sq_mutex};
        if (!sq.empty()) {
            auto signal = sq.front();
            sq.pop_front();
            l.unlock();

            switch (signal)  {
                case SIGTERM:
                    spdlog::info("SIGTERM received. Stopping...");
                    run = false;
                    break;
                case SIGINT:
                    spdlog::info("SIGINT received. Stopping...");
                    run = false;
                    break;
                case SIGHUP:
                    spdlog::info("Restarting REST server...");
                    stop_rest_server();
                    start_rest_server();
                    if (servers.size() > 0) {
                        spdlog::info("REST server restarted. Listening on {} address{}.", servers.size(), servers.size() == 1 ? "":"es");
                    } else {
                        spdlog::warn("Failed to restart REST server.");
                    }
                    break;
                default:
                    break;
            }
        } else {
            sq_cv.wait_for(l, 10s, [&sq](){ return !sq.empty(); });
            if (sq.empty()) {
                l.unlock();
                spdlog::debug("Main thread doing bookkeeping");
            }
        }
    }

    if (!servers.empty()) {
        spdlog::info("Stopping REST server...");
        stop_rest_server();
        spdlog::info("REST server stopped.");
    }

    spdlog::info("Successfully stopped. Bye.");

    return 0;
}
