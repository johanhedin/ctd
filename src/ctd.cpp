
#include <iostream>
#include <thread>

#include <argparse/argparse.hpp>

static const std::string VERSION_STR{"0.99rc1"};

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
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    // Extract arguments given
    std::string cfg_file = program.is_used("-c") ? program.get<std::string>("-c") : "/etc/ctd/ctd.yaml";

    if (program["--validate"] == true) {
        std::cout << "Validating config file: " << cfg_file << std::endl;
        return 0;
    }

    std::cout << "Using config file: " << cfg_file << std::endl;

    return 0;
}
