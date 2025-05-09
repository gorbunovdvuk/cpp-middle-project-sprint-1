#include "cmd_options.h"

#include <iostream>
#include <print>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help,h", "Show help.")
        ("command,c", po::value<std::string>(), "Command 'encrypt', 'decrypt' or 'checksum'.")
        ("input,i", po::value<std::string>(), "Input file.")
        ("output,o", po::value<std::string>(), "Output file.")
        ("password,p", po::value<std::string>(), "Password.");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);
        if (vm.contains("help")) {
            std::cout << desc_ << std::endl;
            return false;
        }
        if (!vm.contains("command")) {
            std::cerr << "Argument error: --command option is required" << std::endl;
            return false;
        }
        std::string command = vm["command"].as<std::string>();
        std::ranges::transform(command, command.begin(), ::tolower);
        if (command == "encrypt") {
            command_ = COMMAND_TYPE::ENCRYPT;
        } else if (command == "decrypt") {
            command_ = COMMAND_TYPE::DECRYPT;
        } else if (command == "checksum") {
            command_ = COMMAND_TYPE::CHECKSUM;
        } else {
            std::cerr << "Argument error: Unknown command '" << command << "'" << std::endl;
            return false;
        }
        if (!vm.contains("input")) {
            std::cerr << "Argument error: input option is required" << std::endl;
            return false;
        }
        inputFile_ = vm["input"].as<std::string>();
        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            if (!vm.contains("output")) {
                std::cerr << "Argument error: output option is required" << std::endl;
                return false;
            }
            if (!vm.contains("password")) {
                std::cerr << "Argument error: password option is required" << std::endl;
                return false;
            }
        }
    } catch (po::error &e) {
        std::cerr << "Argument error: " + std::string(e.what());
        return false;
    }
    return true;
}

}  // namespace CryptoGuard
