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

bool ProgramOptions::Parse(int argc, const char* const argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);
        if (vm.contains("help")) {
            std::cout << desc_ << std::endl;
            return false;
        }
        if (!vm.contains("command")) {
            throw std::runtime_error("Argument error: --command option is required");
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
            throw std::runtime_error("Argument error: Unknown command '" + command + "'");
        }
        if (!vm.contains("input")) {
            throw std::runtime_error("Argument error: input option is required");
        }
        inputFile_ = vm["input"].as<std::string>();
        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            if (!vm.contains("output")) {
                throw std::runtime_error("Argument error: output option is required");
            }
            if (!vm.contains("password")) {
                throw std::runtime_error("Argument error: password option is required");
            }
            outputFile_ = vm["output"].as<std::string>();
            password_ = vm["password"].as<std::string>();
        } else {
            if (vm.contains("output")) {
                throw std::runtime_error("Argument error: output option is redundant");
            }
            if (vm.contains("password")) {
                throw std::runtime_error("Argument error: password option is redundant");
            }
        }
    } catch (po::error &e) {
        throw std::runtime_error("Argument error: " + std::string(e.what()));
    }
    return true;
}

}  // namespace CryptoGuard
