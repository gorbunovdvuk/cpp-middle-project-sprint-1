#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

namespace {

std::fstream GetFilename(std::string_view path, std::ios_base::openmode mode) {
    std::fstream file(path.data(), mode);
    if (!file.is_open()) {
        throw std::runtime_error(std::format("Failed to open file '{}'", path));
    }
    return file;
}

}  // namespace

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        if (!options.Parse(argc, argv)) {
            options.PrintHelp();
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream fin(GetFilename(options.GetInputFile(), std::ios::binary | std::ios::in));
            std::fstream fout(GetFilename(options.GetOutputFile(), std::ios::binary | std::ios::out | std::ios::trunc));
            cryptoCtx.EncryptFile(fin, fout, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream fin(GetFilename(options.GetInputFile(), std::ios::binary | std::ios::in));
            std::fstream fout(GetFilename(options.GetOutputFile(), std::ios::binary | std::ios::out | std::ios::trunc));
            cryptoCtx.DecryptFile(fin, fout, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream fin(GetFilename(options.GetInputFile(), std::ios::binary | std::ios::in));
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(fin));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}