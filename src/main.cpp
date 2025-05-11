#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        if (!options.Parse(argc, argv)) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream fin(options.GetInputFile(), std::ios::binary | std::ios::in);
            if (!fin) {
                throw std::runtime_error("Failed to open input file");
            }
            std::fstream fout(options.GetOutputFile(), std::ios::binary | std::ios::out | std::ios::trunc);
            if (!fout) {
                throw std::runtime_error("Failed to open output file");
            }
            cryptoCtx.EncryptFile(fin, fout, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream fin(options.GetInputFile(), std::ios::binary | std::ios::in);
            if (!fin) {
                throw std::runtime_error("Failed to open input file");
            }
            std::fstream fout(options.GetOutputFile(), std::ios::binary | std::ios::out | std::ios::trunc);
            if (!fout) {
                throw std::runtime_error("Failed to open output file");
            }
            cryptoCtx.DecryptFile(fin, fout, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream fin(options.GetInputFile(), std::ios::binary | std::ios::in);
            if (!fin) {
                throw std::runtime_error("Failed to open input file");
            }
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