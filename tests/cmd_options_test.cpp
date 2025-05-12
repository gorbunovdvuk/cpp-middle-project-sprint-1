#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(CmdOptionsTest, TestHelp) {
    static constexpr std::array args = {"CryptoGuard", "--help"};
    EXPECT_EQ(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), 0);
}

TEST(CmdOptionsTest, TestEncryptCorrect) {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array args = {"CryptoGuard", "-c",          "encrypt", "-i",      "input_file",
                                        "-o",          "output_file", "-p",      "password"};
    options.Parse(args.size(), args.data());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetPassword(), "password");
    EXPECT_EQ(options.GetInputFile(), "input_file");
    EXPECT_EQ(options.GetOutputFile(), "output_file");
}

TEST(CmdOptionsTest, TestDecryptCorrect) {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array args = {"CryptoGuard", "-c",          "decrypt", "-i",      "input_file",
                                        "-o",          "output_file", "-p",      "password"};
    options.Parse(args.size(), args.data());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetPassword(), "password");
    EXPECT_EQ(options.GetInputFile(), "input_file");
    EXPECT_EQ(options.GetOutputFile(), "output_file");
}

TEST(CmdOptionsTest, TestChecksumCorrect) {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array argsEncrypt = {"CryptoGuard", "-c", "checksum", "-i", "input_file"};
    options.Parse(argsEncrypt.size(), argsEncrypt.data());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetPassword(), "");
    EXPECT_EQ(options.GetInputFile(), "input_file");
    EXPECT_EQ(options.GetOutputFile(), "");
}

TEST(CmdOptionsTest, TestCommandUppercase) {
    static constexpr std::array args = {"CryptoGuard", "-c", "ChEcKsUm", "-i", "input_file"};
    CryptoGuard::ProgramOptions options;
    options.Parse(args.size(), args.data());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(CmdOptionsTest, TestNoCommand) {
    static constexpr std::array args = {"CryptoGuard", "-i", "input_file"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestUnknownCommand) {
    static constexpr std::array args = {"CryptoGuard", "-c", "abracadabra"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestNoInputOption) {
    static constexpr std::array args = {"CryptoGuard", "-c", "encrypt", "-o", "output_file", "-p", "password"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestNoOutputOption) {
    static constexpr std::array args = {"CryptoGuard", "-c", "decrypt", "-i", "input_file", "-p", "password"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestNoPasswordOption) {
    static constexpr std::array args = {"CryptoGuard", "-c", "encrypt", "-i", "input_file", "-o", "output_file"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestOutputRedundantOption) {
    static constexpr std::array args = {"CryptoGuard", "-c", "checksum", "-i", "input_file", "-o", "output_file"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestPasswordRedundantOption) {
    static constexpr std::array args = {"CryptoGuard", "-c", "checksum", "-i", "input_file", "-p", "password"};
    EXPECT_THROW(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), std::runtime_error);
}

TEST(CmdOptionsTest, TestLongNames) {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array args = {"CryptoGuard", "--command",   "encrypt",    "--input", "input_file",
                                        "--output",    "output_file", "--password", "password"};
    options.Parse(args.size(), args.data());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetPassword(), "password");
    EXPECT_EQ(options.GetInputFile(), "input_file");
    EXPECT_EQ(options.GetOutputFile(), "output_file");
}
