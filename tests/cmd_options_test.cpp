#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(CmdOptionsTest, TestHelp) {
  static constexpr std::array args = { "CryptoGuard", "--help" };
  EXPECT_EQ(CryptoGuard::ProgramOptions().Parse(args.size(), args.data()), 0);
}

TEST(CmdOptionsTest, TestAllCmdCorrect) {
  static constexpr std::string_view inputFile = "input_file";
  static constexpr std::string_view outputFile = "output_file";
  static constexpr std::string_view password = "password";

  {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array argsEncrypt = { "CryptoGuard", "-c", "encrypt", "-i", inputFile.data(), "-o", outputFile.data(), "-p", password.data() };
    EXPECT_NO_THROW(options.Parse(argsEncrypt.size(), argsEncrypt.data()));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetPassword(), password);
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), outputFile);
  }

  {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array argsDecrypt = { "CryptoGuard", "-c", "decrypt", "-i", inputFile.data(), "-o", outputFile.data(), "-p", password.data() };
    EXPECT_NO_THROW(options.Parse(argsDecrypt.size(), argsDecrypt.data()));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetPassword(), password);
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), outputFile);
  }

  {
    CryptoGuard::ProgramOptions options;
    static constexpr std::array argsChecksum = { "CryptoGuard", "-c", "checksum", "-i", inputFile.data() };
    EXPECT_NO_THROW(options.Parse(argsChecksum.size(), argsChecksum.data()));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetPassword(), "");
    EXPECT_EQ(options.GetInputFile(), inputFile);
    EXPECT_EQ(options.GetOutputFile(), "");
  }
}

TEST(CmdOptionsTest, TestCommandUppercase) {
  static constexpr std::array args = { "CryptoGuard", "-c", "ChEcKsUm", "-i", "input_file" };
  CryptoGuard::ProgramOptions options;
  EXPECT_NO_THROW(options.Parse(args.size(), args.data()));
  EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}


