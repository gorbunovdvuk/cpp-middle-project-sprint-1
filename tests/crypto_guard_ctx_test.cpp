#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <sstream>

TEST(CryptoGuardCtxTest, TestCalculateChecksum) {
    const std::string line = "Hello OpenSSL crypto world!";
    std::stringstream input(line);
    EXPECT_EQ(CryptoGuard::CryptoGuardCtx().CalculateChecksum(input),
              "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899");
}

TEST(CryptoGuardCtxTest, TestEncryptDecrypt) {
    const std::string line = "Hello OpenSSL crypto world!";
    const std::string password = "PaSsWoRd";

    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input(line);
    std::stringstream encrypted, decrypted;
    ctx.EncryptFile(input, encrypted, password);
    ctx.DecryptFile(encrypted, decrypted, password);
    EXPECT_EQ(line, decrypted.str());
}

TEST(CryptoGuardCtxTest, TestLargeInput) {
    const std::string line = std::string(1'000'000, 'A');
    const std::string password = "password";
    CryptoGuard::CryptoGuardCtx ctx;
    std::string initial_checksum = [&line, &ctx]() {
        std::stringstream input(line);
        return ctx.CalculateChecksum(input);
    }();
    std::string encdec_checksum = [&line, &ctx, &password]() {
        std::stringstream input(line);
        std::stringstream encrypted, decrypted;
        ctx.EncryptFile(input, encrypted, password);
        ctx.DecryptFile(encrypted, decrypted, password);
        return ctx.CalculateChecksum(decrypted);
    }();
    EXPECT_EQ(initial_checksum, encdec_checksum);
}

TEST(CryptoGuardCtxTest, TestDecryptDifferentPassword) {
    const std::string line = "Hello OpenSSL crypto world!";
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input(line);
    std::stringstream encrypted, decrypted;
    ctx.EncryptFile(input, encrypted, "pass1");
    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "pass2"), std::runtime_error);
}

TEST(CryptoGuardCtxTest, TestUnreadableInput) {
    const std::string password = "password";
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream unreadable_input, output;
    unreadable_input.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.EncryptFile(unreadable_input, output, password), std::runtime_error);
    ASSERT_THROW(ctx.DecryptFile(unreadable_input, output, password), std::runtime_error);
    ASSERT_THROW(ctx.CalculateChecksum(unreadable_input), std::runtime_error);
}

TEST(CryptoGuardCtxTest, TestUnwritableOutput) {
    const std::string line = "Hello OpenSSL crypto world!";
    const std::string password = "password";
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input(line), unwritable_output;
    unwritable_output.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.EncryptFile(input, unwritable_output, password), std::runtime_error);
    ASSERT_THROW(ctx.DecryptFile(input, unwritable_output, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, TestAlteredData) {
    const std::string line = "Hello OpenSSL crypto world!";
    const std::string password = "password";
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input(line), encrypted, decrypted;
    ctx.EncryptFile(input, encrypted, password);
    std::string encrypted_string = encrypted.str();
    encrypted_string.erase(encrypted_string.begin());
    encrypted = std::stringstream(encrypted_string);
    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, EmptyStreamTest) {
    const std::string password = "password";
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input, encrypted, decrypted;
    ctx.EncryptFile(input, encrypted, password);
    ctx.DecryptFile(encrypted, decrypted, password);
    EXPECT_TRUE(decrypted.str().empty());
}
