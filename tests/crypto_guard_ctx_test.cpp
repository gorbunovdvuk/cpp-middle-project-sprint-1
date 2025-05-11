#include "crypto_guard_ctx.h"

#include <sstream>
#include <gtest/gtest.h>

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
