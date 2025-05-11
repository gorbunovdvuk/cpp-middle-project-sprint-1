#include "crypto_guard_ctx.h"

#include <sstream>
#include <gtest/gtest.h>

TEST(CryptoGuardCtxTest, BasicAppUsage) {
    const std::string line = "Hello OpenSSL crypto world!";
    const std::string password = "PaSsWoRd";
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
