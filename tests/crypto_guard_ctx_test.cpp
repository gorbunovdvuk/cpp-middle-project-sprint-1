#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

TEST(CryptoGuardCtxTest, BasicAppUsage) {
    static constexpr std::string_view line = "Hello OpenSSL crypto world!";
    static constexpr std::string_view password = "PaSsWoRd";
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input1, input2, encrypted, decrypted;
    input1 << line;
    input2 << line;
    ASSERT_NO_THROW(ctx.EncryptFile(input1, encrypted, password));
    ASSERT_NO_THROW(ctx.DecryptFile(encrypted, decrypted, password));
    EXPECT_EQ(decrypted.str(), line);
    ASSERT_EQ(ctx.CalculateChecksum(input2), ctx.CalculateChecksum(decrypted));
}
