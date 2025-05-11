#include "crypto_guard_ctx.h"

#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <vector>

namespace CryptoGuard {

namespace {

std::string OpenSSLError() {
    auto err = ERR_get_error();
    std::array<char, 256> buffer;
    ERR_error_string_n(err, buffer.data(), buffer.size());
    return std::string(buffer.data());
}

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); };
    ~Impl() { EVP_cleanup(); };

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CipherFile(inStream, outStream, password, true);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CipherFile(inStream, outStream, password, false);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        using ChecksumCtxPointer = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); })>;

        if (!inStream.good()) {
            throw std::runtime_error("Input stream is not readable");
        }

        ChecksumCtxPointer ctx(EVP_MD_CTX_new());
        if (!ctx) {
            throw std::runtime_error("Failed to create MD context: " + OpenSSLError());
        }

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("Failed to initialize MD context: " + OpenSSLError());
        }

        static constexpr std::size_t BUFFER_SIZE = 1024;
        std::vector<unsigned char> inBuffer(BUFFER_SIZE);

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
            if (inStream.bad()) {
                throw std::runtime_error("File read failure");
            }
            std::size_t readSize = inStream.gcount();
            if (readSize > 0 && EVP_DigestUpdate(ctx.get(), inBuffer.data(), readSize) != 1) {
                throw std::runtime_error("Failed to update MD context: " + OpenSSLError());
            }
        }

        unsigned int outLength;
        std::array<unsigned char, EVP_MAX_MD_SIZE> outBuffer;

        if (EVP_DigestFinal_ex(ctx.get(), outBuffer.data(), &outLength) != 1) {
            throw std::runtime_error("Failed to calculate final checksum: " + OpenSSLError());
        }

        std::ostringstream result;
        for (std::size_t i = 0; i < outLength; i++) {
            std::print(result, "{:02x}", outBuffer[i]);
        }
        return result.str();
    }

private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CipherParamsByPassword(std::string_view password, bool encrypt) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()),
                                    static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password: " + OpenSSLError()};
        }

        params.encrypt = encrypt;

        return params;
    }

    void CipherFile(std::iostream &inStream, std::iostream &outStream, std::string_view password, bool encrypt) {
        using CipherCtxPointer =
            std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); })>;
        if (!inStream.good()) {
            throw std::runtime_error("Input stream is not readable");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream is not writable");
        }
        AesCipherParams params = CipherParamsByPassword(password, encrypt);
        CipherCtxPointer ctx(EVP_CIPHER_CTX_new());

        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context: " + OpenSSLError());
        }

        if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
            1) {
            throw std::runtime_error("Failed to initialize cipher: " + OpenSSLError());
        }

        static constexpr std::size_t BUFFER_SIZE = 1024;

        std::vector<unsigned char> inBuffer(BUFFER_SIZE);
        std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
            if (inStream.bad()) {
                throw std::runtime_error("File read failure");
            }
            std::size_t readSize = inStream.gcount();
            if (readSize > 0) {
                int writeSize;
                if (EVP_CipherUpdate(ctx.get(), outBuffer.data(), &writeSize, inBuffer.data(), readSize) != 1) {
                    throw std::runtime_error("Failed to cipher data: " + OpenSSLError());
                }
                outStream.write(reinterpret_cast<char *>(outBuffer.data()), writeSize);
                if (outStream.bad()) {
                    throw std::runtime_error("File write failure");
                }
            }
        }
        int finalWriteSize;
        if (EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &finalWriteSize) != 1) {
            throw std::runtime_error("Failed to finalize data: " + OpenSSLError());
        }
        outStream.write(reinterpret_cast<char *>(outBuffer.data()), finalWriteSize);
        if (outStream.bad()) {
            throw std::runtime_error("File write failure");
        }
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
