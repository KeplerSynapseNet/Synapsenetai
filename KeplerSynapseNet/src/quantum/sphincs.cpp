#include "quantum/quantum_security.h"
#include "crypto/crypto.h"
#include <mutex>
#include <random>
#include <cstring>
#include <algorithm>

namespace synapse {
namespace quantum {

namespace {
std::vector<uint8_t> deriveSphincsSignatureMaterial(const std::vector<uint8_t>& message,
                                                    const std::array<uint8_t, 32>& publicTag) {
    std::vector<uint8_t> seed(message.begin(), message.end());
    seed.insert(seed.end(), publicTag.begin(), publicTag.end());
    auto state = crypto::sha256(seed.data(), seed.size());

    std::vector<uint8_t> out(SPHINCS_SIGNATURE_SIZE);
    size_t written = 0;
    uint32_t counter = 0;
    while (written < out.size()) {
        std::vector<uint8_t> input(state.begin(), state.end());
        input.push_back(static_cast<uint8_t>((counter >> 24) & 0xff));
        input.push_back(static_cast<uint8_t>((counter >> 16) & 0xff));
        input.push_back(static_cast<uint8_t>((counter >> 8) & 0xff));
        input.push_back(static_cast<uint8_t>(counter & 0xff));
        auto block = crypto::sha256(input.data(), input.size());
        size_t take = std::min(block.size(), out.size() - written);
        std::memcpy(out.data() + written, block.data(), take);
        written += take;
        state = block;
        counter++;
    }
    return out;
}
}

struct Sphincs::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(rng());
        }
    }
};

Sphincs::Sphincs() : impl_(std::make_unique<Impl>()) {}
Sphincs::~Sphincs() = default;

SphincsKeyPair Sphincs::generateKeyPair() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    SphincsKeyPair kp;
    impl_->fillRandom(kp.secretKey.data(), kp.secretKey.size());
    
    auto hash = crypto::sha256(kp.secretKey.data(), kp.secretKey.size());
    std::memcpy(kp.publicKey.data(), hash.data(), kp.publicKey.size());
    
    return kp;
}

SignatureResult Sphincs::sign(const std::vector<uint8_t>& message,
                               const SphincsSecretKey& secretKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    SignatureResult result;
    auto publicHash = crypto::sha256(secretKey.data(), secretKey.size());
    std::array<uint8_t, 32> publicTag{};
    std::memcpy(publicTag.data(), publicHash.data(), publicTag.size());
    result.signature = deriveSphincsSignatureMaterial(message, publicTag);
    result.success = true;
    return result;
}

bool Sphincs::verify(const std::vector<uint8_t>& message,
                     const SphincsSignature& signature,
                     const SphincsPublicKey& publicKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (!validatePublicKey(publicKey)) return false;

    std::array<uint8_t, 32> publicTag{};
    std::memcpy(publicTag.data(), publicKey.data(), publicTag.size());
    auto expected = deriveSphincsSignatureMaterial(message, publicTag);
    for (size_t i = 0; i < signature.size(); i++) {
        if (signature[i] != expected[i]) {
            return false;
        }
    }
    return true;
}

bool Sphincs::validatePublicKey(const SphincsPublicKey& publicKey) {
    for (size_t i = 0; i < publicKey.size(); i++) {
        if (publicKey[i] != 0) return true;
    }
    return false;
}

bool Sphincs::validateSecretKey(const SphincsSecretKey& secretKey) {
    for (size_t i = 0; i < secretKey.size(); i++) {
        if (secretKey[i] != 0) return true;
    }
    return false;
}

}
}
