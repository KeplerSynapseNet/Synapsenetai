#include "quantum/quantum_security.h"
#include "crypto/crypto.h"
#include <mutex>
#include <random>
#include <cstring>
#include <algorithm>

namespace synapse {
namespace quantum {

namespace {
std::array<uint8_t, 64> deriveClassicSignatureMaterial(const std::vector<uint8_t>& message,
                                                       const std::array<uint8_t, 32>& publicTag) {
    std::array<uint8_t, 64> out{};
    std::vector<uint8_t> seed(message.begin(), message.end());
    seed.insert(seed.end(), publicTag.begin(), publicTag.end());
    auto state = crypto::sha256(seed.data(), seed.size());

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

struct HybridSig::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    CryptoAlgorithm classicAlgo = CryptoAlgorithm::CLASSIC_ED25519;
    CryptoAlgorithm pqcAlgo = CryptoAlgorithm::LATTICE_DILITHIUM65;
    Dilithium dilithium;
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(rng());
        }
    }
};

HybridSig::HybridSig() : impl_(std::make_unique<Impl>()) {}
HybridSig::~HybridSig() = default;

HybridKeyPair HybridSig::generateKeyPair() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    HybridKeyPair kp;
    kp.classicAlgo = impl_->classicAlgo;
    kp.pqcAlgo = impl_->pqcAlgo;
    
    kp.classicSecretKey.resize(64);
    kp.classicPublicKey.resize(32);
    impl_->fillRandom(kp.classicSecretKey.data(), 64);
    
    auto hash = crypto::sha256(kp.classicSecretKey.data(), 32);
    std::memcpy(kp.classicPublicKey.data(), hash.data(), 32);
    
    auto dilithiumKp = impl_->dilithium.generateKeyPair();
    kp.pqcPublicKey.assign(dilithiumKp.publicKey.begin(), dilithiumKp.publicKey.end());
    kp.pqcSecretKey.assign(dilithiumKp.secretKey.begin(), dilithiumKp.secretKey.end());
    
    return kp;
}

SignatureResult HybridSig::sign(const std::vector<uint8_t>& message,
                                 const HybridKeyPair& secretKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    SignatureResult result;
    result.success = false;
    if (secretKey.classicSecretKey.size() < 32 || secretKey.pqcSecretKey.empty()) {
        return result;
    }

    auto classicPubHash = crypto::sha256(secretKey.classicSecretKey.data(), 32);
    std::array<uint8_t, 32> classicPublicTag{};
    std::memcpy(classicPublicTag.data(), classicPubHash.data(), classicPublicTag.size());
    auto classicSig = deriveClassicSignatureMaterial(message, classicPublicTag);
    
    DilithiumSecretKey dilithiumSk{};
    size_t copyLen = std::min(secretKey.pqcSecretKey.size(), dilithiumSk.size());
    std::memcpy(dilithiumSk.data(), secretKey.pqcSecretKey.data(), copyLen);
    
    auto pqcResult = impl_->dilithium.sign(message, dilithiumSk);
    if (!pqcResult.success) {
        return result;
    }
    
    result.signature.assign(classicSig.begin(), classicSig.end());
    result.signature.insert(result.signature.end(), 
                            pqcResult.signature.begin(), 
                            pqcResult.signature.end());
    result.success = true;
    return result;
}

bool HybridSig::verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& signature,
                       const HybridKeyPair& publicKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (signature.size() != 64 + DILITHIUM_SIGNATURE_SIZE) {
        return false;
    }
    if (publicKey.classicPublicKey.size() < 32 || publicKey.pqcPublicKey.size() < DILITHIUM_PUBLIC_KEY_SIZE) {
        return false;
    }

    std::array<uint8_t, 32> classicPublicTag{};
    std::memcpy(classicPublicTag.data(), publicKey.classicPublicKey.data(), classicPublicTag.size());
    auto expectedClassic = deriveClassicSignatureMaterial(message, classicPublicTag);
    for (size_t i = 0; i < expectedClassic.size(); i++) {
        if (signature[i] != expectedClassic[i]) {
            return false;
        }
    }
    
    DilithiumSignature dilithiumSig{};
    std::memcpy(dilithiumSig.data(), signature.data() + 64, DILITHIUM_SIGNATURE_SIZE);
    
    DilithiumPublicKey dilithiumPk{};
    size_t copyLen = std::min(publicKey.pqcPublicKey.size(), dilithiumPk.size());
    std::memcpy(dilithiumPk.data(), publicKey.pqcPublicKey.data(), copyLen);
    
    return impl_->dilithium.verify(message, dilithiumSig, dilithiumPk);
}

void HybridSig::setClassicAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->classicAlgo = algo;
}

void HybridSig::setPQCAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->pqcAlgo = algo;
}

}
}
