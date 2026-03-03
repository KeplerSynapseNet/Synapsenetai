#include "quantum/quantum_security.h"
#include "crypto/crypto.h"
#include <mutex>
#include <random>
#include <cstring>

namespace synapse {
namespace quantum {

struct HybridKEM::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    CryptoAlgorithm classicAlgo = CryptoAlgorithm::CLASSIC_X25519;
    CryptoAlgorithm pqcAlgo = CryptoAlgorithm::LATTICE_KYBER768;
    Kyber kyber;
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(rng());
        }
    }
};

HybridKEM::HybridKEM() : impl_(std::make_unique<Impl>()) {}
HybridKEM::~HybridKEM() = default;

HybridKeyPair HybridKEM::generateKeyPair() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    HybridKeyPair kp;
    kp.classicAlgo = impl_->classicAlgo;
    kp.pqcAlgo = impl_->pqcAlgo;
    
    kp.classicSecretKey.resize(32);
    kp.classicPublicKey.resize(32);
    impl_->fillRandom(kp.classicSecretKey.data(), 32);
    
    auto hash = crypto::sha256(kp.classicSecretKey.data(), 32);
    std::memcpy(kp.classicPublicKey.data(), hash.data(), 32);
    
    auto kyberKp = impl_->kyber.generateKeyPair();
    kp.pqcPublicKey.assign(kyberKp.publicKey.begin(), kyberKp.publicKey.end());
    kp.pqcSecretKey.assign(kyberKp.secretKey.begin(), kyberKp.secretKey.end());
    
    return kp;
}

EncapsulationResult HybridKEM::encapsulate(const HybridKeyPair& recipientPublicKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    EncapsulationResult result;
    result.success = true;
    
    std::vector<uint8_t> classicSecret(32);
    impl_->fillRandom(classicSecret.data(), 32);
    
    KyberPublicKey kyberPk{};
    size_t copyLen = std::min(recipientPublicKey.pqcPublicKey.size(), kyberPk.size());
    std::memcpy(kyberPk.data(), recipientPublicKey.pqcPublicKey.data(), copyLen);
    
    auto kyberResult = impl_->kyber.encapsulate(kyberPk);
    
    result.ciphertext = classicSecret;
    result.ciphertext.insert(result.ciphertext.end(), 
                             kyberResult.ciphertext.begin(), 
                             kyberResult.ciphertext.end());
    
    result.sharedSecret = combineSharedSecrets(classicSecret, kyberResult.sharedSecret);
    
    return result;
}

std::vector<uint8_t> HybridKEM::decapsulate(const std::vector<uint8_t>& ciphertext,
                                             const HybridKeyPair& secretKey) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (ciphertext.size() < 32 + KYBER_CIPHERTEXT_SIZE) {
        return {};
    }
    
    std::vector<uint8_t> classicSecret(ciphertext.begin(), ciphertext.begin() + 32);
    
    KyberCiphertext kyberCt{};
    std::memcpy(kyberCt.data(), ciphertext.data() + 32, KYBER_CIPHERTEXT_SIZE);
    
    KyberSecretKey kyberSk{};
    size_t copyLen = std::min(secretKey.pqcSecretKey.size(), kyberSk.size());
    std::memcpy(kyberSk.data(), secretKey.pqcSecretKey.data(), copyLen);
    
    auto pqcSecret = impl_->kyber.decapsulate(kyberCt, kyberSk);
    
    return combineSharedSecrets(classicSecret, pqcSecret);
}

void HybridKEM::setClassicAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->classicAlgo = algo;
}

void HybridKEM::setPQCAlgorithm(CryptoAlgorithm algo) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->pqcAlgo = algo;
}

std::vector<uint8_t> HybridKEM::combineSharedSecrets(const std::vector<uint8_t>& classicSecret,
                                                      const std::vector<uint8_t>& pqcSecret) {
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), classicSecret.begin(), classicSecret.end());
    combined.insert(combined.end(), pqcSecret.begin(), pqcSecret.end());
    
    auto hash = crypto::sha256(combined.data(), combined.size());
    return std::vector<uint8_t>(hash.begin(), hash.end());
}

}
}
