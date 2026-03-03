#include "privacy/privacy.h"
#include "crypto/crypto.h"
#include <mutex>
#include <map>
#include <random>
#include <cstring>
#include <algorithm>

namespace synapse {
namespace privacy {

struct SessionCrypto::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    std::map<std::string, std::vector<uint8_t>> sessionKeys;
    std::map<std::string, uint64_t> sessionCounters;
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(rng());
        }
    }
    
    std::vector<uint8_t> keystream(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& nonce,
                                   size_t len) {
        std::vector<uint8_t> stream;
        stream.reserve(len);
        uint64_t counter = 0;
        while (stream.size() < len) {
            std::vector<uint8_t> input;
            input.reserve(key.size() + nonce.size() + 8);
            input.insert(input.end(), key.begin(), key.end());
            input.insert(input.end(), nonce.begin(), nonce.end());
            for (int i = 0; i < 8; i++) {
                input.push_back(static_cast<uint8_t>((counter >> (i * 8)) & 0xff));
            }
            auto hash = crypto::sha256(input.data(), input.size());
            size_t remain = len - stream.size();
            size_t take = std::min(remain, hash.size());
            stream.insert(stream.end(), hash.begin(), hash.begin() + take);
            counter++;
        }
        return stream;
    }
};

SessionCrypto::SessionCrypto() : impl_(std::make_unique<Impl>()) {}
SessionCrypto::~SessionCrypto() { clearAllSessions(); }

bool SessionCrypto::createSession(const std::string& sessionId, 
                                   const std::vector<uint8_t>& sharedSecret) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto hash = crypto::sha256(sharedSecret.data(), sharedSecret.size());
    impl_->sessionKeys[sessionId] = std::vector<uint8_t>(hash.begin(), hash.end());
    impl_->sessionCounters[sessionId] = 0;
    
    return true;
}

bool SessionCrypto::destroySession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto it = impl_->sessionKeys.find(sessionId);
    if (it != impl_->sessionKeys.end()) {
        volatile uint8_t* ptr = it->second.data();
        for (size_t i = 0; i < it->second.size(); i++) {
            ptr[i] = 0;
        }
        impl_->sessionKeys.erase(it);
        impl_->sessionCounters.erase(sessionId);
        return true;
    }
    return false;
}

void SessionCrypto::clearAllSessions() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    for (auto& [id, key] : impl_->sessionKeys) {
        volatile uint8_t* ptr = key.data();
        for (size_t i = 0; i < key.size(); i++) {
            ptr[i] = 0;
        }
    }
    impl_->sessionKeys.clear();
    impl_->sessionCounters.clear();
}

std::vector<uint8_t> SessionCrypto::encrypt(const std::string& sessionId, 
                                             const std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto keyIt = impl_->sessionKeys.find(sessionId);
    if (keyIt == impl_->sessionKeys.end()) return {};
    
    std::vector<uint8_t> nonce(12);
    uint64_t counter = impl_->sessionCounters[sessionId]++;
    std::memcpy(nonce.data(), &counter, 8);
    impl_->fillRandom(nonce.data() + 8, 4);
    
    auto stream = impl_->keystream(keyIt->second, nonce, plaintext.size());
    std::vector<uint8_t> ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] = plaintext[i] ^ stream[i];
    }
    
    std::vector<uint8_t> macInput;
    macInput.reserve(nonce.size() + ciphertext.size());
    macInput.insert(macInput.end(), nonce.begin(), nonce.end());
    macInput.insert(macInput.end(), ciphertext.begin(), ciphertext.end());
    auto mac = crypto::hmacSha256(keyIt->second, macInput);
    
    std::vector<uint8_t> out;
    out.reserve(nonce.size() + mac.size() + ciphertext.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), mac.begin(), mac.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

std::vector<uint8_t> SessionCrypto::decrypt(const std::string& sessionId, 
                                             const std::vector<uint8_t>& ciphertext) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto keyIt = impl_->sessionKeys.find(sessionId);
    if (keyIt == impl_->sessionKeys.end() || ciphertext.size() < 12 + 32) return {};
    
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 12);
    std::vector<uint8_t> mac(ciphertext.begin() + 12, ciphertext.begin() + 44);
    std::vector<uint8_t> enc(ciphertext.begin() + 44, ciphertext.end());
    
    std::vector<uint8_t> macInput;
    macInput.reserve(nonce.size() + enc.size());
    macInput.insert(macInput.end(), nonce.begin(), nonce.end());
    macInput.insert(macInput.end(), enc.begin(), enc.end());
    auto expected = crypto::hmacSha256(keyIt->second, macInput);
    
    if (!crypto::constantTimeCompare(mac.data(), expected.data(), expected.size())) {
        return {};
    }
    
    auto stream = impl_->keystream(keyIt->second, nonce, enc.size());
    std::vector<uint8_t> plaintext(enc.size());
    for (size_t i = 0; i < enc.size(); i++) {
        plaintext[i] = enc[i] ^ stream[i];
    }
    
    return plaintext;
}

bool SessionCrypto::hasSession(const std::string& sessionId) const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->sessionKeys.find(sessionId) != impl_->sessionKeys.end();
}

bool SessionCrypto::rotateKey(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    auto it = impl_->sessionKeys.find(sessionId);
    if (it == impl_->sessionKeys.end()) return false;
    
    auto hash = crypto::sha256(it->second.data(), it->second.size());
    it->second = std::vector<uint8_t>(hash.begin(), hash.end());
    impl_->sessionCounters[sessionId] = 0;
    
    return true;
}

}
}
