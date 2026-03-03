#include "quantum/quantum_security.h"
#include "crypto/crypto.h"
#include <mutex>
#include <random>
#include <fstream>
#include <cstring>
#include <ctime>

namespace synapse {
namespace quantum {

struct HWRNG::Impl {
    mutable std::mutex mtx;
    std::mt19937_64 rng;
    bool initialized = false;
    bool hasRdrand = false;
    bool hasRdseed = false;
    bool hasTpm = false;
    bool useFallback = true;
    bool mixEntropy = true;
    RNGStats stats{};
    
    Impl() : rng(std::random_device{}()) {}
    
    void fillRandom(uint8_t* buf, size_t len);
    bool readDevRandom(uint8_t* buf, size_t len);
    void mixWithHash(uint8_t* buf, size_t len);
};

void HWRNG::Impl::fillRandom(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<uint8_t>(rng());
    }
    stats.bytesGenerated += len;
}

bool HWRNG::Impl::readDevRandom(uint8_t* buf, size_t len) {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.is_open()) return false;
    
    urandom.read(reinterpret_cast<char*>(buf), len);
    bool success = urandom.good();
    
    if (success) {
        stats.devRandomCalls++;
    }
    
    return success;
}

void HWRNG::Impl::mixWithHash(uint8_t* buf, size_t len) {
    if (!mixEntropy || len == 0) return;

    std::vector<uint8_t> temp(len);
    if (!readDevRandom(temp.data(), len)) {
        // Could not mix with fresh entropy; leave buffer unchanged
        return;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= temp[i];
    }
}

HWRNG::HWRNG() : impl_(std::make_unique<Impl>()) {}
HWRNG::~HWRNG() = default;

bool HWRNG::init() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    impl_->initialized = true;
    impl_->stats = RNGStats{};
    
    uint8_t test[32];
    impl_->hasRdrand = false;
    impl_->hasRdseed = false;
    impl_->hasTpm = false;
    
    if (impl_->readDevRandom(test, 32)) {
        impl_->stats.hardwareAvailable = true;
    }
    
    return true;
}

bool HWRNG::isAvailable() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->initialized;
}

std::vector<uint8_t> HWRNG::generate(size_t length) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    std::vector<uint8_t> result(length);
    
    if (impl_->useFallback) {
        if (!impl_->readDevRandom(result.data(), length)) {
            impl_->fillRandom(result.data(), length);
        }
    } else {
        impl_->fillRandom(result.data(), length);
    }
    
    if (impl_->mixEntropy) {
        impl_->mixWithHash(result.data(), length);
    }
    
    return result;
}

void HWRNG::fill(uint8_t* buffer, size_t length) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    
    if (impl_->useFallback) {
        if (!impl_->readDevRandom(buffer, length)) {
            impl_->fillRandom(buffer, length);
        }
    } else {
        impl_->fillRandom(buffer, length);
    }
    
    if (impl_->mixEntropy) {
        impl_->mixWithHash(buffer, length);
    }
}

bool HWRNG::hasRDRAND() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->hasRdrand;
}

bool HWRNG::hasRDSEED() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->hasRdseed;
}

bool HWRNG::hasTPM() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->hasTpm;
}

void HWRNG::setFallbackToDevRandom(bool enable) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->useFallback = enable;
}

void HWRNG::setEntropyMixing(bool enable) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->mixEntropy = enable;
}

HWRNG::RNGStats HWRNG::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->stats;
}

}
}
