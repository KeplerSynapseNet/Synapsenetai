#include "quantum/wallet_security.h"
#include "crypto/crypto.h"
#include <array>
#include <algorithm>

namespace synapse {
namespace quantum {

static std::array<uint8_t, crypto::AES_KEY_SIZE> toAesKey(const std::vector<uint8_t>& key) {
    std::array<uint8_t, crypto::AES_KEY_SIZE> out{};
    if (key.size() >= out.size()) {
        std::copy_n(key.begin(), out.size(), out.begin());
        return out;
    }
    auto hash = crypto::sha256(key.data(), key.size());
    std::copy_n(hash.begin(), out.size(), out.begin());
    return out;
}

WalletSecurity::WalletSecurity() = default;

void WalletSecurity::setSecurityLevel(SecurityLevel level) {
    level_ = level;
}

SecurityLevel WalletSecurity::getSecurityLevel() const {
    return level_;
}

std::vector<uint8_t> WalletSecurity::encryptSeed(const std::vector<uint8_t>& seed,
                                                 const std::vector<uint8_t>& key) const {
    if (seed.empty()) return {};
    return crypto::encryptAES(seed, toAesKey(key));
}

std::vector<uint8_t> WalletSecurity::decryptSeed(const std::vector<uint8_t>& data,
                                                 const std::vector<uint8_t>& key) const {
    if (data.empty()) return {};
    return crypto::decryptAES(data, toAesKey(key));
}

std::vector<uint8_t> WalletSecurity::wrapKey(const std::vector<uint8_t>& privateKey,
                                             const std::vector<uint8_t>& wrappingKey) const {
    if (privateKey.empty()) return {};
    return crypto::encryptAES(privateKey, toAesKey(wrappingKey));
}

std::vector<uint8_t> WalletSecurity::unwrapKey(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& wrappingKey) const {
    if (data.empty()) return {};
    return crypto::decryptAES(data, toAesKey(wrappingKey));
}

}
}
