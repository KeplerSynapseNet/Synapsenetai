#pragma once

#include "crypto.h"
#include <string>
#include <vector>

namespace synapse {
namespace crypto {

constexpr uint8_t ADDRESS_VERSION_MAINNET = 0x00;
constexpr uint8_t ADDRESS_VERSION_TESTNET = 0x6F;
constexpr uint8_t ADDRESS_VERSION_P2SH = 0x05;
constexpr const char* ADDRESS_PREFIX = "syn1";

enum class AddressType {
    UNKNOWN,
    P2PKH,
    P2SH,
    BECH32,
    BECH32M
};

class Address {
public:
    static std::string fromPublicKey(const PublicKey& publicKey);
    static std::string fromHash160(const Hash256& hash160);
    static bool isValid(const std::string& address);
    static Hash256 toHash160(const std::string& address);
    
    static std::vector<uint8_t> decode(const std::string& address);
    static std::string encode(const std::vector<uint8_t>& data);
    static AddressType getType(const std::string& address);
    
    static std::string fromScript(const std::vector<uint8_t>& script);
    static std::vector<uint8_t> toScript(const std::string& address);
    
    static std::string createMultisig(uint8_t required, const std::vector<PublicKey>& pubkeys);
    static bool verifyChecksum(const std::string& address);
    
    static std::string toSegwit(const std::string& address);
    static std::string fromSegwit(const std::string& segwitAddr);
    
    static std::string encodeBase58Check(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> decodeBase58Check(const std::string& encoded);
    
    static std::string encodeBech32(const std::string& hrp, const std::vector<uint8_t>& data);
    static std::vector<uint8_t> decodeBech32(const std::string& encoded, std::string& hrp);

private:
    static std::string base58Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base58Decode(const std::string& encoded);
};

}
}
