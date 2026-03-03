#ifndef SYNAPSE_CORE_WALLET_H
#define SYNAPSE_CORE_WALLET_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace synapse {
namespace core {

class Wallet {
public:
    Wallet();
    ~Wallet();
    
    bool create();
    bool restore(const std::vector<std::string>& seedWords);
    bool load(const std::string& path, const std::string& password);
    bool save(const std::string& path, const std::string& password);
    
    void lock();
    bool unlock(const std::string& password);
    bool isLocked() const;
    
    std::vector<std::string> getSeedWords() const;
    std::string getAddress() const;
    std::vector<uint8_t> getPublicKey() const;
    
    double getBalance() const;
    double getPendingBalance() const;
    double getStakedBalance() const;
    
    void setBalance(double balance);
    void setPendingBalance(double pending);
    void setStakedBalance(double staked);
    
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const;
    static bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& publicKey);
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
}

#endif
