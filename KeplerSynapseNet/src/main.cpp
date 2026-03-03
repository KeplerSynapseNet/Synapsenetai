#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <ctime>
#include <vector>
#include <array>
#include <deque>
#include <memory>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <condition_variable>
#include <random>
#include <filesystem>
#include <algorithm>
#include <utility>
#include <cmath>
#include <stdexcept>
#include <limits>
#include <optional>
#include <cctype>
#include <cerrno>
#include <regex>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/time.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <signal.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "core/ledger.h"
#include "core/knowledge.h"
#include "core/transfer.h"
#include "core/consensus.h"
#include "core/poe_v1_engine.h"
#include "core/update_bundle.h"
#include "core/update_installer.h"
#include "core/implant_compatibility.h"
#include "core/implant_safety_pipeline.h"
#include "core/agent_coordination.h"
#include "core/agent_draft_queue.h"
#include "core/agent_submission_pipeline.h"
#include "core/agent_score.h"
#include "core/agent_storage.h"
#include "core/agent_runtime.h"
#include "core/agent_scheduler.h"
#include "core/tor_process_guard.h"
#include "core/tor_bridge_provider.h"
#include "core/tor_bridge_utils.h"
#include "core/tor_route_policy.h"
#if SYNAPSE_BUILD_TUI
#include "tui/tui.h"
#endif
#include "network/network.h"
#include "network/discovery.h"
#include "model/model_loader.h"
#include "model/model_access.h"
#include "crypto/crypto.h"
#include "crypto/keys.h"
#include "database/database.h"
#include "utils/logger.h"
#include "utils/config.h"
#include "utils/single_instance.h"
#include "utils/utils.h"
#include "privacy/privacy.h"
#include "python/sandbox.h"
#include "quantum/quantum_security.h"
#include "infrastructure/messages.h"
#include "web/rpc_server.h"
#include "web/curl_fetch.h"
#include "web/web.h"
#include "../third_party/llama.cpp/vendor/nlohmann/json.hpp"

namespace synapse {

using json = nlohmann::json;

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_reloadConfig{false};
static std::atomic<bool> g_daemonMode{false};

// Forward declarations
std::string formatUptime(uint64_t seconds);

struct NodeConfig {
    std::string dataDir;
    std::string configPath;
    std::string networkType = "mainnet";
    std::string logLevel = "info";
    std::string bindAddress = "0.0.0.0";
    uint16_t port = 8333;
    uint16_t rpcPort = 8332;
    uint32_t maxPeers = 125;
    uint32_t maxConnections = 125;
    uint32_t maxInbound = 100;
    uint32_t maxOutbound = 25;
    bool networkAdaptiveAdmission = true;
    bool networkDeterministicEviction = true;
    uint32_t networkMaxPeersPerIp = 8;
    uint32_t networkMaxPeersPerSubnet = 32;
    uint32_t networkSubnetPrefixBits = 24;
    bool networkTokenBucketEnabled = true;
    uint32_t networkTokenBucketBytesPerSecond = static_cast<uint32_t>(network::MAX_MESSAGE_SIZE * 2);
    uint32_t networkTokenBucketBytesBurst = static_cast<uint32_t>(network::MAX_MESSAGE_SIZE * 4);
    uint32_t networkTokenBucketMessagesPerSecond = 500;
    uint32_t networkTokenBucketMessagesBurst = 1000;
    uint32_t networkMalformedPenalty = 20;
    uint32_t networkRatePenalty = 10;
    uint32_t networkPenaltyHalfLifeSeconds = 900;
    uint32_t networkBaseBanSeconds = 120;
    uint32_t networkMaxBanSeconds = 3600;
    bool networkOverloadMode = true;
    uint32_t networkOverloadEnterPeerPercent = 90;
    uint32_t networkOverloadExitPeerPercent = 70;
    uint64_t networkOverloadEnterBufferedRxBytes = network::MAX_MESSAGE_SIZE * 32;
    uint64_t networkOverloadExitBufferedRxBytes = network::MAX_MESSAGE_SIZE * 16;
    uint32_t networkInvMaxItems = 256;
    uint32_t networkInvOverloadItems = 32;
    uint32_t networkGetDataMaxItems = 128;
    uint32_t networkGetDataOverloadItems = 32;
    uint32_t networkGossipFanoutLimit = 64;
    uint32_t networkGossipDedupWindowSeconds = 5;
    uint32_t networkVoteDedupWindowSeconds = 600;
    uint32_t networkVoteDedupMaxEntries = 20000;
    uint32_t dbCacheSize = 450;
    uint32_t maxMempool = 300;
    bool daemon = false;
    bool tui = true;
    bool amnesia = false;
    bool testnet = false;
    bool regtest = false;
    bool discovery = true;
    bool showVersion = false;
    bool showHelp = false;
    bool privacyMode = false;
    bool quantumSecurity = false;
    bool resetNgt = false;
    bool dev = false;
    std::string poeValidators;
    std::string poeValidatorMode = "static"; // static|stake
    std::string poeMinStake = "0";           // NGT (decimal), used when poeValidatorMode == "stake"
    bool cli = false;
    std::string securityLevel = "standard";
    bool securityLevelSetByCli = false;
    bool quantumSecuritySetByCli = false;
    std::vector<std::string> connectNodes;
    std::vector<std::string> addNodes;
    std::vector<std::string> seedNodes;
    std::vector<std::string> commandArgs;
};

struct NodeStats {
    uint64_t uptime = 0;
    uint64_t peersConnected = 0;
    uint64_t peersInbound = 0;
    uint64_t peersOutbound = 0;
    uint64_t knowledgeEntries = 0;
    uint64_t transactionsProcessed = 0;
    uint64_t blocksValidated = 0;
    uint64_t modelRequests = 0;
    uint64_t bytesReceived = 0;
    uint64_t bytesSent = 0;
    double syncProgress = 0.0;
    double cpuUsage = 0.0;
    uint64_t memoryUsage = 0;
    uint64_t diskUsage = 0;
};

struct SystemInfo {
    std::string osName;
    std::string osVersion;
    std::string architecture;
    uint32_t cpuCores;
    uint64_t totalMemory;
    uint64_t availableMemory;
    uint64_t totalDisk;
    uint64_t availableDisk;
};

class SynapseNet {
public:
    SynapseNet() : running_(false), startTime_(0), syncProgress_(0.0) {}
    ~SynapseNet() { shutdown(); }
    
    bool initialize(const NodeConfig& config) {
        config_ = config;
        for (char& c : config_.poeValidatorMode) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (config_.poeValidatorMode != "stake") config_.poeValidatorMode = "static";
        if (config_.poeMinStake.empty()) config_.poeMinStake = "0";
        utils::Config::instance().setDataDir(config_.dataDir);
        
	        utils::Logger::init(config_.dataDir + "/synapsenet.log");
	        utils::Logger::enableConsole(!config_.tui);
	        setLogLevel(config_.logLevel);
	        utils::Logger::info("SynapseNet v0.1.0 starting...");
	        utils::Logger::info("Data directory: " + config_.dataDir);
        
        if (!config_.tui) std::cout << "Loading configuration..." << std::endl;
        if (!loadConfiguration()) {
            utils::Logger::error("Failed to load configuration");
            return false;
        }
        
        if (!config_.tui) std::cout << "Initializing database..." << std::endl;
        if (!initDatabase()) return false;
        
        if (!config_.tui) std::cout << "Initializing crypto..." << std::endl;
        if (!initCrypto()) return false;
        
        if (!config_.tui) std::cout << "Initializing quantum security..." << std::endl;
        if (!initQuantumSecurity()) return false;

        if (!config_.cli) {
            if (!config_.tui) std::cout << "Initializing network..." << std::endl;
            if (!initNetwork()) return false;
        }
        
	        if (!config_.tui) std::cout << "Initializing core..." << std::endl;
	        if (!initCore()) return false;

	        bool needsModel = !config_.cli;
	        if (config_.cli && !config_.commandArgs.empty()) {
	            const std::string cmd = config_.commandArgs[0];
	            needsModel = (cmd == "model" || cmd == "ai");
	        }

	        if (needsModel) {
	            if (!config_.tui) std::cout << "Initializing model..." << std::endl;
	            if (!initModel()) return false;
	        }

	        if (!config_.cli) {
	            if (!config_.tui) std::cout << "Initializing privacy..." << std::endl;
	            if (!initPrivacy()) return false;

	            if (!config_.tui) std::cout << "Initializing RPC..." << std::endl;
            if (!initRPC()) return false;

            if (!config_.tui) std::cout << "Initializing mempool..." << std::endl;
            if (!initMempool()) return false;
        }
        
        utils::Logger::info("All subsystems initialized successfully");
        if (!config_.tui) std::cout << "Initialization complete!" << std::endl;
        return true;
    }

	private:
	    enum class PoeInvKind : uint8_t { ENTRY = 1, VOTE = 2, EPOCH = 3 };
	    struct PoeSyncState {
	        bool active = false;
	        bool done = false;
	        bool inFlight = false;
	        crypto::Hash256 after{};
	        uint32_t limit = 0;
	        uint64_t lastRequestAt = 0;
	        uint64_t pages = 0;
	    };
	    struct PoePeerSyncState {
	        PoeSyncState entries;
	        PoeSyncState votes;
	        PoeSyncState epochs;
	    };

        // Remote model routing (opt-in)
        struct RemoteOfferCache {
            synapse::RemoteModelOfferMessage offer;
            std::string peerId;
            uint64_t receivedAt = 0;
        };

        struct RemoteSessionInfo {
            std::string peerId;
            std::string sessionId;
            std::string providerAddress;
            uint64_t pricePerRequestAtoms = 0;
            uint64_t expiresAt = 0;
        };

        struct RemotePending {
            bool done = false;
            std::string text;
            uint32_t tokensUsed = 0;
            uint64_t latencyMs = 0;
        };

        struct ProviderSession {
            std::string renterId;
            uint64_t expiresAt = 0;
            uint64_t pricePerRequestAtoms = 0;
        };

        enum class UpdateManifestAccept {
            ACCEPTED,
            DUPLICATE,
            REJECTED
        };

        struct NaanAbuseClassifierPolicy {
            uint32_t spamRejectThreshold = 3;
            uint32_t spamViolationSteps = 1;
            uint32_t invalidCitationViolationSteps = 1;
            uint32_t policyViolationSteps = 1;
        };

        struct NaanAbuseClassification {
            uint32_t spamViolations = 0;
            uint32_t invalidCitationViolations = 0;
            uint32_t policyViolations = 0;
        };

        struct NaanUiEvent {
            uint64_t timestamp = 0;
            std::string category;
            std::string message;
        };

	    json parseRpcParams(const std::string& paramsJson) const {
	    if (paramsJson.empty()) {
	        return json::object();
	    }
    json parsed = json::parse(paramsJson, nullptr, false);
    if (parsed.is_discarded()) {
        throw std::runtime_error("Invalid JSON params");
    }
    if (parsed.is_array()) {
        if (parsed.empty()) return json::object();
        if (!parsed.front().is_object()) {
            throw std::runtime_error("Expected object params");
        }
        return parsed.front();
    }
    if (!parsed.is_object()) {
        throw std::runtime_error("Expected object params");
    }
    return parsed;
}

crypto::Hash256 parseHash256Hex(const std::string& hex) const {
    crypto::Hash256 out{};
    auto bytes = crypto::fromHex(hex);
    if (bytes.size() != out.size()) {
        throw std::runtime_error("Expected 32-byte hex string");
    }
    std::memcpy(out.data(), bytes.data(), out.size());
    return out;
}

json updateManifestToJson(const core::UpdateManifest& manifest, bool includeChunks = true) const {
    json out;
    out["version"] = manifest.version;
    out["bundleId"] = crypto::toHex(manifest.bundleId);
    out["contentHash"] = crypto::toHex(manifest.contentHash);
    out["target"] = manifest.target;
    out["protocolMin"] = manifest.protocolMin;
    out["protocolMax"] = manifest.protocolMax;
    out["signer"] = crypto::toHex(manifest.signer);
    out["signature"] = crypto::toHex(manifest.signature);
    out["chunkCount"] = manifest.chunks.size();
    if (includeChunks) {
        json chunks = json::array();
        for (const auto& c : manifest.chunks) {
            json item;
            item["hash"] = crypto::toHex(c.hash);
            item["size"] = c.size;
            chunks.push_back(item);
        }
        out["chunks"] = chunks;
    }
    return out;
}

json updateInstallerStateToJson(const core::UpdateInstallerState& state) const {
    json out;
    out["activeSlot"] = std::string(1, state.activeSlot);
    out["hasSlotABundle"] = state.hasSlotABundle;
    out["slotABundle"] = state.hasSlotABundle ? crypto::toHex(state.slotABundle) : "";
    out["hasSlotBBundle"] = state.hasSlotBBundle;
    out["slotBBundle"] = state.hasSlotBBundle ? crypto::toHex(state.slotBBundle) : "";
    out["hasPending"] = state.hasPending;
    out["pendingSlot"] = state.hasPending ? std::string(1, state.pendingSlot) : "";
    out["pendingBundle"] = state.hasPending ? crypto::toHex(state.pendingBundle) : "";
    out["pendingStage"] = state.hasPending ? core::toString(state.pendingStage) : "";
    out["hasLastKnownGood"] = state.hasLastKnownGood;
    out["lastKnownGood"] = state.hasLastKnownGood ? crypto::toHex(state.lastKnownGood) : "";
    return out;
}

json implantSafetyRecordToJson(const core::ImplantSafetyRecord& record) const {
    json out;
    out["deterministicTestsPassed"] = record.deterministicTestsPassed;
    out["sandboxBoundariesPassed"] = record.sandboxBoundariesPassed;
    out["canaryHealthPassed"] = record.canaryHealthPassed;
    out["wideHealthPassed"] = record.wideHealthPassed;
    out["updatedAt"] = record.updatedAt;
    return out;
}

bool parsePublicKeyHex(const std::string& hex, crypto::PublicKey& out) const {
    auto bytes = crypto::fromHex(hex);
    if (bytes.size() != out.size()) return false;
    std::memcpy(out.data(), bytes.data(), out.size());
    return true;
}

bool parseSignatureHex(const std::string& hex, crypto::Signature& out) const {
    auto bytes = crypto::fromHex(hex);
    if (bytes.size() != out.size()) return false;
    std::memcpy(out.data(), bytes.data(), out.size());
    return true;
}

bool canConnectTcp(const std::string& host, uint16_t port, uint32_t timeoutMs = 1200) const {
    if (host.empty() || port == 0) return false;

    struct addrinfo hints {};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    std::string portStr = std::to_string(port);
    struct addrinfo* results = nullptr;
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &results) != 0) {
        return false;
    }

    bool ok = false;
    for (struct addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        int rc = connect(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen));
        if (rc == 0) {
            ok = true;
            close(fd);
            break;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            continue;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv{};
        tv.tv_sec = static_cast<long>(timeoutMs / 1000);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
        int sel = select(fd + 1, nullptr, &wfds, nullptr, &tv);
        if (sel > 0 && FD_ISSET(fd, &wfds)) {
            int err = 0;
            socklen_t errLen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errLen) == 0 && err == 0) {
                ok = true;
                close(fd);
                break;
            }
        }
        close(fd);
    }

    freeaddrinfo(results);
    return ok;
}

std::string configuredTorSocksHost() const {
    auto& cfg = utils::Config::instance();
    std::string host = cfg.getString("tor.socks.host", "");
    if (host.empty()) host = cfg.getString("agent.tor.socks_host", "127.0.0.1");
    if (host.empty()) host = "127.0.0.1";
    return host;
}

uint16_t configuredTorSocksPort() const {
    auto& cfg = utils::Config::instance();
    int port = cfg.has("tor.socks.port")
        ? cfg.getInt("tor.socks.port", 9050)
        : cfg.getInt("agent.tor.socks_port", 9050);
    if (port <= 0 || port > 65535) port = 9050;
    return static_cast<uint16_t>(port);
}

uint16_t configuredTorControlPort() const {
    int port = utils::Config::instance().getInt("tor.control.port", 9051);
    if (port <= 0 || port > 65535) port = 9051;
    return static_cast<uint16_t>(port);
}

std::string configuredTorRuntimeMode() const {
    return core::normalizeTorRuntimeMode(utils::Config::instance().getString("agent.tor.mode", "auto"));
}

bool allowManagedTorAutostart() const {
    return core::isManagedTorAutostartAllowedForMode(configuredTorRuntimeMode());
}

std::filesystem::path managedTorDirPath() const {
    return std::filesystem::path(config_.dataDir) / "tor";
}

std::filesystem::path managedTorPidFilePath() const {
    return managedTorDirPath() / "tor.pid";
}

bool readManagedTorPidFile(int64_t* outPid = nullptr) const {
    std::ifstream in(managedTorPidFilePath());
    if (!in.is_open()) return false;
    int64_t pid = 0;
    in >> pid;
    if (!in || pid <= 0) return false;
    if (outPid) *outPid = pid;
    return true;
}

#ifndef _WIN32
std::string readCommandOutput(const std::string& cmd, size_t maxBytes = 8192) const {
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return {};
    std::string out;
    out.reserve(512);
    char buf[512];
    while (!feof(fp) && out.size() < maxBytes) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0) break;
        const size_t take = std::min(n, maxBytes - out.size());
        out.append(buf, take);
    }
    (void)pclose(fp);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ' || out.back() == '\t')) {
        out.pop_back();
    }
    return out;
}

bool managedTorProcessMatchesOwnership(int64_t pid) const {
    if (pid <= 0) return false;
    const std::string torDir = managedTorDirPath().string();
    std::ostringstream cmd;
    cmd << "ps -ww -p " << pid << " -o command= 2>/dev/null";
    const std::string line = readCommandOutput(cmd.str(), 16384);
    return core::isOwnedManagedTorCommandLine(line, torDir);
}

std::vector<int64_t> findOwnedManagedTorPidsByDataDir() const {
    const std::string torDir = managedTorDirPath().string();
    const std::string out = readCommandOutput("ps -axww -o pid= -o command= 2>/dev/null", 262144);
    return core::parseOwnedManagedTorPidsFromPsOutput(out, torDir);
}

bool stopManagedTorPidAndWait(int64_t pid) {
    if (pid <= 0) return false;
    if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
        utils::Logger::warn("Managed Tor stop failed (SIGTERM): pid=" + std::to_string(pid) +
                            " errno=" + std::to_string(errno));
        return false;
    }

    bool exited = false;
    for (int i = 0; i < 20; ++i) {
        if (kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH) {
            exited = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!exited) {
        utils::Logger::warn("Managed Tor did not exit after SIGTERM (pid=" + std::to_string(pid) + ")");
        return false;
    }
    return true;
}

bool spawnManagedTorProcess(const std::string& torBin,
                            const std::string& socksHost,
                            uint16_t socksPort,
                            uint16_t controlPort,
                            const std::filesystem::path& torDir,
                            const std::filesystem::path& pidFile) {
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
            (void)dup2(nullfd, STDIN_FILENO);
            (void)dup2(nullfd, STDOUT_FILENO);
            (void)dup2(nullfd, STDERR_FILENO);
        }
        long maxFd = sysconf(_SC_OPEN_MAX);
        if (maxFd < 0) maxFd = 256;
        for (int fd = 3; fd < maxFd; ++fd) {
            if (fd == nullfd) continue;
            close(fd);
        }
        if (nullfd > 2) close(nullfd);

        const std::string socksSpec = socksHost + ":" + std::to_string(socksPort);
        const std::string controlSpec = std::string("127.0.0.1:") + std::to_string(controlPort);
        execlp(torBin.c_str(),
               torBin.c_str(),
               "--quiet",
               "--SocksPort", socksSpec.c_str(),
               "--ControlPort", controlSpec.c_str(),
               "--DataDirectory", torDir.string().c_str(),
               "--PidFile", pidFile.string().c_str(),
               "--RunAsDaemon", "1",
               static_cast<char*>(nullptr));
        _exit(127);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        return false;
    }
    if (!WIFEXITED(status)) return false;
    return WEXITSTATUS(status) == 0;
}

bool stopManagedTorRuntimeIfOwned(bool logOnNoop = false) {
    int64_t pid = managedTorPid_.load();
    bool hadPidCandidate = (pid > 0);
    if (pid <= 0) {
        (void)readManagedTorPidFile(&pid);
        hadPidCandidate = (pid > 0);
    }

    std::vector<int64_t> candidates;
    if (pid > 0 && managedTorProcessMatchesOwnership(pid)) {
        candidates.push_back(pid);
    } else {
        if (pid > 0 && logOnNoop) {
            utils::Logger::warn("Managed Tor stop pid ownership mismatch (" + std::to_string(pid) +
                                "); trying commandline/dataDir fallback scan");
        }
        candidates = findOwnedManagedTorPidsByDataDir();
    }

    if (candidates.empty()) {
        if (logOnNoop) {
            if (hadPidCandidate) utils::Logger::info("Managed Tor stop skipped: no owned runtime found");
            else utils::Logger::info("Managed Tor stop skipped: no pid file and no owned runtime found");
        }
        agentTorManaged_.store(false);
        managedTorPid_.store(0);
        return false;
    }

    bool allStopped = true;
    for (int64_t candidate : candidates) {
        if (!stopManagedTorPidAndWait(candidate)) {
            allStopped = false;
        }
    }
    if (!allStopped) {
        return false;
    }

    std::error_code ec;
    std::filesystem::remove(managedTorPidFilePath(), ec);
    agentTorManaged_.store(false);
    agentTorReachable_.store(false);
    agentTorWebReady_.store(false);
    agentTorWebProbeConsecutiveFailures_.store(0);
    agentTorWebProbeConsecutiveSuccesses_.store(0);
    resetManagedTorRestartBackoffState();
    managedTorPid_.store(0);
    if (candidates.size() == 1) {
        utils::Logger::info("Stopped managed Tor runtime (pid=" + std::to_string(candidates.front()) + ")");
    } else {
        utils::Logger::warn("Stopped multiple owned managed Tor runtimes matched by dataDir (" +
                           std::to_string(candidates.size()) + ")");
    }
    return true;
}
#else
bool stopManagedTorRuntimeIfOwned(bool /*logOnNoop*/ = false) { return false; }
#endif

bool probeTorSocks() const {
    return canConnectTcp(configuredTorSocksHost(), configuredTorSocksPort(), 700);
}

bool probeTorControl() const {
    return canConnectTcp("127.0.0.1", configuredTorControlPort(), 350);
}

bool isOnionServiceActive() const {
    return privacy_ && !privacy_->getOnionAddress().empty();
}

bool likelyTor9050vs9150ConflictHint(bool torSocksReachable) const {
    return core::evaluateTor9050vs9150ConflictHint(
        configuredTorRuntimeMode(),
        configuredTorSocksPort(),
        torSocksReachable,
        canConnectTcp("127.0.0.1", 9150, 120));
}

void setTorWebProbeLastError(const std::string& err) {
    std::lock_guard<std::mutex> lock(agentTorWebProbeMtx_);
    agentTorWebProbeLastError_ = err;
}

std::string getTorWebProbeLastError() const {
    std::lock_guard<std::mutex> lock(agentTorWebProbeMtx_);
    return agentTorWebProbeLastError_;
}

void setTorBridgeProviderMetaSnapshot(const json& meta) {
    std::lock_guard<std::mutex> lock(torBridgeProviderMetaMtx_);
    torBridgeProviderMeta_ = meta;
    torBridgeProviderMetaUpdatedAt_.store(static_cast<uint64_t>(std::time(nullptr)));
}

json getTorBridgeProviderMetaSnapshot() const {
    std::lock_guard<std::mutex> lock(torBridgeProviderMetaMtx_);
    return torBridgeProviderMeta_;
}

std::filesystem::path torLastKnownGoodBridgeSubsetPath() const {
    return managedTorDirPath() / "last_known_good_bridge_subset.json";
}

std::string torBridgeSubsetNodeIdHint() const {
    if (!address_.empty()) return address_;
    if (keys_ && keys_->isValid()) {
        const auto pub = keys_->getPublicKey();
        if (!pub.empty()) {
            return crypto::toHex(crypto::sha256(pub.data(), pub.size()));
        }
    }
    return crypto::toHex(crypto::sha256("tor_bridge_subset_node|" + config_.dataDir));
}

bool persistLastKnownGoodBridgeSubset(const std::string& trigger) {
    if (!agentTorWebReady_.load()) return false;

    const std::string naanWebCfgPath = config_.dataDir + "/naan_agent_web.conf";
    if (!std::filesystem::exists(naanWebCfgPath)) return false;

    web::SearchConfig cfg;
    (void)web::loadSearchConfig(config_.dataDir + "/web_search.conf", cfg);
    web::SearchConfigValidationStats validation{};
    (void)web::loadSearchConfigOverlay(naanWebCfgPath, cfg, &validation);
    web::sanitizeSearchConfig(cfg);
    const auto bridges = core::sanitizeAndDedupeObfs4BridgeLines(cfg.tor.bridgeManualLines);
    if (cfg.tor.bridgeTransport != "obfs4" || bridges.empty()) {
        return false;
    }

    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    auto& runtimeCfg = utils::Config::instance();
    const uint64_t epochWindowSec = static_cast<uint64_t>(std::max<int64_t>(
        60, runtimeCfg.getInt64("agent.tor.bridge_epoch_window_seconds", 86400)));
    const uint64_t epoch = now / epochWindowSec;
    const size_t desiredSubsetCount = static_cast<size_t>(std::max<uint32_t>(1, cfg.tor.bridgeMinPoolSize == 0 ? 2u : cfg.tor.bridgeMinPoolSize));
    auto subset = core::selectDeterministicObfs4BridgeSubset(
        bridges, torBridgeSubsetNodeIdHint(), epoch, desiredSubsetCount);
    if (subset.empty()) {
        const size_t take = std::min(bridges.size(), desiredSubsetCount);
        subset.assign(bridges.begin(), bridges.begin() + take);
    }
    if (subset.empty()) return false;

    json snapshot;
    snapshot["version"] = 1;
    snapshot["trigger"] = trigger;
    snapshot["savedAt"] = now;
    snapshot["epochWindowSeconds"] = epochWindowSec;
    snapshot["epoch"] = epoch;
    snapshot["runtimeMode"] = configuredTorRuntimeMode();
    snapshot["socksHost"] = configuredTorSocksHost();
    snapshot["socksPort"] = configuredTorSocksPort();
    snapshot["controlPort"] = configuredTorControlPort();
    snapshot["bridgeTransport"] = cfg.tor.bridgeTransport;
    snapshot["bridgeSource"] = cfg.tor.bridgeSource;
    snapshot["bridgePoolCount"] = bridges.size();
    snapshot["selectedCount"] = subset.size();
    snapshot["validationTotalLines"] = validation.totalLines;
    snapshot["validationInvalidLines"] = validation.invalidLines;
    snapshot["validationMalformedBridgeLines"] = validation.malformedBridgeLines;
    snapshot["nodeIdHash"] = crypto::toHex(crypto::sha256(torBridgeSubsetNodeIdHint()));
    snapshot["selectedBridges"] = subset;

    std::error_code ec;
    std::filesystem::create_directories(torLastKnownGoodBridgeSubsetPath().parent_path(), ec);
    std::ofstream out(torLastKnownGoodBridgeSubsetPath(), std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        utils::Logger::warn("Failed to persist last-known-good Tor bridge subset snapshot (open failed)");
        return false;
    }
    out << snapshot.dump(2) << "\n";
    out.close();
    if (!out) {
        utils::Logger::warn("Failed to persist last-known-good Tor bridge subset snapshot (write failed)");
        return false;
    }

    agentTorBridgeSubsetPersistCount_.fetch_add(1);
    agentTorBridgeSubsetLastPersistAt_.store(now);
    agentTorBridgeSubsetLastEpoch_.store(epoch);
    agentTorBridgeSubsetLastCount_.store(static_cast<uint32_t>(subset.size()));
    utils::Logger::info("Persisted last-known-good Tor bridge subset: count=" +
                       std::to_string(subset.size()) + " epoch=" + std::to_string(epoch) +
                       " trigger=" + trigger);
    return true;
}

void updateAndLogTorReadinessState(bool torRequired, bool torReachable, bool torReadyForWeb, bool torDegraded) {
    core::TorBootstrapStateInput in;
    in.torRequired = torRequired;
    in.torSocksReachable = torReachable;
    in.torWebReady = torReadyForWeb;
    in.torDegraded = torDegraded;

    const std::string webProbeError = getTorWebProbeLastError();
    const std::string state = core::evaluateTorBootstrapState(in);
    const std::string reason = core::evaluateTorBootstrapReasonCode(in, webProbeError);
    const uint32_t percent = core::evaluateTorBootstrapPercent(in);
    const bool onionReady = core::evaluateTorReadyForOnion(in);

    agentTorBootstrapPercent_.store(percent);
    agentTorOnionReady_.store(onionReady);

    std::string prevState;
    std::string prevReason;
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(agentTorReadinessMtx_);
        prevState = agentTorReadinessState_;
        prevReason = agentTorBootstrapReasonCode_;
        changed = (prevState != state) || (prevReason != reason);
        agentTorReadinessState_ = state;
        agentTorBootstrapReasonCode_ = reason;
    }
    if (!changed) return;

    const std::string detail =
        "state=" + state +
        " reason=" + reason +
        " percent=" + std::to_string(percent) +
        " socks=" + std::string(torReachable ? "yes" : "no") +
        " web=" + std::string(torReadyForWeb ? "yes" : "no") +
        " onion=" + std::string(onionReady ? "yes" : "no") +
        (webProbeError.empty() ? std::string() : (" webProbeError=" + webProbeError));

    if (prevState.empty() && prevReason.empty()) {
        utils::Logger::info("Tor readiness state initialized: " + detail);
    } else {
        utils::Logger::info("Tor readiness transition: " +
                            prevState + "/" + prevReason + " -> " +
                            state + "/" + reason + " (" + detail + ")");
    }

    if (torReadyForWeb && (state == "WEB_READY" || state == "WEB_READY_DEGRADED")) {
        (void)persistLastKnownGoodBridgeSubset("tor_readiness_transition");
    }
}

std::string getTorBootstrapReasonCodeCached() const {
    std::lock_guard<std::mutex> lock(agentTorReadinessMtx_);
    return agentTorBootstrapReasonCode_;
}

bool refreshTorWebReadiness(bool torSocksReachable, bool force = false) {
    if (!torSocksReachable) {
        agentTorWebReady_.store(false);
        agentTorWebProbeConsecutiveFailures_.store(0);
        agentTorWebProbeConsecutiveSuccesses_.store(0);
        agentTorWebProbeExitCode_.store(-1);
        setTorWebProbeLastError("socks_unreachable");
        return false;
    }

    auto& cfg = utils::Config::instance();
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t intervalSec = static_cast<uint64_t>(std::max<int64_t>(
        3, cfg.getInt64("agent.tor.web_probe_interval_seconds", 15)));
    const uint64_t lastProbeAt = agentTorWebProbeLastAt_.load();
    if (!force && lastProbeAt != 0 && now >= lastProbeAt && (now - lastProbeAt) < intervalSec) {
        return agentTorWebReady_.load();
    }

    bool expected = false;
    if (!agentTorWebProbeInFlight_.compare_exchange_strong(expected, true)) {
        return agentTorWebReady_.load();
    }

    const auto parseProbeUrls = [](const std::string& raw) {
        std::vector<std::string> out;
        std::string cur;
        auto flush = [&]() {
            std::string v = cur;
            cur.clear();
            const auto notSpace = [](unsigned char c) { return !std::isspace(c); };
            v.erase(v.begin(), std::find_if(v.begin(), v.end(), notSpace));
            v.erase(std::find_if(v.rbegin(), v.rend(), notSpace).base(), v.end());
            if (v.empty()) return;
            if (std::find(out.begin(), out.end(), v) == out.end()) out.push_back(v);
        };
        for (char ch : raw) {
            if (ch == ',' || ch == ';' || ch == '\n' || ch == '\r') {
                flush();
            } else {
                cur.push_back(ch);
            }
        }
        flush();
        return out;
    };

    const std::string probeUrlSingle =
        cfg.getString("agent.tor.web_probe_url", "https://duckduckgo.com/robots.txt");
    std::vector<std::string> probeUrls = parseProbeUrls(
        cfg.getString("agent.tor.web_probe_urls",
                      "https://duckduckgo.com/robots.txt,https://check.torproject.org/api/ip,https://example.com/"));
    if (probeUrls.empty()) probeUrls.push_back(probeUrlSingle);

    const uint32_t probeRetries = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.web_probe_retries", 2), 1, 8));
    const uint32_t retryDelayMs = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.web_probe_retry_delay_ms", 350), 0, 5000));
    const uint32_t failStreakToDegrade = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.web_probe_fail_streak_to_degrade", 2), 1, 12));
    const uint32_t successStreakToReady = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.web_probe_success_streak_to_ready", 1), 1, 12));
    const uint32_t timeoutSec = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.web_probe_timeout_seconds", 6), 2, 30));

    web::CurlFetchOptions opts;
    opts.socksProxyHostPort = configuredTorSocksHost() + ":" + std::to_string(configuredTorSocksPort());
    opts.timeoutSeconds = timeoutSec;
    opts.maxBytes = 1024;
    opts.followRedirects = true;
    opts.userAgent = "Mozilla/5.0 (compatible; SynapseNet-TorProbe/0.1)";

    const uint64_t rotation = agentTorWebProbeUrlRotation_.fetch_add(1);
    const size_t startIdx = probeUrls.empty() ? 0 : static_cast<size_t>(rotation % probeUrls.size());

    bool ok = false;
    int lastExitCode = -1;
    std::string lastError;

    for (uint32_t attempt = 0; attempt < probeRetries && !ok; ++attempt) {
        for (size_t i = 0; i < probeUrls.size(); ++i) {
            const size_t idx = (startIdx + i) % probeUrls.size();
            const auto probeResult = web::curlFetch(probeUrls[idx], opts);
            lastExitCode = probeResult.exitCode;
            if (probeResult.exitCode == 0) {
                ok = true;
                lastError.clear();
                break;
            }
            lastError = probeResult.error.empty()
                ? ("curl_exit=" + std::to_string(probeResult.exitCode))
                : probeResult.error;
        }
        if (!ok && attempt + 1 < probeRetries && retryDelayMs > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
        }
    }

    const bool prevReady = agentTorWebReady_.load();
    bool effectiveReady = false;
    if (ok) {
        agentTorWebProbeConsecutiveFailures_.store(0);
        const uint32_t successStreak = agentTorWebProbeConsecutiveSuccesses_.fetch_add(1) + 1;
        effectiveReady = prevReady || successStreak >= successStreakToReady;
        if (effectiveReady) {
            agentTorWebProbeLastOkAt_.store(now);
            setTorWebProbeLastError("");
        } else {
            setTorWebProbeLastError("warming_up");
        }
    } else {
        agentTorWebProbeConsecutiveSuccesses_.store(0);
        const uint32_t failStreak = agentTorWebProbeConsecutiveFailures_.fetch_add(1) + 1;
        effectiveReady = prevReady && failStreak < failStreakToDegrade;
        if (effectiveReady) {
            // Keep readiness during short Tor jitter to avoid 100<->70 flapping.
            setTorWebProbeLastError("");
        } else {
            setTorWebProbeLastError(lastError.empty() ? "curl_exit=-1" : lastError);
        }
    }

    agentTorWebReady_.store(effectiveReady);
    agentTorWebProbeLastAt_.store(now);
    agentTorWebProbeExitCode_.store(lastExitCode);
    agentTorWebProbeInFlight_.store(false);
    return effectiveReady;
}

bool startManagedTorRuntime() {
    const std::string torBin = utils::Config::instance().getString("agent.tor.binary", "tor");
    const std::string host = configuredTorSocksHost();
    const uint16_t socksPort = configuredTorSocksPort();
    const uint16_t controlPort = configuredTorControlPort();
    std::filesystem::path torDir = managedTorDirPath();
    std::filesystem::path pidFile = managedTorPidFilePath();

    const auto startup = core::runManagedTorStartup(
        allowManagedTorAutostart(),
        40,
        [&]() { return probeTorSocks(); },
        [&]() {
            const std::string checkCmd = torBin + " --version > /dev/null 2>&1";
            return std::system(checkCmd.c_str()) == 0;
        },
        [&]() {
            std::error_code ec;
            std::filesystem::create_directories(torDir, ec);
            return !ec;
        },
        [&]() {
#ifndef _WIN32
            return spawnManagedTorProcess(torBin, host, socksPort, controlPort, torDir, pidFile);
#else
            std::ostringstream cmd;
            cmd << torBin
                << " --quiet"
                << " --SocksPort " << host << ":" << socksPort
                << " --ControlPort 127.0.0.1:" << controlPort
                << " --DataDirectory \"" << torDir.string() << "\""
                << " --PidFile \"" << pidFile.string() << "\""
                << " --RunAsDaemon 1"
                << " > NUL 2>&1";
            return std::system(cmd.str().c_str()) == 0;
#endif
        },
        [&]() -> std::optional<int64_t> {
            int64_t pid = 0;
            if (readManagedTorPidFile(&pid)) return pid;
            return std::nullopt;
        },
        [&](int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); });

    if (startup.managedPid > 0) {
        managedTorPid_.store(startup.managedPid);
    }
    return startup.socksReachable;
}

void resetManagedTorRestartBackoffState() {
    agentTorManagedRestartConsecutiveFailures_.store(0);
    agentTorManagedRestartNextAllowedAt_.store(0);
}

bool maybeStartManagedTorRuntimeWithBackoff(bool allowStartManagedTor, const char* context) {
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    const bool torRequired = agentTorRequired_.load();
    const bool torReachable = probeTorSocks();
    if (torReachable) {
        resetManagedTorRestartBackoffState();
        return true;
    }

    auto& cfg = utils::Config::instance();
    const uint32_t baseBackoffSec = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.managed_restart_backoff_base_seconds", 2), 1, 300));
    const uint32_t maxBackoffSec = static_cast<uint32_t>(std::clamp<int64_t>(
        cfg.getInt64("agent.tor.managed_restart_backoff_max_seconds", 60), baseBackoffSec, 3600));

    core::ManagedTorRestartGateInput gateIn;
    gateIn.torRequired = torRequired;
    gateIn.allowStartManagedTor = allowStartManagedTor;
    gateIn.allowManagedAutostart = allowManagedTorAutostart();
    gateIn.torSocksReachable = false;
    gateIn.now = now;
    gateIn.nextAllowedAttemptAt = agentTorManagedRestartNextAllowedAt_.load();
    const auto gate = core::evaluateManagedTorRestartGate(gateIn);
    if (!gate.shouldAttempt) {
        if (gate.reason == "backoff") {
            agentTorManagedRestartBackoffSkips_.fetch_add(1);
        }
        return false;
    }

    bool expected = false;
    if (!agentTorManagedRestartInFlight_.compare_exchange_strong(expected, true)) {
        return false;
    }

    bool started = false;
    const uint64_t attemptAt = static_cast<uint64_t>(std::time(nullptr));
    agentTorManagedRestartLastAttemptAt_.store(attemptAt);
    if (probeTorSocks()) {
        started = true;
    } else {
        started = startManagedTorRuntime();
    }

    if (started) {
        const uint32_t failuresBefore = agentTorManagedRestartConsecutiveFailures_.exchange(0);
        agentTorManagedRestartNextAllowedAt_.store(0);
        if (failuresBefore > 0) {
            utils::Logger::info(std::string("Managed Tor bootstrap recovered after restart retries") +
                                " (failures=" + std::to_string(failuresBefore) +
                                (context ? ", context=" + std::string(context) : std::string()) + ")");
        }
    } else {
        const uint32_t failures = agentTorManagedRestartConsecutiveFailures_.fetch_add(1) + 1;
        const uint32_t backoffSec =
            core::evaluateManagedTorRestartBackoffSeconds(failures, baseBackoffSec, maxBackoffSec);
        const uint64_t nextAllowedAt = attemptAt + backoffSec;
        agentTorManagedRestartNextAllowedAt_.store(nextAllowedAt);
        utils::Logger::warn(std::string("Managed Tor bootstrap retry backoff scheduled") +
                            " (failures=" + std::to_string(failures) +
                            ", backoff=" + std::to_string(backoffSec) + "s" +
                            (context ? ", context=" + std::string(context) : std::string()) + ")");
    }

    agentTorManagedRestartInFlight_.store(false);
    return started;
}

core::TorRoutePolicyDecision refreshTorRoutePolicy(bool allowStartManagedTor) {
    const bool torRequired = agentTorRequired_.load();
    bool torReachable = probeTorSocks();

    if (torRequired && !torReachable && allowStartManagedTor) {
        torReachable = maybeStartManagedTorRuntimeWithBackoff(allowStartManagedTor, "refresh_tor_route_policy");
        if (torReachable) {
            agentTorManaged_.store(true);
        }
    }
    if (torReachable) {
        resetManagedTorRestartBackoffState();
    }

    agentTorReachable_.store(torReachable);
    refreshTorWebReadiness(torReachable, false);

    core::TorRoutePolicyInput routeIn;
    routeIn.torRequired = torRequired;
    routeIn.torReachable = torReachable;
    routeIn.allowClearnetFallback = agentAllowClearnetFallback_.load();
    routeIn.allowP2PFallback = agentAllowP2PFallback_.load();
    const auto route = core::evaluateTorRoutePolicy(routeIn);
    agentTorDegraded_.store(route.torDegraded);
    updateAndLogTorReadinessState(torRequired, torReachable, agentTorWebReady_.load(), route.torDegraded);
    return route;
}

std::string redactPotentialSecrets(const std::string& input) const {
    std::string out = input;
    static const std::regex pattern(
        "(api[_-]?key|token|authorization|bearer|private[ _-]?key|mnemonic|seed[ _-]?phrase|secret|password)\\s*[:=]\\s*[^\\s\\\"'<>]+",
        std::regex::icase
    );
    out = std::regex_replace(out, pattern, "$1=[REDACTED]");
    return out;
}

bool containsPotentialSecrets(const std::string& input) const {
    static const std::regex pattern(
        "(api[_-]?key|token|authorization|bearer|private[ _-]?key|mnemonic|seed[ _-]?phrase|secret|password)\\s*[:=]\\s*[^\\s\\\"'<>]+",
        std::regex::icase
    );
    return std::regex_search(input, pattern);
}

json redactPotentialSecretsInJson(const json& value, bool* redacted = nullptr) const {
    if (value.is_string()) {
        const std::string current = value.get<std::string>();
        const std::string safe = redactPotentialSecrets(current);
        if (redacted && safe != current) *redacted = true;
        return safe;
    }
    if (value.is_array()) {
        json out = json::array();
        for (const auto& item : value) {
            out.push_back(redactPotentialSecretsInJson(item, redacted));
        }
        return out;
    }
    if (value.is_object()) {
        json out = json::object();
        for (auto it = value.begin(); it != value.end(); ++it) {
            out[it.key()] = redactPotentialSecretsInJson(it.value(), redacted);
        }
        return out;
    }
    return value;
}

void reloadImplantUpdatePoliciesFromConfig() {
    auto& cfg = utils::Config::instance();

    core::ImplantCompatibilityPolicy compatibility;
    compatibility.protocolMin = static_cast<uint32_t>(std::max(1, cfg.getInt("implant.update.protocol_min", 1)));
    compatibility.protocolMax = static_cast<uint32_t>(std::max<int>(
        static_cast<int>(compatibility.protocolMin),
        cfg.getInt("implant.update.protocol_max", static_cast<int>(compatibility.protocolMin))
    ));
    compatibility.halVersion = static_cast<uint32_t>(std::max(1, cfg.getInt("implant.hal.version", 1)));
    compatibility.intentSchemaVersion = static_cast<uint32_t>(std::max(1, cfg.getInt("implant.intent.schema_version", 1)));
    compatibility.requireSafetyGate = cfg.getBool("implant.update.require_safety_gate", true);

    core::ImplantUpdateGovernancePolicy governance;
    governance.requireTrustedSigner = cfg.getBool("implant.update.require_trusted_signer", true);
    governance.minSignerApprovals = static_cast<uint32_t>(std::max(1, cfg.getInt("implant.update.min_signer_approvals", 1)));

    for (const auto& signerHex : cfg.getList("implant.update.trusted_signers")) {
        crypto::PublicKey signer{};
        if (!parsePublicKeyHex(signerHex, signer)) {
            utils::Logger::warn("Ignoring invalid implant.update.trusted_signers entry (expected 32-byte hex): " + signerHex);
            continue;
        }
        governance.trustedSigners.push_back(signer);
    }

    std::sort(governance.trustedSigners.begin(), governance.trustedSigners.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    });
    governance.trustedSigners.erase(std::unique(governance.trustedSigners.begin(), governance.trustedSigners.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
        return a == b;
    }), governance.trustedSigners.end());

    {
        std::lock_guard<std::mutex> lock(implantPolicyMtx_);
        implantCompatibilityPolicy_ = compatibility;
        implantUpdatePolicy_ = governance;
    }

    refreshSecurityPolicyHashes("config_reload");
}

json implantUpdatePolicyToJson() {
    core::ImplantCompatibilityPolicy compatibility;
    core::ImplantUpdateGovernancePolicy governance;
    {
        std::lock_guard<std::mutex> lock(implantPolicyMtx_);
        compatibility = implantCompatibilityPolicy_;
        governance = implantUpdatePolicy_;
    }

    json out;
    out["protocolMin"] = compatibility.protocolMin;
    out["protocolMax"] = compatibility.protocolMax;
    out["halVersion"] = compatibility.halVersion;
    out["intentSchemaVersion"] = compatibility.intentSchemaVersion;
    out["requireSafetyGate"] = compatibility.requireSafetyGate;
    out["requireTrustedSigner"] = governance.requireTrustedSigner;
    out["minSignerApprovals"] = governance.minSignerApprovals;
    json trusted = json::array();
    for (const auto& signer : governance.trustedSigners) {
        trusted.push_back(crypto::toHex(signer));
    }
    out["trustedSigners"] = trusted;
    return out;
}

std::string hashWithDomain(const std::string& domain, const std::string& payload) const {
    std::vector<uint8_t> bytes;
    bytes.reserve(domain.size() + payload.size());
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return crypto::toHex(crypto::sha256(bytes.data(), bytes.size()));
}

json sandboxPolicyToJson(const core::SandboxPolicy& policy) const {
    json out;
    out["allowSideEffects"] = policy.allowSideEffects;
    out["workspaceRoot"] = policy.workspaceRoot;
    out["readRoots"] = policy.readRoots;
    out["writeRoots"] = policy.writeRoots;
    out["deniedPathPrefixes"] = policy.deniedPathPrefixes;
    out["deniedFileNames"] = policy.deniedFileNames;
    out["deniedExtensions"] = policy.deniedExtensions;
    out["maxToolPayloadBytes"] = policy.maxToolPayloadBytes;
    json allowlist = json::array();
    for (auto capability : policy.allowlist) {
        allowlist.push_back(core::capabilityToString(capability));
    }
    out["allowlist"] = allowlist;
    return out;
}

json taskSchedulerPolicyToJson(const core::AgentTaskSchedulerPolicy& policy) const {
    json out;
    out["tickSeconds"] = policy.tickSeconds;
    out["epochTicks"] = policy.epochTicks;
    out["starvationThresholdTicks"] = policy.starvationThresholdTicks;
    out["epochBudgetCpu"] = policy.epochBudget.cpu;
    out["epochBudgetRam"] = policy.epochBudget.ram;
    out["epochBudgetNetwork"] = policy.epochBudget.network;
    json priority = json::array();
    for (auto taskClass : policy.fixedPriority) {
        priority.push_back(core::agentTaskClassToString(taskClass));
    }
    out["fixedPriority"] = priority;
    json classes = json::array();
    for (size_t idx = 0; idx < core::kAgentTaskClassCount; ++idx) {
        json item;
        item["taskClass"] = core::agentTaskClassToString(static_cast<core::AgentTaskClass>(idx));
        item["cpu"] = policy.classes[idx].cost.cpu;
        item["ram"] = policy.classes[idx].cost.ram;
        item["network"] = policy.classes[idx].cost.network;
        item["minIntervalTicks"] = policy.classes[idx].minIntervalTicks;
        classes.push_back(item);
    }
    out["classes"] = classes;
    return out;
}

json scorePolicyToJson(const core::AgentScorePolicy& policy) const {
    json out;
    out["scoreMin"] = policy.scoreMin;
    out["scoreMax"] = policy.scoreMax;
    out["initialScore"] = policy.initialScore;
    out["decayNumerator"] = policy.decayNumerator;
    out["decayDenominator"] = policy.decayDenominator;
    out["acceptWeight"] = policy.acceptWeight;
    out["rejectWeight"] = policy.rejectWeight;
    out["violationWeight"] = policy.violationWeight;
    out["throttledBelowOrEqual"] = policy.throttledBelowOrEqual;
    out["reviewOnlyBelowOrEqual"] = policy.reviewOnlyBelowOrEqual;
    out["localDraftOnlyBelowOrEqual"] = policy.localDraftOnlyBelowOrEqual;
    out["localDraftRecoveryAbove"] = policy.localDraftRecoveryAbove;
    out["localDraftRecoveryCleanSteps"] = policy.localDraftRecoveryCleanSteps;
    out["normalBatchLimit"] = policy.normalBatchLimit;
    out["throttledBatchLimit"] = policy.throttledBatchLimit;
    out["reviewOnlyBatchLimit"] = policy.reviewOnlyBatchLimit;
    out["localDraftOnlyBatchLimit"] = policy.localDraftOnlyBatchLimit;
    return out;
}

json submissionPipelineConfigToJson(const core::AgentSubmissionPipelineConfig& config) const {
    json out;
    out["maxBatchSize"] = config.maxBatchSize;
    out["includeReviewRequired"] = config.includeReviewRequired;
    out["minDistinctReviewers"] = config.minDistinctReviewers;
    out["requireNonAuthorReviewer"] = config.requireNonAuthorReviewer;
    out["intentMinTitleBytes"] = config.intentMinTitleBytes;
    out["intentMinBodyBytes"] = config.intentMinBodyBytes;
    out["intentRequireCitationForText"] = config.intentRequireCitationForText;
    out["intentMinCitationsForText"] = config.intentMinCitationsForText;
    out["duplicateGateContentId"] = config.duplicateGateContentId;
    out["duplicateGateNoveltyBuckets"] = config.duplicateGateNoveltyBuckets;
    out["duplicateGateCitationGraph"] = config.duplicateGateCitationGraph;
    out["duplicateCitationGraphMaxHamming"] = config.duplicateCitationGraphMaxHamming;
    out["citationSanityMaxCitations"] = config.citationSanityMaxCitations;
    out["citationSanityRejectDuplicateCitations"] = config.citationSanityRejectDuplicateCitations;
    out["citationSanityRequireKnownCitations"] = config.citationSanityRequireKnownCitations;
    out["citationSanityRejectSelfReference"] = config.citationSanityRejectSelfReference;
    out["citationSanityRejectIntraSetCycles"] = config.citationSanityRejectIntraSetCycles;
    out["citationSanityMaxIntraSetEdges"] = config.citationSanityMaxIntraSetEdges;
    out["citationSanityMinCorroboratingCitations"] = config.citationSanityMinCorroboratingCitations;
    out["citationSanityMinDistinctCitationAuthors"] = config.citationSanityMinDistinctCitationAuthors;
    return out;
}

json connectorAbusePolicyToJson(const web::ConnectorAbusePolicy& policy) const {
    json out;
    out["policyBlockDeltaThreshold"] = policy.policyBlockDeltaThreshold;
    out["failureDeltaThreshold"] = policy.failureDeltaThreshold;
    out["cooldownTicks"] = policy.cooldownTicks;
    out["violationPenaltySteps"] = policy.violationPenaltySteps;
    return out;
}

std::string computeNaanPolicyHash() const {
    auto& cfg = utils::Config::instance();
    json out;
    out["sandbox"] = sandboxPolicyToJson(agentRuntimeSandbox_.getPolicy());
    out["taskScheduler"] = taskSchedulerPolicyToJson(naanTaskScheduler_.policy());
    out["score"] = scorePolicyToJson(agentScore_.policy());
    out["adaptiveScheduler"] = {
        {"draftNormal", agentAdaptiveScheduler_.policy().draftIntervalNormalSeconds},
        {"draftThrottled", agentAdaptiveScheduler_.policy().draftIntervalThrottledSeconds},
        {"draftQuarantined", agentAdaptiveScheduler_.policy().draftIntervalQuarantinedSeconds},
        {"pipelineNormal", agentAdaptiveScheduler_.policy().pipelineIntervalNormalSeconds},
        {"pipelineThrottled", agentAdaptiveScheduler_.policy().pipelineIntervalThrottledSeconds},
        {"pipelineQuarantined", agentAdaptiveScheduler_.policy().pipelineIntervalQuarantinedSeconds},
        {"heartbeatNormal", agentAdaptiveScheduler_.policy().heartbeatIntervalNormalSeconds},
        {"heartbeatThrottled", agentAdaptiveScheduler_.policy().heartbeatIntervalThrottledSeconds},
        {"heartbeatQuarantined", agentAdaptiveScheduler_.policy().heartbeatIntervalQuarantinedSeconds}
    };
    out["submissionPipeline"] = submissionPipelineConfigToJson(agentSubmissionPipeline_.config());
    out["connectorAbuse"] = connectorAbusePolicyToJson(naanConnectorAbuseGuard_.getPolicy());
    out["routing"] = {
        {"torRequired", cfg.getBool("agent.tor.required", true)},
        {"allowClearnetFallback", cfg.getBool("agent.routing.allow_clearnet_fallback", false)},
        {"allowP2PFallback", cfg.getBool("agent.routing.allow_p2p_clearnet_fallback", false)}
    };
    out["retention"] = {
        {"maxSubmittedDrafts", cfg.getInt64("agent.retention.max_submitted_drafts", 0)},
        {"maxObservatoryHistory", cfg.getInt64("agent.retention.max_observatory_history", 0)},
        {"roomMaxMessages", cfg.getInt64("agent.retention.room.max_messages", 0)},
        {"roomRetentionSeconds", cfg.getInt64("agent.retention.room.seconds", 0)}
    };
    out["toolSchemas"] = json::array();
    for (const auto& schema : naanToolSchemas_) {
        json s;
        s["toolName"] = schema.toolName;
        s["capability"] = core::capabilityToString(schema.capability);
        s["requiredKeys"] = schema.requiredKeys;
        s["optionalKeys"] = schema.optionalKeys;
        s["maxPayloadBytes"] = schema.maxPayloadBytes;
        s["allowSideEffects"] = schema.allowSideEffects;
        s["requireExplicitSideEffectFlag"] = schema.requireExplicitSideEffectFlag;
        out["toolSchemas"].push_back(s);
    }
    return hashWithDomain("synapsenet:naan:policy:v1", out.dump());
}

std::string computeImplantPolicyHash() {
    return hashWithDomain("synapsenet:implant:policy:v1", implantUpdatePolicyToJson().dump());
}

std::pair<std::string, std::string> securityPolicyHashes() {
    std::lock_guard<std::mutex> lock(securityPolicyMtx_);
    return {naanPolicyHash_, implantPolicyHash_};
}

void refreshSecurityPolicyHashes(const std::string& context) {
    const std::string naanHash = computeNaanPolicyHash();
    const std::string implantHash = computeImplantPolicyHash();
    {
        std::lock_guard<std::mutex> lock(securityPolicyMtx_);
        naanPolicyHash_ = naanHash;
        implantPolicyHash_ = implantHash;
    }
    utils::Logger::info("security_policy_hash naan=" + naanHash + " implant=" + implantHash + " context=" + context);
}

void emitSecurityEvent(uint64_t atTimestamp,
                       const std::string& kind,
                       const std::string& severity,
                       const std::string& subject,
                       const json& details) {
    bool redacted = false;
    json safeDetails = redactPotentialSecretsInJson(details, &redacted);
    auto hashes = securityPolicyHashes();
    json payload;
    payload["event"] = "security_event";
    payload["kind"] = kind;
    payload["severity"] = severity;
    payload["subject"] = subject;
    payload["details"] = safeDetails;
    payload["policyHashNaan"] = hashes.first;
    payload["policyHashImplant"] = hashes.second;
    payload["redacted"] = redacted;
    appendNaanAuditEvent(atTimestamp, "security_event", subject, payload);
    naanSecurityEvents_.fetch_add(1);
    naanSecurityLastEventAt_.store(atTimestamp);
    if (severity == "high" || severity == "critical") {
        naanSecurityHighSeverityEvents_.fetch_add(1);
    }
    utils::Logger::warn("SECURITY_EVENT " + payload.dump());
}

std::vector<core::DetachedSignerApproval> detachedSignerApprovals(const crypto::Hash256& bundleId) {
    const std::string bundleHex = crypto::toHex(bundleId);
    std::lock_guard<std::mutex> lock(updateApprovalMtx_);
    auto it = updateDetachedApprovalsByBundle_.find(bundleHex);
    if (it == updateDetachedApprovalsByBundle_.end()) {
        return {};
    }
    return it->second;
}

void upsertDetachedSignerApproval(const crypto::Hash256& bundleId, const core::DetachedSignerApproval& approval) {
    const std::string bundleHex = crypto::toHex(bundleId);
    std::lock_guard<std::mutex> lock(updateApprovalMtx_);
    auto& approvals = updateDetachedApprovalsByBundle_[bundleHex];
    auto it = std::find_if(approvals.begin(), approvals.end(), [&](const core::DetachedSignerApproval& item) {
        return item.signer == approval.signer;
    });
    if (it == approvals.end()) {
        approvals.push_back(approval);
    } else {
        *it = approval;
    }
}

json detachedSignerApprovalsToJson(const crypto::Hash256& bundleId) {
    const std::string bundleHex = crypto::toHex(bundleId);
    std::vector<core::DetachedSignerApproval> approvals;
    {
        std::lock_guard<std::mutex> lock(updateApprovalMtx_);
        auto it = updateDetachedApprovalsByBundle_.find(bundleHex);
        if (it != updateDetachedApprovalsByBundle_.end()) {
            approvals = it->second;
        }
    }

    json out;
    out["bundleId"] = bundleHex;
    out["count"] = approvals.size();
    json items = json::array();
    for (const auto& approval : approvals) {
        json item;
        item["signer"] = crypto::toHex(approval.signer);
        item["signature"] = crypto::toHex(approval.signature);
        const auto digest = core::ImplantCompatibility::detachedApprovalHash(bundleId);
        item["signatureValid"] = crypto::verify(digest, approval.signature, approval.signer);
        items.push_back(item);
    }
    out["items"] = items;
    return out;
}

bool fetchStoredUpdateManifest(const crypto::Hash256& bundleId, core::UpdateManifest& outManifest) {
    std::string idHex = crypto::toHex(bundleId);
    std::lock_guard<std::mutex> lock(invMtx_);
    auto it = updateManifestsById_.find(idHex);
    if (it == updateManifestsById_.end()) return false;
    outManifest = it->second;
    return true;
}

bool validateImplantDistributionManifest(const core::UpdateManifest& manifest, bool safetyGatePassed, std::string* reason = nullptr) {
    core::ImplantCompatibilityPolicy compatibility;
    core::ImplantUpdateGovernancePolicy governance;
    std::vector<core::DetachedSignerApproval> approvals;
    {
        std::lock_guard<std::mutex> lock(implantPolicyMtx_);
        compatibility = implantCompatibilityPolicy_;
        governance = implantUpdatePolicy_;
    }
    approvals = detachedSignerApprovals(manifest.bundleId);
    return core::ImplantCompatibility::canDistributeManifest(manifest, safetyGatePassed, compatibility, governance, approvals, reason);
}

bool validateUpdateSignerThreshold(const core::UpdateManifest& manifest, std::string* reason = nullptr) {
    core::ImplantUpdateGovernancePolicy governance;
    {
        std::lock_guard<std::mutex> lock(implantPolicyMtx_);
        governance = implantUpdatePolicy_;
    }
    auto approvals = detachedSignerApprovals(manifest.bundleId);
    return core::ImplantCompatibility::verifyDetachedSignerApprovals(manifest, governance, approvals, reason);
}

core::UpdateInstaller::UpdatePolicy installerPolicyForManifest(const core::UpdateManifest& manifest) {
    core::ImplantUpdateGovernancePolicy governance;
    {
        std::lock_guard<std::mutex> lock(implantPolicyMtx_);
        governance = implantUpdatePolicy_;
    }

    core::UpdateInstaller::UpdatePolicy policy;
    if (governance.requireTrustedSigner && !governance.trustedSigners.empty()) {
        policy.allowedSigners = governance.trustedSigners;
        policy.minSignatures = std::max<uint32_t>(1, governance.minSignerApprovals);
        return policy;
    }

    policy.allowedSigners.push_back(manifest.signer);
    for (const auto& extra : manifest.additionalSignatures) {
        if (std::find(policy.allowedSigners.begin(), policy.allowedSigners.end(), extra.first) == policy.allowedSigners.end()) {
            policy.allowedSigners.push_back(extra.first);
        }
    }
    policy.minSignatures = 1;
    return policy;
}

std::optional<core::ImplantSafetyRecord> getImplantSafetyRecord(const crypto::Hash256& bundleId) {
    std::lock_guard<std::mutex> lock(implantSafetyMtx_);
    return implantSafetyPipeline_.getRecord(bundleId);
}

json observatoryEntryToJson(const core::ObservatoryEntry& entry) const {
    json out;
    out["hash"] = crypto::toHex(entry.hash);
    out["roomId"] = entry.roomId;
    out["type"] = core::roomMessageTypeToString(entry.type);
    out["author"] = crypto::toHex(entry.author);
    out["payloadPreview"] = redactPotentialSecrets(entry.payloadPreview);
    out["timestamp"] = entry.timestamp;
    return out;
}

json signedArtifactToJson(const core::SignedArtifact& artifact, bool includePayload = true) const {
    json out;
    out["hash"] = crypto::toHex(artifact.hash);
    out["insertedAt"] = artifact.insertedAt;

    json msg;
    msg["sequence"] = artifact.message.sequence;
    msg["timestamp"] = artifact.message.timestamp;
    msg["type"] = core::roomMessageTypeToString(artifact.message.type);
    msg["author"] = crypto::toHex(artifact.message.author);
    msg["roomId"] = artifact.message.roomId;
    msg["signature"] = crypto::toHex(artifact.message.signature);
    if (includePayload) {
        msg["payload"] = redactPotentialSecrets(artifact.message.payload);
    } else {
        msg["payloadBytes"] = artifact.message.payload.size();
    }
    out["message"] = msg;
    return out;
}

json draftProposalToJson(const core::AgentDraftProposal& proposal, bool includeBody = false) const {
    json out;
    out["version"] = proposal.version;
    out["draftId"] = crypto::toHex(proposal.draftId());
    out["contentHash"] = crypto::toHex(proposal.contentHash());
    out["createdAt"] = proposal.createdAt;
    out["author"] = crypto::toHex(proposal.author);
    out["title"] = redactPotentialSecrets(proposal.title);
    out["powBits"] = proposal.powBits;
    out["powNonce"] = proposal.powNonce;
    out["signature"] = crypto::toHex(proposal.signature);

    json cites = json::array();
    for (const auto& c : proposal.citations) {
        cites.push_back(crypto::toHex(c));
    }
    out["citations"] = cites;

    if (includeBody) {
        out["body"] = redactPotentialSecrets(proposal.body);
    } else {
        out["bodyBytes"] = proposal.body.size();
    }
    return out;
}

json draftRecordToJson(const core::AgentDraftRecord& record, bool includeBody = false) const {
    json out;
    out["proposal"] = draftProposalToJson(record.proposal, includeBody);
    out["status"] = core::draftStatusToString(record.status);
    out["rejectReason"] = redactPotentialSecrets(record.rejectReason);
    out["reviewCount"] = record.reviews.size();
    json reviews = json::array();
    for (const auto& review : record.reviews) {
        json r;
        r["reviewer"] = crypto::toHex(review.reviewer);
        r["approved"] = review.approved;
        r["reviewedAt"] = review.reviewedAt;
        r["reason"] = redactPotentialSecrets(review.reason);
        reviews.push_back(std::move(r));
    }
    out["reviews"] = std::move(reviews);
    out["updatedAt"] = record.updatedAt;
    return out;
}

json draftDryRunToJson(const core::AgentSubmissionDryRunResult& result) const {
    json out;
    out["draftId"] = crypto::toHex(result.draftId);
    out["ok"] = result.ok;
    out["reason"] = redactPotentialSecrets(result.reason);
    out["nextStatus"] = result.nextStatus;
    if (result.ok) {
        out["submitId"] = crypto::toHex(result.entry.submitId());
        out["contentId"] = crypto::toHex(result.entry.contentId());
    }
    return out;
}

json draftBatchItemToJson(const core::AgentSubmissionBatchItem& result) const {
    json out;
    out["draftId"] = crypto::toHex(result.draftId);
    out["ok"] = result.ok;
    out["action"] = result.action;
    out["reason"] = redactPotentialSecrets(result.reason);
    if (result.submitId != crypto::Hash256{}) out["submitId"] = crypto::toHex(result.submitId);
    if (result.contentId != crypto::Hash256{}) out["contentId"] = crypto::toHex(result.contentId);
    out["expectedAcceptanceRewardAtoms"] = result.expectedAcceptanceRewardAtoms;
    out["acceptanceRewardCredited"] = result.acceptanceRewardCredited;
    return out;
}

bool authorizeNaanTool(const core::ToolInvocation& invocation, const std::string& context) {
    core::RuntimeActionResult gate = agentRuntimeSandbox_.authorizeTool(invocation, naanToolSchemas_);
    if (gate != core::RuntimeActionResult::ALLOWED) {
        utils::Logger::warn("NAAN sandbox denied " + context + ": " + core::runtimeActionResultToString(gate));
        json details;
        details["toolName"] = invocation.toolName;
        details["context"] = context;
        details["gate"] = core::runtimeActionResultToString(gate);
        details["capability"] = core::capabilityToString(invocation.capability);
        details["payloadBytes"] = invocation.payloadBytes;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "sandbox_denied", "high", invocation.toolName, details);
        return false;
    }
    return true;
}

bool sanitizeNaanPayload(json* payload, const std::string& context, uint64_t nowTimestamp) {
    if (payload == nullptr) return false;
    bool redacted = false;
    *payload = redactPotentialSecretsInJson(*payload, &redacted);
    const std::string encoded = payload->dump();
    if (containsPotentialSecrets(encoded)) {
        json details;
        details["context"] = context;
        details["reason"] = "secret_guardrail_blocked";
        emitSecurityEvent(nowTimestamp, "secret_guardrail_blocked", "critical", context, details);
        return false;
    }
    if (redacted) {
        json details;
        details["context"] = context;
        details["reason"] = "secret_guardrail_redacted";
        emitSecurityEvent(nowTimestamp, "secret_guardrail_redacted", "high", context, details);
    }
    return true;
}

static bool hasPrefix(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

std::string classifyNaanEventCategory(const std::string& kind) const {
    if (kind.find("tor") != std::string::npos) return "tor";
    if (kind.find("connector") != std::string::npos) return "connector";
    if (kind.find("pipeline") != std::string::npos || kind.find("draft") != std::string::npos) return "pipeline";
    if (kind.find("reward") != std::string::npos || kind.find("epoch") != std::string::npos) return "reward";
    if (kind.find("quarantine") != std::string::npos || kind.find("score") != std::string::npos) return "quarantine";
    if (kind.find("security") != std::string::npos) return "security";
    if (kind.find("observatory") != std::string::npos || kind.find("room") != std::string::npos) return "timeline";
    return "scheduler";
}

void recordNaanUiEvent(uint64_t timestamp, const std::string& category, const std::string& message) {
    NaanUiEvent ev;
    ev.timestamp = timestamp;
    ev.category = category;
    ev.message = message;

    std::lock_guard<std::mutex> lock(naanUiEventsMtx_);
    naanUiEvents_.push_back(std::move(ev));
    while (naanUiEvents_.size() > 512) {
        naanUiEvents_.pop_front();
    }
}

std::vector<NaanUiEvent> snapshotNaanUiEvents() const {
    std::lock_guard<std::mutex> lock(naanUiEventsMtx_);
    return std::vector<NaanUiEvent>(naanUiEvents_.begin(), naanUiEvents_.end());
}

bool configureNaanStorage() {
    auto& cfg = utils::Config::instance();
    auto readBoundedU64 = [&](const char* key, int64_t fallback, int64_t minValue, int64_t maxValue) {
        int64_t v = cfg.getInt64(key, fallback);
        if (v < minValue) v = minValue;
        if (v > maxValue) v = maxValue;
        return static_cast<uint64_t>(v);
    };

    core::AgentStorageAuditPolicy policy = naanAuditLog_.policy();
    policy.maxSegments = static_cast<uint32_t>(readBoundedU64(
        "naan.storage.audit.max_segments", 8, 1, 256));
    policy.maxSegmentBytes = readBoundedU64(
        "naan.storage.audit.max_segment_bytes", 1048576, 1024, 1073741824);
    naanAuditLog_.setPolicy(policy);

    naanStorageRootPath_ = config_.dataDir + "/naan/storage";
    std::string reason;
    if (!naanAuditLog_.open(naanStorageRootPath_, &reason)) {
        utils::Logger::error("Failed to initialize NAAN storage audit log: " + reason);
        return false;
    }

    auto st = naanAuditLog_.stats();
    naanStorageRecoveredLines_.store(st.recoveredTruncatedLines);
    naanStorageDroppedSegments_.store(st.droppedSegments);
    if (reason != "ok") {
        utils::Logger::warn("NAAN storage audit log recovered with reason: " + reason);
    }
    return true;
}

void appendNaanAuditEvent(uint64_t atTimestamp,
                          const std::string& kind,
                          const std::string& objectId,
                          const json& payload) {
    bool redacted = false;
    json safePayload = redactPotentialSecretsInJson(payload, &redacted);
    if (redacted) {
        naanRedactionCount_.fetch_add(1);
    }

    std::string reason;
    if (!naanAuditLog_.append(atTimestamp, kind, objectId, safePayload.dump(), &reason)) {
        utils::Logger::warn("Failed to append NAAN audit event (" + kind + "): " + reason);
        return;
    }

    auto st = naanAuditLog_.stats();
    naanStorageRecoveredLines_.store(st.recoveredTruncatedLines);
    naanStorageDroppedSegments_.store(st.droppedSegments);

    std::string safeObject = redactPotentialSecrets(objectId);
    if (safeObject != objectId) {
        naanRedactionCount_.fetch_add(1);
    }

    std::string payloadSummary = safePayload.dump();
    if (payloadSummary.size() > 220) {
        payloadSummary = payloadSummary.substr(0, 220) + "...";
    }
    std::string message = kind;
    if (!safeObject.empty()) {
        message += " object=" + safeObject;
    }
    if (!payloadSummary.empty()) {
        message += " payload=" + payloadSummary;
    }
    recordNaanUiEvent(atTimestamp, classifyNaanEventCategory(kind), message);
}

bool persistNaanCrashState(const std::string& context) {
    if (naanRuntimeCrashStatePath_.empty()) return true;
    std::string reason;
    if (!naanRuntimeSupervisor_.saveCrashState(naanRuntimeCrashStatePath_, &reason)) {
        utils::Logger::warn("Failed to persist NAAN runtime crash state (" + context + "): " + reason);
        return false;
    }
    return true;
}

bool loadNaanScoreState(std::string* reason = nullptr) {
    if (naanScoreStatePath_.empty()) {
        if (reason) *reason = "path_empty";
        return true;
    }

    std::string scoreReason;
    if (!agentScore_.loadState(naanScoreStatePath_, &scoreReason)) {
        if (reason) *reason = "score_" + scoreReason;
        return false;
    }

    uint64_t loadedDecay = 0;
    uint64_t loadedViolationTick = 0;
    std::ifstream in(naanScoreDecayStatePath_);
    if (in.good()) {
        std::string line;
        if (!std::getline(in, line)) {
            if (reason) *reason = "decay_empty";
            return false;
        }
        std::stringstream ss(line);
        std::string tag;
        std::string decayToken;
        std::string violationToken;
        if (!std::getline(ss, tag, ',') || !std::getline(ss, decayToken, ',') || !std::getline(ss, violationToken, ',')) {
            if (reason) *reason = "decay_invalid_format";
            return false;
        }
        if (tag != "v1") {
            if (reason) *reason = "decay_invalid_version";
            return false;
        }
        try {
            loadedDecay = std::stoull(decayToken);
            loadedViolationTick = std::stoull(violationToken);
        } catch (...) {
            if (reason) *reason = "decay_invalid_numbers";
            return false;
        }
    }

    const auto snap = agentScore_.snapshot();
    naanScoreLastDecayTs_.store(loadedDecay);
    naanScoreLastViolationTick_.store(loadedViolationTick);
    naanLastScoreBand_.store(static_cast<uint8_t>(snap.band));
    if (reason) *reason = scoreReason;
    return true;
}

bool persistNaanScoreState(const std::string& context) {
    if (naanScoreStatePath_.empty()) return true;

    std::string scoreReason;
    if (!agentScore_.saveState(naanScoreStatePath_, &scoreReason)) {
        utils::Logger::warn("Failed to persist NAAN score state (" + context + "): " + scoreReason);
        return false;
    }

    if (!naanScoreDecayStatePath_.empty()) {
        std::error_code ec;
        std::filesystem::path p(naanScoreDecayStatePath_);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path(), ec);
            if (ec) {
                utils::Logger::warn("Failed to persist NAAN score decay state (" + context + "): mkdir_failed");
                return false;
            }
        }

        std::ofstream out(naanScoreDecayStatePath_, std::ios::trunc);
        if (!out.good()) {
            utils::Logger::warn("Failed to persist NAAN score decay state (" + context + "): open_failed");
            return false;
        }
        out << "v1,"
            << naanScoreLastDecayTs_.load() << ","
            << naanScoreLastViolationTick_.load();
        if (!out.good()) {
            utils::Logger::warn("Failed to persist NAAN score decay state (" + context + "): write_failed");
            return false;
        }
    }
    return true;
}

void noteNaanScoreBandTransition(core::AgentScoreBand before,
                                 core::AgentScoreBand after,
                                 uint64_t nowTimestamp) {
    if (before == after) return;
    naanScoreBandTransitions_.fetch_add(1);
    if (before == core::AgentScoreBand::LOCAL_DRAFT_ONLY && after != core::AgentScoreBand::LOCAL_DRAFT_ONLY) {
        naanQuarantineRecoveryTransitions_.fetch_add(1);
        naanQuarantineRecoveryLastAt_.store(nowTimestamp);
    }
    naanLastScoreBand_.store(static_cast<uint8_t>(after));

    json payload;
    payload["before"] = core::agentScoreBandToString(before);
    payload["after"] = core::agentScoreBandToString(after);
    payload["transitions"] = naanScoreBandTransitions_.load();
    payload["quarantineRecoveries"] = naanQuarantineRecoveryTransitions_.load();
    appendNaanAuditEvent(nowTimestamp, "score_band_transition", "agent_score", payload);
}

void applyNaanScoreStep(uint32_t accepted,
                        uint32_t rejected,
                        uint32_t violations,
                        uint64_t nowTimestamp,
                        const std::string& context) {
    const auto before = agentScore_.snapshot();
    agentScore_.applyStep(accepted, rejected, violations);
    const auto after = agentScore_.snapshot();

    if (rejected > 0 || violations > 0) {
        naanScoreLastViolationTick_.store(naanTickCount_.load());
    }
    noteNaanScoreBandTransition(before.band, after.band, nowTimestamp);

    json payload;
    payload["context"] = context;
    payload["accepted"] = accepted;
    payload["rejected"] = rejected;
    payload["violations"] = violations;
    payload["beforeScore"] = before.score;
    payload["afterScore"] = after.score;
    payload["beforeBand"] = core::agentScoreBandToString(before.band);
    payload["afterBand"] = core::agentScoreBandToString(after.band);
    appendNaanAuditEvent(nowTimestamp, "score_step", "agent_score", payload);

    (void)persistNaanScoreState(context);
}

void applyNaanScoreDecayTick(uint64_t nowTimestamp) {
    const uint32_t interval = naanScoreDecayIntervalSeconds_.load();
    if (interval == 0) return;

    uint64_t lastDecay = naanScoreLastDecayTs_.load();
    if (lastDecay == 0) {
        naanScoreLastDecayTs_.store(nowTimestamp);
        (void)persistNaanScoreState("decay_seed");
        return;
    }
    if (nowTimestamp <= lastDecay) return;

    uint64_t steps = (nowTimestamp - lastDecay) / interval;
    if (steps == 0) return;
    if (steps > 100000) steps = 100000;

    const auto before = agentScore_.snapshot();
    for (uint64_t i = 0; i < steps; ++i) {
        agentScore_.applyStep(0, 0, 0);
    }
    const auto after = agentScore_.snapshot();

    naanScoreLastDecayTs_.store(lastDecay + steps * static_cast<uint64_t>(interval));
    noteNaanScoreBandTransition(before.band, after.band, nowTimestamp);
    (void)persistNaanScoreState("decay_tick");
}

core::AgentRuntimeFailoverState currentNaanFailoverState(uint64_t now) const {
    const auto score = agentScore_.snapshot();
    return naanRuntimeSupervisor_.failoverState(score.throttled, score.quarantined, now);
}

core::AgentAdaptiveSchedule currentNaanSchedule() const {
    const auto score = agentScore_.snapshot();
    return agentAdaptiveScheduler_.schedule(score.throttled, score.quarantined);
}

bool persistNaanSchedulerState(const std::string& context) {
    if (naanSchedulerStatePath_.empty()) return true;
    std::string reason;
    if (!naanTaskScheduler_.saveCheckpoint(naanSchedulerStatePath_, &reason)) {
        utils::Logger::warn("Failed to persist NAAN scheduler state (" + context + "): " + reason);
        return false;
    }
    return true;
}

bool configureNaanTaskScheduler() {
    auto& cfg = utils::Config::instance();

    core::AgentTaskSchedulerPolicy policy;
    int64_t epochTicksRaw = cfg.getInt64("naan.scheduler.epoch_ticks", 300);
    if (epochTicksRaw < 1) epochTicksRaw = 1;
    if (epochTicksRaw > 86400) epochTicksRaw = 86400;
    policy.epochTicks = static_cast<uint32_t>(epochTicksRaw);

    int64_t starveRaw = cfg.getInt64("naan.scheduler.starvation_threshold_ticks", 120);
    if (starveRaw < 1) starveRaw = 1;
    if (starveRaw > 1000000) starveRaw = 1000000;
    policy.starvationThresholdTicks = static_cast<uint32_t>(starveRaw);

    auto readBudget = [&](const char* key, uint32_t fallback) {
        int64_t v = cfg.getInt64(key, static_cast<int64_t>(fallback));
        if (v < 1) v = 1;
        if (v > 1000000000LL) v = 1000000000LL;
        return static_cast<uint32_t>(v);
    };
    policy.epochBudget.cpu = readBudget("naan.scheduler.budget.cpu_tokens", 1200);
    policy.epochBudget.ram = readBudget("naan.scheduler.budget.ram_tokens", 1200);
    policy.epochBudget.network = readBudget("naan.scheduler.budget.network_tokens", 1200);

    policy.fixedPriority = {
        core::AgentTaskClass::SUBMIT,
        core::AgentTaskClass::REVIEW,
        core::AgentTaskClass::VERIFY,
        core::AgentTaskClass::DRAFT,
        core::AgentTaskClass::RESEARCH
    };

    auto setClassPolicy = [&](core::AgentTaskClass taskClass,
                              const std::string& taskName,
                              uint32_t defCpu,
                              uint32_t defRam,
                              uint32_t defNet,
                              uint32_t defInterval) {
        const size_t idx = core::agentTaskClassIndex(taskClass);
        auto& cls = policy.classes[idx];

        auto readClass = [&](const std::string& suffix, uint32_t fallback, uint32_t maxValue) {
            int64_t v = cfg.getInt64("naan.scheduler.task." + taskName + "." + suffix, static_cast<int64_t>(fallback));
            if (v < 1) v = 1;
            if (v > static_cast<int64_t>(maxValue)) v = static_cast<int64_t>(maxValue);
            return static_cast<uint32_t>(v);
        };

        cls.cost.cpu = readClass("cpu_tokens", defCpu, policy.epochBudget.cpu);
        cls.cost.ram = readClass("ram_tokens", defRam, policy.epochBudget.ram);
        cls.cost.network = readClass("network_tokens", defNet, policy.epochBudget.network);
        cls.minIntervalTicks = readClass("min_interval_ticks", defInterval, 1000000);
    };

    setClassPolicy(core::AgentTaskClass::RESEARCH, "research", 30, 16, 20, 15);
    setClassPolicy(core::AgentTaskClass::VERIFY, "verify", 20, 12, 8, 10);
    setClassPolicy(core::AgentTaskClass::REVIEW, "review", 18, 10, 8, 10);
    setClassPolicy(core::AgentTaskClass::DRAFT, "draft", 40, 24, 16, 15);
    setClassPolicy(core::AgentTaskClass::SUBMIT, "submit", 45, 28, 18, 8);

    naanTaskScheduler_.setPolicy(policy);
    naanSchedulerStatePath_ = config_.dataDir + "/naan/scheduler.state";

    std::string loadReason;
    if (!naanTaskScheduler_.loadCheckpoint(naanSchedulerStatePath_, &loadReason)) {
        utils::Logger::error("Failed to load NAAN scheduler checkpoint: " + loadReason);
        return false;
    }
    if (loadReason == "not_found") {
        (void)persistNaanSchedulerState("scheduler_seed");
    }
    return true;
}

void configureNaanConnectorAbuseGuard() {
    auto& cfg = utils::Config::instance();
    web::ConnectorAbusePolicy policy;

    auto readPolicy = [&](const char* key, int64_t fallback, int64_t minValue, int64_t maxValue) {
        int64_t v = cfg.getInt64(key, fallback);
        if (v < minValue) v = minValue;
        if (v > maxValue) v = maxValue;
        return static_cast<uint32_t>(v);
    };

    policy.policyBlockDeltaThreshold = readPolicy(
        "naan.connector_abuse.policy_block_delta_threshold", 6, 1, 1000000);
    policy.failureDeltaThreshold = readPolicy(
        "naan.connector_abuse.failure_delta_threshold", 20, 1, 1000000);
    policy.cooldownTicks = readPolicy(
        "naan.connector_abuse.cooldown_ticks", 30, 1, 1000000);
    policy.violationPenaltySteps = readPolicy(
        "naan.connector_abuse.violation_penalty_steps", 2, 1, 16);

    naanConnectorAbuseGuard_.setPolicy(policy);
}

void configureNaanScorePolicy() {
    auto& cfg = utils::Config::instance();

    auto readBoundedI64 = [&](const char* key, int64_t fallback, int64_t minValue, int64_t maxValue) {
        int64_t v = cfg.getInt64(key, fallback);
        if (v < minValue) v = minValue;
        if (v > maxValue) v = maxValue;
        return v;
    };
    auto readBoundedU32 = [&](const char* key, int64_t fallback, int64_t minValue, int64_t maxValue) {
        int64_t v = cfg.getInt64(key, fallback);
        if (v < minValue) v = minValue;
        if (v > maxValue) v = maxValue;
        return static_cast<uint32_t>(v);
    };

    core::AgentScorePolicy policy = agentScore_.policy();
    policy.scoreMin = readBoundedI64("naan.score.min", -1000, -1000000, 0);
    policy.scoreMax = readBoundedI64("naan.score.max", 1000, 0, 1000000);
    if (policy.scoreMax < policy.scoreMin) std::swap(policy.scoreMax, policy.scoreMin);
    policy.initialScore = readBoundedI64("naan.score.initial", 0, policy.scoreMin, policy.scoreMax);

    policy.decayNumerator = readBoundedU32("naan.score.decay_numerator", 95, 0, 1000000);
    policy.decayDenominator = readBoundedU32("naan.score.decay_denominator", 100, 1, 1000000);
    if (policy.decayNumerator > policy.decayDenominator) {
        policy.decayNumerator = policy.decayDenominator;
    }

    policy.acceptWeight = readBoundedI64("naan.score.accept_weight", 12, 0, 1000000);
    policy.rejectWeight = readBoundedI64("naan.score.reject_weight", 30, 0, 1000000);
    policy.violationWeight = readBoundedI64("naan.score.violation_weight", 120, 0, 1000000);

    policy.throttledBelowOrEqual = readBoundedI64(
        "naan.score.band.throttled_below_or_equal", -60, policy.scoreMin, policy.scoreMax);
    policy.reviewOnlyBelowOrEqual = readBoundedI64(
        "naan.score.band.review_only_below_or_equal", -120, policy.scoreMin, policy.scoreMax);
    policy.localDraftOnlyBelowOrEqual = readBoundedI64(
        "naan.score.band.local_draft_only_below_or_equal", -200, policy.scoreMin, policy.scoreMax);
    policy.localDraftRecoveryAbove = readBoundedI64(
        "naan.score.band.local_draft_recovery_above", -120, policy.scoreMin, policy.scoreMax);
    policy.localDraftRecoveryCleanSteps = readBoundedU32(
        "naan.score.band.local_draft_recovery_clean_steps", 3, 0, 1000000);

    policy.normalBatchLimit = readBoundedU32("naan.score.batch_limit.full", 16, 0, 500);
    policy.throttledBatchLimit = readBoundedU32("naan.score.batch_limit.throttled", 4, 0, 500);
    policy.reviewOnlyBatchLimit = readBoundedU32("naan.score.batch_limit.review_only", 0, 0, 500);
    policy.localDraftOnlyBatchLimit = readBoundedU32("naan.score.batch_limit.local_draft_only", 0, 0, 500);
    agentScore_.setPolicy(policy);

    naanScoreDecayIntervalSeconds_.store(readBoundedU32(
        "naan.score.decay_interval_seconds", 60, 0, 86400));

    naanAbuseSpamPenalty_.store(readBoundedU32(
        "naan.abuse_classifier.spam_loop_penalty", 1, 0, 64));
    naanAbuseCitationPenalty_.store(readBoundedU32(
        "naan.abuse_classifier.invalid_citation_penalty", 1, 0, 64));
    naanAbusePolicyPenalty_.store(readBoundedU32(
        "naan.abuse_classifier.policy_violation_penalty", 2, 0, 64));

    naanScoreStatePath_ = config_.dataDir + "/naan/score.state";
    naanScoreDecayStatePath_ = config_.dataDir + "/naan/score_decay.state";
}

void configureNaanAdaptiveScheduler() {
    auto& cfg = utils::Config::instance();
    auto policy = agentAdaptiveScheduler_.policy();

    auto readBoundedU32 = [&](const char* key, int64_t fallback, int64_t minValue, int64_t maxValue) {
        int64_t v = cfg.getInt64(key, fallback);
        if (v < minValue) v = minValue;
        if (v > maxValue) v = maxValue;
        return static_cast<uint32_t>(v);
    };

    policy.draftIntervalNormalSeconds = readBoundedU32(
        "naan.scheduler.adaptive.draft_interval_normal_seconds",
        policy.draftIntervalNormalSeconds, 1, 86400);
    policy.draftIntervalThrottledSeconds = readBoundedU32(
        "naan.scheduler.adaptive.draft_interval_throttled_seconds",
        policy.draftIntervalThrottledSeconds, 1, 86400);
    policy.draftIntervalQuarantinedSeconds = readBoundedU32(
        "naan.scheduler.adaptive.draft_interval_quarantined_seconds",
        policy.draftIntervalQuarantinedSeconds, 1, 86400);

    policy.pipelineIntervalNormalSeconds = readBoundedU32(
        "naan.scheduler.adaptive.pipeline_interval_normal_seconds",
        policy.pipelineIntervalNormalSeconds, 1, 86400);
    policy.pipelineIntervalThrottledSeconds = readBoundedU32(
        "naan.scheduler.adaptive.pipeline_interval_throttled_seconds",
        policy.pipelineIntervalThrottledSeconds, 1, 86400);
    policy.pipelineIntervalQuarantinedSeconds = readBoundedU32(
        "naan.scheduler.adaptive.pipeline_interval_quarantined_seconds",
        policy.pipelineIntervalQuarantinedSeconds, 1, 86400);

    policy.heartbeatIntervalNormalSeconds = readBoundedU32(
        "naan.scheduler.adaptive.heartbeat_interval_normal_seconds",
        policy.heartbeatIntervalNormalSeconds, 1, 86400);
    policy.heartbeatIntervalThrottledSeconds = readBoundedU32(
        "naan.scheduler.adaptive.heartbeat_interval_throttled_seconds",
        policy.heartbeatIntervalThrottledSeconds, 1, 86400);
    policy.heartbeatIntervalQuarantinedSeconds = readBoundedU32(
        "naan.scheduler.adaptive.heartbeat_interval_quarantined_seconds",
        policy.heartbeatIntervalQuarantinedSeconds, 1, 86400);

    agentAdaptiveScheduler_.setPolicy(policy);
}

void configureNaanSubmissionPipeline() {
    auto& cfg = utils::Config::instance();
    core::AgentSubmissionPipelineConfig policy = agentSubmissionPipeline_.config();

    auto readBoundedU32 = [&](const char* key, int64_t fallback, int64_t minValue, int64_t maxValue) {
        int64_t v = cfg.getInt64(key, fallback);
        if (v < minValue) v = minValue;
        if (v > maxValue) v = maxValue;
        return static_cast<uint32_t>(v);
    };

    int64_t minReviewersRaw = cfg.getInt64("naan.reviewer_diversity.min_distinct_reviewers", 1);
    if (minReviewersRaw < 0) minReviewersRaw = 0;
    if (minReviewersRaw > 64) minReviewersRaw = 64;
    policy.minDistinctReviewers = static_cast<uint32_t>(minReviewersRaw);

    policy.requireNonAuthorReviewer = cfg.getBool("naan.reviewer_diversity.require_non_author", false);
    policy.includeReviewRequired = cfg.getBool("naan.reviewer_diversity.include_review_required", true);
    policy.intentMinTitleBytes = readBoundedU32(
        "agent.intent.min_title_bytes", 4, 1, 512);
    policy.intentMinBodyBytes = readBoundedU32(
        "agent.intent.min_body_bytes", 24, 1, 65536);
    policy.intentRequireCitationForText = cfg.getBool(
        "agent.intent.require_citation_for_text", false);
    policy.intentMinCitationsForText = readBoundedU32(
        "agent.intent.min_citations_for_text", 0, 0, 1024);

    policy.duplicateGateContentId = cfg.getBool("naan.duplicate_gates.content_id", true);
    policy.duplicateGateNoveltyBuckets = cfg.getBool("naan.duplicate_gates.novelty_buckets", true);
    policy.duplicateGateCitationGraph = cfg.getBool("naan.duplicate_gates.citation_graph", true);
    policy.duplicateCitationGraphMaxHamming = readBoundedU32(
        "naan.duplicate_gates.citation_graph_max_hamming", 24, 0, 64);

    policy.citationSanityMaxCitations = readBoundedU32(
        "naan.citation_sanity.max_citations", 64, 1, 1024);
    policy.citationSanityRejectDuplicateCitations = cfg.getBool(
        "naan.citation_sanity.reject_duplicate_citations", true);
    policy.citationSanityRequireKnownCitations = cfg.getBool(
        "naan.citation_sanity.require_known_citations", true);
    policy.citationSanityRejectSelfReference = cfg.getBool(
        "naan.citation_sanity.reject_self_reference", true);
    policy.citationSanityRejectIntraSetCycles = cfg.getBool(
        "naan.citation_sanity.reject_intra_set_cycles", true);
    policy.citationSanityMaxIntraSetEdges = readBoundedU32(
        "naan.citation_sanity.max_intra_set_edges", 8, 0, 1000000);
    policy.citationSanityMinCorroboratingCitations = readBoundedU32(
        "naan.citation_sanity.min_corroborating_citations", 0, 0, 1024);
    policy.citationSanityMinDistinctCitationAuthors = readBoundedU32(
        "naan.citation_sanity.min_distinct_authors", 0, 0, 1024);

    agentSubmissionPipeline_ = core::AgentSubmissionPipeline(policy);
}

uint32_t classifyNaanBatchViolations(const std::vector<core::AgentSubmissionBatchItem>& batch) const {
    uint64_t spamEvents = 0;
    uint64_t citationEvents = 0;
    uint64_t policyEvents = 0;
    for (const auto& item : batch) {
        if (item.action == "submit_error") {
            policyEvents += 1;
            continue;
        }
        if (item.action != "rejected") continue;

        if (hasPrefix(item.reason, "citation_")) {
            citationEvents += 1;
        } else if (hasPrefix(item.reason, "duplicate_gate_") ||
                   item.reason == "review_diversity_insufficient") {
            spamEvents += 1;
        } else if (hasPrefix(item.reason, "submit_") ||
                   hasPrefix(item.reason, "policy_")) {
            policyEvents += 1;
        }
    }

    const uint64_t total = spamEvents * static_cast<uint64_t>(naanAbuseSpamPenalty_.load()) +
                           citationEvents * static_cast<uint64_t>(naanAbuseCitationPenalty_.load()) +
                           policyEvents * static_cast<uint64_t>(naanAbusePolicyPenalty_.load());
    if (total > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(total);
}

void applyNaanConnectorAbuseAutoAction(uint64_t now, uint64_t tickValue) {
    web::WebConnectorHealth health{};
    {
        std::lock_guard<std::mutex> lock(webMtx_);
        if (!webSearch_) return;
        health = webSearch_->getConnectorHealth();
    }

    const auto decision = naanConnectorAbuseGuard_.observe(tickValue, health);
    if (!decision.triggered) {
        return;
    }

    const uint64_t scaled = static_cast<uint64_t>(decision.violations) *
                            static_cast<uint64_t>(naanAbusePolicyPenalty_.load());
    const uint32_t violationSteps = scaled > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(scaled);
    applyNaanScoreStep(0, 0, violationSteps, now, "connector_abuse_auto");
    naanConnectorAbuseEvents_.fetch_add(1);
    naanConnectorAbuseLastAt_.store(now);
    naanConnectorAbuseLastPolicyDelta_.store(decision.deltaPolicyBlocks);
    naanConnectorAbuseLastFailureDelta_.store(decision.deltaFailures);
    naanConnectorAbuseLastViolations_.store(decision.violations);

    utils::Logger::warn("NAAN connector abuse auto-action: policy_delta=" +
                       std::to_string(decision.deltaPolicyBlocks) +
                       " failure_delta=" + std::to_string(decision.deltaFailures) +
                       " violations=" + std::to_string(decision.violations));
    json details;
    details["policyDelta"] = decision.deltaPolicyBlocks;
    details["failureDelta"] = decision.deltaFailures;
    details["violations"] = decision.violations;
    details["penaltySteps"] = violationSteps;
    emitSecurityEvent(now, "connector_abuse_auto_action", "high", "connector_health", details);
}

bool hasPendingNaanDrafts() const {
    if (!agentDraftQueue_.listByStatus(core::DraftStatus::QUEUED, 1).empty()) return true;
    if (!agentDraftQueue_.listByStatus(core::DraftStatus::REVIEW_REQUIRED, 1).empty()) return true;
    if (!agentDraftQueue_.listByStatus(core::DraftStatus::APPROVED, 1).empty()) return true;
    return false;
}

void reconcileNaanDraftQueueWithLedger(uint64_t nowTimestamp) {
    if (!poeV1_ || !attachedAgentIdentity_.valid()) return;

    std::vector<core::AgentDraftRecord> candidates;
    auto queued = agentDraftQueue_.listByStatus(core::DraftStatus::QUEUED, 1000000);
    auto review = agentDraftQueue_.listByStatus(core::DraftStatus::REVIEW_REQUIRED, 1000000);
    auto approved = agentDraftQueue_.listByStatus(core::DraftStatus::APPROVED, 1000000);
    candidates.reserve(queued.size() + review.size() + approved.size());
    candidates.insert(candidates.end(), queued.begin(), queued.end());
    candidates.insert(candidates.end(), review.begin(), review.end());
    candidates.insert(candidates.end(), approved.begin(), approved.end());

    std::sort(candidates.begin(), candidates.end(), [](const core::AgentDraftRecord& a, const core::AgentDraftRecord& b) {
        const std::string ah = crypto::toHex(a.proposal.draftId());
        const std::string bh = crypto::toHex(b.proposal.draftId());
        if (ah != bh) return ah < bh;
        return a.proposal.createdAt < b.proposal.createdAt;
    });

    uint32_t checked = 0;
    uint32_t repaired = 0;
    for (const auto& record : candidates) {
        core::poe_v1::KnowledgeEntryV1 entry;
        std::string convertReason;
        if (!agentSubmissionPipeline_.convertDraftToEntry(
                record.proposal,
                attachedAgentIdentity_.privateKey,
                &entry,
                &convertReason)) {
            continue;
        }

        checked += 1;
        if (!poeV1_->getSubmitIdByContentId(entry.contentId()).has_value()) {
            continue;
        }

        std::string statusReason;
        if (record.status == core::DraftStatus::QUEUED ||
            record.status == core::DraftStatus::REVIEW_REQUIRED) {
            if (!agentDraftQueue_.setStatus(
                    record.proposal.draftId(),
                    core::DraftStatus::APPROVED,
                    nowTimestamp,
                    "ledger_crosscheck",
                    &statusReason)) {
                continue;
            }
        }

        if (agentDraftQueue_.markSubmitted(record.proposal.draftId(), nowTimestamp, &statusReason)) {
            repaired += 1;
        }
    }

    if (checked > 0 || repaired > 0) {
        json payload;
        payload["checked"] = checked;
        payload["repaired"] = repaired;
        appendNaanAuditEvent(nowTimestamp, "draft_queue_ledger_crosscheck", "draft_queue", payload);
    }
}

void reconcileNaanReviewArtifactsWithDraftQueue(uint64_t nowTimestamp) {
    if (!attachedAgentIdentity_.valid()) return;

    auto* reviewRoom = agentCoordination_.getRoom("reviews/main");
    if (!reviewRoom) return;

    std::set<std::string> knownDraftIds;
    const auto artifacts = reviewRoom->getArtifacts(0, 1000000);
    for (const auto& artifact : artifacts) {
        const auto parsed = json::parse(artifact.message.payload, nullptr, false);
        if (parsed.is_discarded()) continue;
        if (!parsed.contains("draftId") || !parsed["draftId"].is_string()) continue;
        knownDraftIds.insert(parsed["draftId"].get<std::string>());
    }

    auto records = agentDraftQueue_.list(1000000, true);
    std::sort(records.begin(), records.end(), [](const core::AgentDraftRecord& a, const core::AgentDraftRecord& b) {
        const std::string ah = crypto::toHex(a.proposal.draftId());
        const std::string bh = crypto::toHex(b.proposal.draftId());
        if (ah != bh) return ah < bh;
        return a.proposal.createdAt < b.proposal.createdAt;
    });

    uint32_t checked = 0;
    uint32_t missing = 0;
    uint32_t repaired = 0;
    for (const auto& record : records) {
        if (record.reviews.empty()) continue;

        const std::string draftIdHex = crypto::toHex(record.proposal.draftId());
        checked += 1;
        if (knownDraftIds.count(draftIdHex) > 0) continue;
        missing += 1;

        json payload;
        payload["event"] = "draft_review_projection_recovery";
        payload["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
        payload["draftId"] = draftIdHex;
        payload["status"] = core::draftStatusToString(record.status);
        payload["reviewCount"] = record.reviews.size();
        uint32_t approvedCount = 0;
        for (const auto& review : record.reviews) {
            if (review.approved) approvedCount += 1;
        }
        payload["reviewApprovedCount"] = approvedCount;
        payload["source"] = "draft_queue_consistency_check";
        if (!sanitizeNaanPayload(&payload, "review_consistency_repair_payload", nowTimestamp)) {
            continue;
        }
        const std::string payloadText = payload.dump();

        core::ToolInvocation call;
        call.toolName = "observatory.post";
        call.capability = core::AgentCapability::READ_NETWORK;
        call.keys = {"room", "kind", "payload"};
        call.payloadBytes = static_cast<uint32_t>(payloadText.size());
        call.hasSideEffects = true;
        call.explicitSideEffectFlag = true;
        if (authorizeNaanTool(call, "review_consistency_repair") &&
            agentCoordination_.postToRoom("reviews/main", attachedAgentIdentity_, core::RoomMessageType::REVIEW, payloadText, nowTimestamp)) {
            repaired += 1;
            knownDraftIds.insert(draftIdHex);
            appendNaanAuditEvent(nowTimestamp, "review_artifact_repair", draftIdHex, payload);
            if (repaired >= 8) break;
        }
    }

    if (checked > 0 || missing > 0 || repaired > 0) {
        json payload;
        payload["checked"] = checked;
        payload["missing"] = missing;
        payload["repaired"] = repaired;
        appendNaanAuditEvent(nowTimestamp, "review_artifact_crosscheck", "reviews/main", payload);
        naanConsistencyChecks_.fetch_add(1);
        naanConsistencyRepairs_.fetch_add(repaired);
        naanConsistencyLastAt_.store(nowTimestamp);
    }
}

void recoverNaanIndexesAndConsistency(uint64_t nowTimestamp, const std::string& context) {
    core::AgentDraftQueueRecoveryStats draftStats;
    core::CoordinationRecoveryStats coordinationStats;
    std::string draftReason;
    std::string coordinationReason;
    const bool draftOk = agentDraftQueue_.verifyAndRepairIndexes(&draftStats, &draftReason);
    const bool coordinationOk = agentCoordination_.verifyAndRepairIndexes(&coordinationStats, &coordinationReason);

    if (!draftOk) {
        utils::Logger::warn("NAAN draft queue index recovery failed (" + context + "): " + draftReason);
    }
    if (!coordinationOk) {
        utils::Logger::warn("NAAN coordination index recovery failed (" + context + "): " + coordinationReason);
    }

    reconcileNaanDraftQueueWithLedger(nowTimestamp);
    reconcileNaanReviewArtifactsWithDraftQueue(nowTimestamp);

    json payload;
    payload["context"] = context;
    payload["draftQueueReason"] = draftReason;
    payload["coordinationReason"] = coordinationReason;
    payload["draftQueueRecords"] = draftStats.records;
    payload["draftQueueDroppedDuplicates"] = draftStats.droppedDuplicateRecords;
    payload["coordinationRooms"] = coordinationStats.roomCount;
    payload["coordinationArtifacts"] = coordinationStats.roomArtifacts;
    payload["coordinationRebuiltEntries"] = coordinationStats.rebuiltEntries;
    appendNaanAuditEvent(nowTimestamp, "startup_recovery", "naan_indexes", payload);

    naanIndexRecoveryRuns_.fetch_add(1);
    naanIndexRecoveryLastAt_.store(nowTimestamp);
}

void configureNaanRuntimeSandbox() {
    core::SandboxPolicy policy;
    policy.allowSideEffects = true;
    policy.allowlist = {
        core::AgentCapability::READ_LEDGER,
        core::AgentCapability::READ_NETWORK,
        core::AgentCapability::PROPOSE_KNOWLEDGE,
        core::AgentCapability::FETCH_EXTERNAL
    };
    policy.workspaceRoot = config_.dataDir;
    policy.readRoots = {config_.dataDir, config_.dataDir + "/naan"};
    policy.writeRoots = {config_.dataDir + "/naan"};
    policy.deniedPathPrefixes = {
        config_.dataDir + "/wallet",
        config_.dataDir + "/keys",
        config_.dataDir + "/keystore"
    };
    policy.deniedFileNames = {
        "wallet.dat",
        "wallet.keys",
        "mnemonic.txt",
        "seed.txt",
        "id_rsa",
        "id_ed25519",
        ".env",
        "credentials.json",
        "private.key"
    };
    policy.deniedExtensions = {".pem", ".key", ".seed", ".mnemonic"};
    policy.maxToolPayloadBytes = 131072;
    agentRuntimeSandbox_.setPolicy(policy);

    naanToolSchemas_.clear();

    core::ToolSchemaRule observatory;
    observatory.toolName = "observatory.post";
    observatory.capability = core::AgentCapability::READ_NETWORK;
    observatory.requiredKeys = {"room", "kind", "payload"};
    observatory.maxPayloadBytes = 65536;
    observatory.allowSideEffects = true;
    observatory.requireExplicitSideEffectFlag = true;
    naanToolSchemas_.push_back(observatory);

    core::ToolSchemaRule enqueue;
    enqueue.toolName = "draft.enqueue";
    enqueue.capability = core::AgentCapability::PROPOSE_KNOWLEDGE;
    enqueue.requiredKeys = {"title", "body", "powBits", "powNonce"};
    enqueue.maxPayloadBytes = 65536;
    enqueue.allowSideEffects = true;
    enqueue.requireExplicitSideEffectFlag = true;
    naanToolSchemas_.push_back(enqueue);

    core::ToolSchemaRule pipelineDrain;
    pipelineDrain.toolName = "draft.submit_batch";
    pipelineDrain.capability = core::AgentCapability::PROPOSE_KNOWLEDGE;
    pipelineDrain.requiredKeys = {"atTimestamp", "maxBatch"};
    pipelineDrain.maxPayloadBytes = 256;
    pipelineDrain.allowSideEffects = true;
    pipelineDrain.requireExplicitSideEffectFlag = true;
    naanToolSchemas_.push_back(pipelineDrain);
}

std::vector<core::AgentSubmissionBatchItem> runNaanPipelineDrain(uint64_t atTimestamp,
                                                                 uint32_t overrideMaxBatch = 0,
                                                                 bool* skippedQuarantine = nullptr,
                                                                 uint32_t* effectiveBatchLimit = nullptr) {
    if (!naanRuntimeInitialized_.load() || !poeV1_ || !attachedAgentIdentity_.valid()) return {};

    std::lock_guard<std::mutex> lock(naanPipelineMtx_);
    const auto scoreBefore = agentScore_.snapshot();
    if (skippedQuarantine) {
        *skippedQuarantine = scoreBefore.quarantined;
    }

    uint32_t requestedBatch = scoreBefore.batchLimit;
    if (overrideMaxBatch > 0) {
        requestedBatch = std::min<uint32_t>(overrideMaxBatch, 500);
    }
    const uint32_t boundedBatch = std::min<uint32_t>(scoreBefore.batchLimit, requestedBatch);
    if (effectiveBatchLimit) {
        *effectiveBatchLimit = boundedBatch;
    }

    core::ToolInvocation drainCall;
    drainCall.toolName = "draft.submit_batch";
    drainCall.capability = core::AgentCapability::PROPOSE_KNOWLEDGE;
    drainCall.keys = {"atTimestamp", "maxBatch"};
    drainCall.payloadBytes = 32;
    drainCall.hasSideEffects = true;
    drainCall.explicitSideEffectFlag = true;
    if (!authorizeNaanTool(drainCall, "pipeline_drain")) {
        applyNaanScoreStep(0, 0, naanAbusePolicyPenalty_.load(), atTimestamp, "pipeline_drain_denied");
        naanLastPipelineTs_.store(atTimestamp);
        json payload;
        payload["result"] = "denied";
        payload["reason"] = "sandbox_denied";
        payload["requestedBatch"] = requestedBatch;
        payload["effectiveBatch"] = boundedBatch;
        appendNaanAuditEvent(atTimestamp, "pipeline_drain", "draft_queue", payload);
        return {};
    }

    if (scoreBefore.quarantined || boundedBatch == 0) {
        naanLastPipelineTs_.store(atTimestamp);
        json payload;
        payload["result"] = "skipped";
        payload["quarantined"] = scoreBefore.quarantined;
        payload["requestedBatch"] = requestedBatch;
        payload["effectiveBatch"] = boundedBatch;
        appendNaanAuditEvent(atTimestamp, "pipeline_drain", "draft_queue", payload);
        return {};
    }

    core::AgentSubmissionPipelineConfig cfg = agentSubmissionPipeline_.config();
    cfg.maxBatchSize = boundedBatch;
    core::AgentSubmissionPipeline pipeline(cfg);

    auto batch = pipeline.runDeterministicBatch(
        agentDraftQueue_, *poeV1_, attachedAgentIdentity_.privateKey, atTimestamp);

    uint32_t accepted = 0;
    uint32_t rejected = 0;
    uint32_t violations = 0;

    if (!batch.empty()) {
        naanPipelineRuns_.fetch_add(1);
        for (auto& item : batch) {
            if (item.submitId != crypto::Hash256{}) {
                item.acceptanceRewardCredited = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(item.submitId)) : false;
            }
            if (item.action == "approved") {
                naanPipelineApproved_.fetch_add(1);
                accepted += 1;
            } else if (item.action == "submitted") {
                naanPipelineSubmitted_.fetch_add(1);
                accepted += 1;
            } else if (item.action == "rejected") {
                naanPipelineRejected_.fetch_add(1);
                rejected += 1;
            }
        }
        violations += classifyNaanBatchViolations(batch);
        naanLastActionTs_.store(atTimestamp);
    }

    applyNaanScoreStep(accepted, rejected, violations, atTimestamp, "pipeline_drain");
    naanLastPipelineTs_.store(atTimestamp);

    uint64_t prunedSubmitted = 0;
    {
        const int64_t keepRaw = utils::Config::instance().getInt64("agent.retention.max_submitted_drafts", 0);
        if (keepRaw > 0) {
            uint32_t keep = static_cast<uint32_t>(std::min<int64_t>(keepRaw, 1000000));
            prunedSubmitted = agentDraftQueue_.pruneSubmitted(keep);
        }
    }

    json payload;
    payload["result"] = "ok";
    payload["accepted"] = accepted;
    payload["rejected"] = rejected;
    payload["violations"] = violations;
    payload["items"] = batch.size();
    payload["requestedBatch"] = requestedBatch;
    payload["effectiveBatch"] = boundedBatch;
    payload["prunedSubmittedDrafts"] = prunedSubmitted;
    payload["rewardVisibility"] = json::array();
    for (const auto& item : batch) {
        if (item.submitId == crypto::Hash256{}) continue;
        json reward;
        reward["draftId"] = crypto::toHex(item.draftId);
        reward["submitId"] = crypto::toHex(item.submitId);
        reward["expectedAcceptanceRewardAtoms"] = item.expectedAcceptanceRewardAtoms;
        reward["acceptanceRewardCredited"] = item.acceptanceRewardCredited;
        payload["rewardVisibility"].push_back(std::move(reward));
    }
    appendNaanAuditEvent(atTimestamp, "pipeline_drain", "draft_queue", payload);
    return batch;
}

core::poe_v1::ContentType inferDraftContentTypeForPoe(const core::AgentDraftProposal& proposal) const {
    if (proposal.title.rfind("CODE:", 0) == 0 || proposal.title.rfind("code:", 0) == 0) {
        return core::poe_v1::ContentType::CODE;
    }
    if (proposal.body.find("\nQ:") != std::string::npos && proposal.body.find("\nA:") != std::string::npos) {
        return core::poe_v1::ContentType::QA;
    }
    if (proposal.body.rfind("```", 0) == 0) {
        return core::poe_v1::ContentType::CODE;
    }
    return core::poe_v1::ContentType::TEXT;
}

bool findPoePowNonceForDraft(const core::AgentDraftProposal& proposal,
                             uint64_t startNonce,
                             uint64_t maxAttempts,
                             uint64_t* outNonce) const {
    if (!outNonce) return false;
    if (proposal.title.empty() || proposal.body.empty()) return false;

    core::poe_v1::KnowledgeEntryV1 entry;
    entry.version = 1;
    entry.timestamp = proposal.createdAt;
    entry.authorPubKey = proposal.author;
    entry.contentType = inferDraftContentTypeForPoe(proposal);
    entry.title = proposal.title;
    entry.body = proposal.body;
    entry.citations = proposal.citations;
    entry.powBits = proposal.powBits;

    crypto::Hash256 cid = entry.contentId();
    std::array<uint8_t, crypto::SHA256_SIZE + 8> buf{};
    std::memcpy(buf.data(), cid.data(), crypto::SHA256_SIZE);

    uint64_t limit = maxAttempts == 0 ? std::numeric_limits<uint64_t>::max() : maxAttempts;
    uint64_t nonce = startNonce;
    for (uint64_t i = 0; i < limit; ++i, ++nonce) {
        for (int b = 0; b < 8; ++b) {
            buf[crypto::SHA256_SIZE + static_cast<size_t>(b)] =
                static_cast<uint8_t>((nonce >> (8 * b)) & 0xFF);
        }
        crypto::Hash256 sid = crypto::sha256(buf.data(), buf.size());
        if (core::poe_v1::hasLeadingZeroBits(sid, proposal.powBits)) {
            *outNonce = nonce;
            return true;
        }
    }

    return false;
}

bool initNaanCoordination() {
    bool expected = false;
    if (!naanRuntimeInitialized_.compare_exchange_strong(expected, true)) {
        utils::Logger::error("NAAN runtime already initialized (single-instance guard)");
        return false;
    }

    auto failInit = [&](const std::string& message) {
        utils::Logger::error(message);
        naanRuntimeInitialized_.store(false);
        return false;
    };

    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    naanRuntimeStartedAt_.store(now);
    naanRuntimeCrashStatePath_ = config_.dataDir + "/naan/runtime.state";
    std::string crashLoadReason;
    if (!naanRuntimeSupervisor_.loadCrashState(naanRuntimeCrashStatePath_, &crashLoadReason)) {
        return failInit("Failed to load NAAN runtime crash state: " + crashLoadReason);
    }

    std::error_code naanDirEc;
    std::filesystem::create_directories(config_.dataDir + "/naan", naanDirEc);
    if (naanDirEc) {
        return failInit("Failed to create NAAN workspace directory");
    }

    if (!configureNaanStorage()) {
        return failInit("Failed to initialize NAAN storage namespace");
    }

    configureNaanRuntimeSandbox();
    if (!configureNaanTaskScheduler()) {
        return failInit("Failed to initialize NAAN deterministic task scheduler");
    }
    configureNaanScorePolicy();
    configureNaanAdaptiveScheduler();

    std::string scoreLoadReason;
    if (!loadNaanScoreState(&scoreLoadReason)) {
        return failInit("Failed to initialize NAAN score state: " + scoreLoadReason);
    }

    configureNaanConnectorAbuseGuard();
    configureNaanSubmissionPipeline();

    {
        auto& cfg = utils::Config::instance();
        core::CoordinationConfig coordCfg = agentCoordination_.config();
        int64_t pruneIntervalRaw = cfg.getInt64("naan.retention.prune_interval_seconds", 0);
        if (pruneIntervalRaw < 0) pruneIntervalRaw = 0;
        if (pruneIntervalRaw > 1000000) pruneIntervalRaw = 1000000;
        coordCfg.pruneIntervalSeconds = static_cast<uint32_t>(pruneIntervalRaw);

        int64_t maxArtifactsRaw = cfg.getInt64("agent.retention.max_observatory_history", 0);
        if (maxArtifactsRaw < 0) maxArtifactsRaw = 0;
        if (maxArtifactsRaw > 1000000) maxArtifactsRaw = 1000000;
        coordCfg.maxArtifactHistory = static_cast<uint32_t>(maxArtifactsRaw);
        agentCoordination_.setConfig(coordCfg);
    }
    refreshSecurityPolicyHashes("naan_runtime_init");
    refreshSecurityPolicyHashes("naan_init");

    if (crashLoadReason == "not_found") {
        (void)persistNaanCrashState("startup_seed");
    }
    if (scoreLoadReason == "not_found") {
        (void)persistNaanScoreState("startup_seed");
    }

    core::RoomConfig roomCfg;
    {
        auto& cfg = utils::Config::instance();
        int64_t maxMessagesRaw = cfg.getInt64("agent.retention.room.max_messages", 0);
        if (maxMessagesRaw < 0) maxMessagesRaw = 0;
        if (maxMessagesRaw > 1000000) maxMessagesRaw = 1000000;
        roomCfg.maxMessages = static_cast<uint32_t>(maxMessagesRaw);

        int64_t retentionRaw = cfg.getInt64("agent.retention.room.seconds", 0);
        if (retentionRaw < 0) retentionRaw = 0;
        if (retentionRaw > 315576000) retentionRaw = 315576000;
        roomCfg.retentionSeconds = static_cast<uint32_t>(retentionRaw);

        int64_t payloadRaw = cfg.getInt64("naan.rooms.max_payload_bytes", 8192);
        if (payloadRaw < 512) payloadRaw = 512;
        if (payloadRaw > 1048576) payloadRaw = 1048576;
        roomCfg.maxPayloadBytes = static_cast<uint32_t>(payloadRaw);
    }

    const std::array<std::pair<const char*, core::RoomType>, 4> defaultRooms = {{
        {"tasks/main", core::RoomType::TASKS},
        {"reviews/main", core::RoomType::REVIEWS},
        {"disputes/main", core::RoomType::DISPUTES},
        {"alerts/main", core::RoomType::ALERTS}
    }};

    for (const auto& room : defaultRooms) {
        if (!agentCoordination_.hasRoom(room.first)) {
            if (!agentCoordination_.createRoom(room.first, room.second, roomCfg)) {
                return failInit(std::string("Failed to initialize NAAN room: ") + room.first);
            }
        }
    }

    auto pathGate = agentRuntimeSandbox_.authorizePath(
        core::AgentCapability::PROPOSE_KNOWLEDGE,
        core::PathAccessMode::WRITE,
        config_.dataDir + "/naan/startup_draft.json",
        true
    );
    if (pathGate != core::RuntimeActionResult::ALLOWED) {
        return failInit("NAAN sandbox path policy denied startup workspace: " + core::runtimeActionResultToString(pathGate));
    }

    std::vector<uint8_t> seedMaterial;
    const std::string tag = "synapsenet:naan:agent:v1";
    seedMaterial.insert(seedMaterial.end(), tag.begin(), tag.end());

    if (keys_ && keys_->isValid()) {
        auto pub = keys_->getPublicKey();
        seedMaterial.insert(seedMaterial.end(), pub.begin(), pub.end());
    } else {
        seedMaterial.insert(seedMaterial.end(), config_.dataDir.begin(), config_.dataDir.end());
    }

    auto seed = crypto::sha256(seedMaterial.data(), seedMaterial.size());
    attachedAgentIdentity_ = core::AgentIdentity::fromSeed(seed);
    if (!attachedAgentIdentity_.valid()) {
        return failInit("Failed to initialize NAAN attached agent identity");
    }

    recoverNaanIndexesAndConsistency(now, "startup");

    json startup;
    startup["event"] = "attached_agent_started";
    startup["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
    startup["nodeAddress"] = address_;
    startup["mode"] = "always_on";
    startup["startedAt"] = now;
    startup["pid"] = static_cast<uint64_t>(::getpid());
    if (!sanitizeNaanPayload(&startup, "startup_alert_payload", now)) {
        return failInit("Failed to sanitize startup alert payload");
    }
    const std::string startupText = startup.dump();

    core::ToolInvocation startupAlertCall;
    startupAlertCall.toolName = "observatory.post";
    startupAlertCall.capability = core::AgentCapability::READ_NETWORK;
    startupAlertCall.keys = {"room", "kind", "payload"};
    startupAlertCall.payloadBytes = static_cast<uint32_t>(startupText.size());
    startupAlertCall.hasSideEffects = true;
    startupAlertCall.explicitSideEffectFlag = true;

    if (authorizeNaanTool(startupAlertCall, "startup_alert") &&
        agentCoordination_.postToRoom("alerts/main", attachedAgentIdentity_, core::RoomMessageType::ALERT, startupText, now)) {
            naanLastActionTs_.store(now);
            appendNaanAuditEvent(now, "observatory_post", "alerts/main", startup);
    } else {
        utils::Logger::warn("NAAN startup alert was blocked or could not be published");
    }

    core::AgentDraftProposal startupDraft;
    startupDraft.createdAt = now;
    startupDraft.author = attachedAgentIdentity_.id;
    startupDraft.title = "NAAN startup report";
    startupDraft.body = startupText;
    const auto poeCfg = poeV1_ ? poeV1_->getConfig() : core::PoeV1Config{};
    startupDraft.powBits = poeCfg.powBits;
    uint64_t powNonce = 0;
    if (!findPoePowNonceForDraft(startupDraft, now, poeCfg.powMaxAttempts, &powNonce)) {
        return failInit("Failed to compute PoE v1 PoW for NAAN startup draft");
    }
    startupDraft.powNonce = powNonce;
    startupDraft.signature = crypto::sign(startupDraft.signatureHash(), attachedAgentIdentity_.privateKey);
    std::string draftReason;
    core::ToolInvocation startupDraftCall;
    startupDraftCall.toolName = "draft.enqueue";
    startupDraftCall.capability = core::AgentCapability::PROPOSE_KNOWLEDGE;
    startupDraftCall.keys = {"title", "body", "powBits", "powNonce"};
    startupDraftCall.payloadBytes = static_cast<uint32_t>(startupDraft.title.size() + startupDraft.body.size());
    startupDraftCall.hasSideEffects = true;
    startupDraftCall.explicitSideEffectFlag = true;

    if (authorizeNaanTool(startupDraftCall, "startup_draft") && agentDraftQueue_.enqueue(startupDraft, &draftReason)) {
        naanLastDraftTs_.store(now);
        json payload;
        payload["result"] = "accepted";
        payload["draftId"] = crypto::toHex(startupDraft.draftId());
        payload["reason"] = "accepted";
        appendNaanAuditEvent(now, "draft_enqueue", crypto::toHex(startupDraft.draftId()), payload);
    } else {
        if (draftReason.empty()) draftReason = "sandbox_denied";
        utils::Logger::warn("NAAN startup draft rejected: " + draftReason);
        json payload;
        payload["result"] = "rejected";
        payload["draftId"] = crypto::toHex(startupDraft.draftId());
        payload["reason"] = draftReason;
        appendNaanAuditEvent(now, "draft_enqueue", crypto::toHex(startupDraft.draftId()), payload);
    }

    naanLastHeartbeatTs_.store(now);
    const auto st = currentNaanFailoverState(now);
    utils::Logger::info("NAAN runtime state: " + core::failoverStateToString(st));
    return true;
}

bool runNaanResearchTask(uint64_t now, const core::AgentAdaptiveSchedule& schedule) {
    auto trimCopy = [](const std::string& value) {
        size_t start = value.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return std::string{};
        size_t end = value.find_last_not_of(" \t\r\n");
        return value.substr(start, end - start + 1);
    };
    auto lowerCopy = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    };
    auto queryTypeToString = [](web::QueryType type) {
        switch (type) {
            case web::QueryType::CLEARNET: return "clearnet";
            case web::QueryType::DARKNET: return "darknet";
            case web::QueryType::BOTH: return "both";
            case web::QueryType::KNOWLEDGE_NETWORK: return "knowledge_network";
            case web::QueryType::DIRECT_LINK: return "direct_link";
        }
        return "both";
    };
    auto truncateCopy = [](const std::string& value, size_t limit) {
        if (value.size() <= limit) return value;
        return value.substr(0, limit);
    };

    const bool subsystemReady = ensureWebSubsystem();
    web::WebSearch* webSearch = nullptr;
    web::AIWrapper* webAi = nullptr;
    web::QueryDetector* webDetector = nullptr;
    web::SearchConfig cfg = web::defaultSearchConfig();
    if (subsystemReady) {
        std::lock_guard<std::mutex> lock(webMtx_);
        if (webSearch_) {
            webSearch = webSearch_.get();
            webAi = webAi_.get();
            webDetector = webDetector_.get();
            cfg = webSearch_->getConfig();
        }
    }

    std::vector<std::string> queries;
    for (const auto& raw : cfg.naanAutoSearchQueries) {
        std::string q = trimCopy(raw);
        if (!q.empty()) queries.push_back(q);
    }
    if (queries.empty()) {
        queries = {
            "latest space engineering research",
            "latest ai research papers",
            "open source systems engineering best practices"
        };
    }

    const uint64_t tick = naanTickCount_.load();
    const uint64_t entropy = static_cast<uint64_t>(attachedAgentIdentity_.id[0]) ^
                             (static_cast<uint64_t>(attachedAgentIdentity_.id[7]) << 8) ^
                             (static_cast<uint64_t>(attachedAgentIdentity_.id[15]) << 16);
    const size_t queryIndex = queries.empty() ? 0 : static_cast<size_t>((tick + entropy) % queries.size());
    std::string selectedQuery = queries.empty() ? std::string{} : queries[queryIndex];

    const auto route = refreshTorRoutePolicy(true);
    const bool torRequired = agentTorRequired_.load();
    const bool torReachable = agentTorReachable_.load();
    const bool torReadyForWeb = agentTorWebReady_.load();
    const bool forceTorMode = cfg.naanForceTorMode || torRequired;

    std::string mode = lowerCopy(trimCopy(cfg.naanAutoSearchMode));
    if (mode != "clearnet" && mode != "darknet" && mode != "both" && mode != "auto") {
        mode = "both";
    }

    if (cfg.routeClearnetThroughTor || forceTorMode) {
        if (cfg.tor.socksHost.empty()) cfg.tor.socksHost = configuredTorSocksHost();
        if (cfg.tor.socksPort == 0) cfg.tor.socksPort = configuredTorSocksPort();
        if (cfg.tor.socksPort == 0) cfg.tor.socksPort = 9050;
    }

    if (forceTorMode) {
        cfg.routeClearnetThroughTor = true;
        cfg.enableClearnet = torReachable && route.allowWebClearnet;
        cfg.enableDarknet = torReachable && route.allowWebOnion;
    }

    web::QueryType queryType = web::QueryType::BOTH;
    if (mode == "clearnet") {
        queryType = web::QueryType::CLEARNET;
    } else if (mode == "darknet") {
        queryType = web::QueryType::DARKNET;
    } else if (mode == "auto" && webDetector) {
        auto analysis = webDetector->analyze(selectedQuery);
        queryType = analysis.type;
        if (queryType == web::QueryType::DIRECT_LINK || queryType == web::QueryType::KNOWLEDGE_NETWORK) {
            queryType = web::QueryType::BOTH;
        }
    } else {
        queryType = web::QueryType::BOTH;
    }

    if (queryType == web::QueryType::BOTH) {
        if (!cfg.enableClearnet && cfg.enableDarknet) queryType = web::QueryType::DARKNET;
        if (!cfg.enableDarknet && cfg.enableClearnet) queryType = web::QueryType::CLEARNET;
    } else if (queryType == web::QueryType::CLEARNET && !cfg.enableClearnet && cfg.enableDarknet) {
        queryType = web::QueryType::DARKNET;
    } else if (queryType == web::QueryType::DARKNET && !cfg.enableDarknet && cfg.enableClearnet) {
        queryType = web::QueryType::CLEARNET;
    }

    const uint32_t maxResults = std::max<uint32_t>(1, std::min<uint32_t>(cfg.naanAutoSearchMaxResults, 32));
    std::vector<web::SearchResult> results;
    uint64_t clearnetResults = 0;
    uint64_t onionResults = 0;
    std::string topSitesSummary;
    std::string context;
    std::string skipReason;
    std::string searchError;

    if (!subsystemReady || !webSearch || !cfg.naanAutoSearchEnabled) {
        skipReason = !cfg.naanAutoSearchEnabled ? "auto_search_disabled" : "web_subsystem_unavailable";
    } else if (selectedQuery.empty()) {
        skipReason = "empty_query";
    } else if (forceTorMode && torRequired && !torReadyForWeb) {
        skipReason = torReachable ? "tor_bootstrap_incomplete" : "tor_socks_unreachable";
    } else if (!cfg.enableClearnet && !cfg.enableDarknet) {
        skipReason = forceTorMode ? "tor_route_unavailable" : "search_routes_disabled";
    } else {
        {
            std::lock_guard<std::mutex> lock(webMtx_);
            if (!webSearch_) {
                skipReason = "web_subsystem_unavailable";
            } else {
                webSearch_->setConfig(cfg);
                webSearch = webSearch_.get();
                webAi = webAi_.get();
            }
        }
        if (skipReason.empty() && webSearch) {
            try {
                results = webSearch->search(selectedQuery, queryType);
                if (results.size() > maxResults) {
                    results.resize(maxResults);
                }
                for (const auto& item : results) {
                    if (item.isOnion) onionResults += 1;
                    else clearnetResults += 1;
                }
                {
                    std::vector<std::string> topSites;
                    std::unordered_set<std::string> seenSites;
                    for (const auto& item : results) {
                        std::string host = trimCopy(item.domain);
                        if (host.empty()) host = trimCopy(web::extractDomain(item.url));
                        if (host.empty()) continue;
                        if (!seenSites.insert(host).second) continue;
                        topSites.push_back(host);
                        if (topSites.size() >= 3) break;
                    }
                    if (!topSites.empty()) {
                        std::ostringstream joined;
                        for (size_t i = 0; i < topSites.size(); ++i) {
                            if (i > 0) joined << ", ";
                            joined << topSites[i];
                        }
                        topSitesSummary = joined.str();
                    }
                }
                if (webAi && !results.empty()) {
                    context = webAi->injectContext(selectedQuery, results);
                }
            } catch (const std::exception& e) {
                searchError = e.what();
            } catch (...) {
                searchError = "unknown_error";
            }
        }
    }
    if (forceTorMode &&
        (skipReason == "tor_route_unavailable" ||
         skipReason == "tor_bootstrap_incomplete" ||
         skipReason == "tor_socks_unreachable")) {
        naanWebFailClosedSkips_.fetch_add(1);
    }

    json payload;
    payload["event"] = "attached_agent_research_auto_search";
    payload["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
    payload["tick"] = tick;
    payload["state"] = core::schedulingStateToString(schedule.state);
    payload["observatoryMessages"] = agentCoordination_.totalMessages();
    payload["autoSearchEnabled"] = cfg.naanAutoSearchEnabled;
    payload["mode"] = mode;
    payload["query"] = selectedQuery;
    payload["queryIndex"] = static_cast<uint64_t>(queryIndex);
    payload["queryType"] = queryTypeToString(queryType);
    payload["maxResults"] = maxResults;
    payload["torRequired"] = torRequired;
    payload["torReachable"] = torReachable;
    payload["torReadyForWeb"] = torReadyForWeb;
    payload["forceTorMode"] = forceTorMode;
    payload["routeClearnetThroughTor"] = cfg.routeClearnetThroughTor;
    payload["enableClearnet"] = cfg.enableClearnet;
    payload["enableDarknet"] = cfg.enableDarknet;
    payload["resultCount"] = results.size();
    payload["clearnetResults"] = clearnetResults;
    payload["onionResults"] = onionResults;
    if (!skipReason.empty()) payload["skipReason"] = skipReason;
    if (!searchError.empty()) payload["error"] = searchError;
    if (!context.empty()) {
        payload["context"] = truncateCopy(context, 4096);
    }
    payload["results"] = json::array();
    for (const auto& result : results) {
        json item;
        item["title"] = truncateCopy(result.title, 160);
        item["url"] = truncateCopy(result.url, 512);
        item["domain"] = truncateCopy(result.domain, 120);
        item["onion"] = result.isOnion;
        item["relevance"] = result.relevanceScore;
        payload["results"].push_back(std::move(item));
    }

    if (!sanitizeNaanPayload(&payload, "research_tick_payload", now)) {
        naanLastResearchTs_.store(now);
        return false;
    }
    const std::string payloadText = payload.dump();

    core::ToolInvocation researchCall;
    researchCall.toolName = "observatory.post";
    researchCall.capability = core::AgentCapability::READ_NETWORK;
    researchCall.keys = {"room", "kind", "payload"};
    researchCall.payloadBytes = static_cast<uint32_t>(payloadText.size());
    researchCall.hasSideEffects = true;
    researchCall.explicitSideEffectFlag = true;

    bool posted = false;
    if (authorizeNaanTool(researchCall, "research_tick") &&
        agentCoordination_.postToRoom("tasks/main", attachedAgentIdentity_, core::RoomMessageType::TASK, payloadText, now)) {
        posted = true;
        naanLastActionTs_.store(now);
        appendNaanAuditEvent(now, "observatory_post", "tasks/main", payload);
    }
    {
        std::lock_guard<std::mutex> lock(naanWebResearchMtx_);
        naanWebResearchSnapshot_.lastSearchAt = now;
        naanWebResearchSnapshot_.query = truncateCopy(selectedQuery, 256);
        naanWebResearchSnapshot_.queryType = queryTypeToString(queryType);
        naanWebResearchSnapshot_.resultCount = static_cast<uint64_t>(results.size());
        naanWebResearchSnapshot_.clearnetResults = clearnetResults;
        naanWebResearchSnapshot_.onionResults = onionResults;
        naanWebResearchSnapshot_.topSites = topSitesSummary;
        naanWebResearchSnapshot_.saved = posted;
        naanWebResearchSnapshot_.skipReason = skipReason;
        naanWebResearchSnapshot_.error = searchError;
    }
    naanLastResearchTs_.store(now);
    return posted;
}

bool runNaanVerifyTask(uint64_t now, const core::AgentAdaptiveSchedule& schedule) {
    (void)schedule;
    if (!poeV1_) {
        naanLastVerifyTs_.store(now);
        return false;
    }

    std::vector<core::AgentDraftRecord> records;
    auto queued = agentDraftQueue_.listByStatus(core::DraftStatus::QUEUED, 1000000);
    auto review = agentDraftQueue_.listByStatus(core::DraftStatus::REVIEW_REQUIRED, 1000000);
    auto approved = agentDraftQueue_.listByStatus(core::DraftStatus::APPROVED, 1000000);
    records.reserve(queued.size() + review.size() + approved.size());
    records.insert(records.end(), queued.begin(), queued.end());
    records.insert(records.end(), review.begin(), review.end());
    records.insert(records.end(), approved.begin(), approved.end());
    std::sort(records.begin(), records.end(), [](const core::AgentDraftRecord& a, const core::AgentDraftRecord& b) {
        const std::string ah = crypto::toHex(a.proposal.draftId());
        const std::string bh = crypto::toHex(b.proposal.draftId());
        if (ah != bh) return ah < bh;
        return a.proposal.createdAt < b.proposal.createdAt;
    });

    if (records.empty()) {
        naanLastVerifyTs_.store(now);
        return false;
    }

    auto dry = agentSubmissionPipeline_.dryRun(records.front(), attachedAgentIdentity_.privateKey, *poeV1_);
    std::string reviewStoreReason;
    const bool reviewStored = agentDraftQueue_.upsertReview(
        dry.draftId,
        attachedAgentIdentity_.id,
        dry.ok,
        now,
        dry.reason,
        &reviewStoreReason
    );
    uint32_t reviewCount = 0;
    uint32_t approvalCount = 0;
    auto reviewedRecord = agentDraftQueue_.get(dry.draftId);
    if (reviewedRecord.has_value()) {
        reviewCount = static_cast<uint32_t>(reviewedRecord->reviews.size());
        for (const auto& review : reviewedRecord->reviews) {
            if (review.approved) approvalCount += 1;
        }
    }

    json reviewPayload;
    reviewPayload["event"] = "attached_agent_verify_tick";
    reviewPayload["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
    reviewPayload["draftId"] = crypto::toHex(dry.draftId);
    reviewPayload["ok"] = dry.ok;
    reviewPayload["reason"] = dry.reason;
    reviewPayload["nextStatus"] = dry.nextStatus;
    reviewPayload["reviewRecorded"] = reviewStored;
    reviewPayload["reviewRecordReason"] = reviewStoreReason;
    reviewPayload["reviewCount"] = reviewCount;
    reviewPayload["reviewApprovedCount"] = approvalCount;
    if (!sanitizeNaanPayload(&reviewPayload, "verify_tick_payload", now)) {
        naanLastVerifyTs_.store(now);
        return false;
    }
    const std::string reviewPayloadText = reviewPayload.dump();

    appendNaanAuditEvent(now, "draft_review_upsert", crypto::toHex(dry.draftId), reviewPayload);

    core::ToolInvocation verifyCall;
    verifyCall.toolName = "observatory.post";
    verifyCall.capability = core::AgentCapability::READ_NETWORK;
    verifyCall.keys = {"room", "kind", "payload"};
    verifyCall.payloadBytes = static_cast<uint32_t>(reviewPayloadText.size());
    verifyCall.hasSideEffects = true;
    verifyCall.explicitSideEffectFlag = true;

    bool posted = false;
    if (authorizeNaanTool(verifyCall, "verify_tick") &&
        agentCoordination_.postToRoom("reviews/main", attachedAgentIdentity_, core::RoomMessageType::REVIEW, reviewPayloadText, now)) {
        posted = true;
        naanLastActionTs_.store(now);
        appendNaanAuditEvent(now, "observatory_post", "reviews/main", reviewPayload);
    }
    naanLastVerifyTs_.store(now);
    return posted;
}

bool runNaanReviewTask(uint64_t now, const core::AgentAdaptiveSchedule& schedule) {
    json heartbeat;
    heartbeat["event"] = "attached_agent_heartbeat";
    heartbeat["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
    heartbeat["tick"] = naanTickCount_.load();
    heartbeat["state"] = core::schedulingStateToString(schedule.state);
    heartbeat["failover"] = core::failoverStateToString(currentNaanFailoverState(now));
    if (!sanitizeNaanPayload(&heartbeat, "heartbeat_payload", now)) {
        naanLastReviewTs_.store(now);
        return false;
    }
    const std::string heartbeatText = heartbeat.dump();

    core::ToolInvocation heartbeatCall;
    heartbeatCall.toolName = "observatory.post";
    heartbeatCall.capability = core::AgentCapability::READ_NETWORK;
    heartbeatCall.keys = {"room", "kind", "payload"};
    heartbeatCall.payloadBytes = static_cast<uint32_t>(heartbeatText.size());
    heartbeatCall.hasSideEffects = true;
    heartbeatCall.explicitSideEffectFlag = true;

    bool posted = false;
    if (authorizeNaanTool(heartbeatCall, "heartbeat_alert") &&
        agentCoordination_.postToRoom("alerts/main", attachedAgentIdentity_, core::RoomMessageType::ALERT, heartbeatText, now)) {
        posted = true;
        naanLastActionTs_.store(now);
        naanLastHeartbeatTs_.store(now);
        appendNaanAuditEvent(now, "observatory_post", "alerts/main", heartbeat);
    }
    naanLastReviewTs_.store(now);
    return posted;
}

bool runNaanDraftTask(uint64_t now, const core::AgentAdaptiveSchedule& schedule) {
    json draftBody;
    draftBody["event"] = "periodic_research_snapshot";
    draftBody["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
    draftBody["tick"] = naanTickCount_.load();
    draftBody["observatoryMessages"] = agentCoordination_.totalMessages();
    draftBody["schedulerState"] = core::schedulingStateToString(schedule.state);
    if (!sanitizeNaanPayload(&draftBody, "periodic_draft_payload", now)) {
        return false;
    }
    const std::string draftBodyText = draftBody.dump();

    core::AgentDraftProposal proposal;
    proposal.createdAt = now;
    proposal.author = attachedAgentIdentity_.id;
    proposal.title = "NAAN periodic research draft";
    proposal.body = draftBodyText;
    const auto poeCfg = poeV1_ ? poeV1_->getConfig() : core::PoeV1Config{};
    proposal.powBits = poeCfg.powBits;
    uint64_t powNonce = 0;
    if (!findPoePowNonceForDraft(proposal, now, poeCfg.powMaxAttempts, &powNonce)) {
        utils::Logger::warn("NAAN periodic draft PoW failed");
        return false;
    }
    proposal.powNonce = powNonce;
    proposal.signature = crypto::sign(proposal.signatureHash(), attachedAgentIdentity_.privateKey);

    std::string reason;
    core::ToolInvocation periodicDraftCall;
    periodicDraftCall.toolName = "draft.enqueue";
    periodicDraftCall.capability = core::AgentCapability::PROPOSE_KNOWLEDGE;
    periodicDraftCall.keys = {"title", "body", "powBits", "powNonce"};
    periodicDraftCall.payloadBytes = static_cast<uint32_t>(proposal.title.size() + proposal.body.size());
    periodicDraftCall.hasSideEffects = true;
    periodicDraftCall.explicitSideEffectFlag = true;

    bool posted = false;
    if (authorizeNaanTool(periodicDraftCall, "periodic_draft") && agentDraftQueue_.enqueue(proposal, &reason)) {
        posted = true;
        naanLastDraftTs_.store(now);
        naanLastActionTs_.store(now);
        json payload;
        payload["result"] = "accepted";
        payload["draftId"] = crypto::toHex(proposal.draftId());
        payload["reason"] = "accepted";
        appendNaanAuditEvent(now, "draft_enqueue", crypto::toHex(proposal.draftId()), payload);
    } else if (reason != "queue_full") {
        if (reason.empty()) reason = "sandbox_denied";
        utils::Logger::warn("NAAN periodic draft rejected: " + reason);
        naanLastDraftTs_.store(now);
        json payload;
        payload["result"] = "rejected";
        payload["draftId"] = crypto::toHex(proposal.draftId());
        payload["reason"] = reason;
        appendNaanAuditEvent(now, "draft_enqueue", crypto::toHex(proposal.draftId()), payload);
    }
    return posted;
}

bool runNaanSubmitTask(uint64_t now, const core::AgentAdaptiveSchedule& schedule) {
    (void)schedule;
    if (!poeV1_) return false;
    auto batch = runNaanPipelineDrain(now);
    return !batch.empty();
}

void tickNaanCoordination(uint64_t now) {
    if (!attachedAgentIdentity_.valid()) return;
    const uint64_t tickValue = naanTickCount_.fetch_add(1) + 1;
    agentCoordination_.periodicMaintenance(now);
    applyNaanScoreDecayTick(now);
    applyNaanConnectorAbuseAutoAction(now, tickValue);
    if (tickValue % 60 == 0) {
        recoverNaanIndexesAndConsistency(now, "periodic_tick");
    }

    const auto schedule = currentNaanSchedule();
    const uint64_t lastResearch = naanLastResearchTs_.load();
    const uint64_t lastVerify = naanLastVerifyTs_.load();
    const uint64_t lastReview = naanLastReviewTs_.load();
    const uint64_t lastDraft = naanLastDraftTs_.load();
    const uint64_t lastPipeline = naanLastPipelineTs_.load();

    const uint32_t researchInterval = std::max<uint32_t>(30, schedule.draftIntervalSeconds / 2);
    const uint32_t verifyInterval = std::max<uint32_t>(10, schedule.pipelineIntervalSeconds);

    const bool researchReady = (lastResearch == 0 || now >= lastResearch + researchInterval);
    const bool verifyReady = poeV1_ && hasPendingNaanDrafts() && (lastVerify == 0 || now >= lastVerify + verifyInterval);
    const bool reviewReady = (lastReview == 0 || now >= lastReview + schedule.heartbeatIntervalSeconds);
    const bool draftReady = (lastDraft == 0 || now >= lastDraft + schedule.draftIntervalSeconds);
    const bool submitReady = poeV1_ && (lastPipeline == 0 || now >= lastPipeline + schedule.pipelineIntervalSeconds);

    std::array<core::AgentTaskRequest, core::kAgentTaskClassCount> requests = {{
        {core::AgentTaskClass::RESEARCH, researchReady},
        {core::AgentTaskClass::VERIFY, verifyReady},
        {core::AgentTaskClass::REVIEW, reviewReady},
        {core::AgentTaskClass::DRAFT, draftReady},
        {core::AgentTaskClass::SUBMIT, submitReady}
    }};

    auto decision = naanTaskScheduler_.tick(requests);
    if (decision.scheduled) {
        switch (decision.taskClass) {
            case core::AgentTaskClass::RESEARCH:
                if (runNaanResearchTask(now, schedule)) naanTaskResearchRuns_.fetch_add(1);
                break;
            case core::AgentTaskClass::VERIFY:
                if (runNaanVerifyTask(now, schedule)) naanTaskVerifyRuns_.fetch_add(1);
                break;
            case core::AgentTaskClass::REVIEW:
                if (runNaanReviewTask(now, schedule)) naanTaskReviewRuns_.fetch_add(1);
                break;
            case core::AgentTaskClass::DRAFT:
                if (runNaanDraftTask(now, schedule)) naanTaskDraftRuns_.fetch_add(1);
                break;
            case core::AgentTaskClass::SUBMIT:
                if (runNaanSubmitTask(now, schedule)) naanTaskSubmitRuns_.fetch_add(1);
                break;
        }
    }

    // Keep NAAN auto-research cadence stable even when higher-priority queues
    // stay busy (submit/review/verify), so web crawling doesn't appear stuck.
    const bool scheduledResearch =
        decision.scheduled && decision.taskClass == core::AgentTaskClass::RESEARCH;
    if (researchReady && !scheduledResearch) {
        if (runNaanResearchTask(now, schedule)) naanTaskResearchRuns_.fetch_add(1);
    }

    if (decision.scheduled || (tickValue % 30 == 0)) {
        (void)persistNaanSchedulerState("tick");
    }
}

void tickNaanCoordinationSupervised(uint64_t now) {
    if (!naanRuntimeInitialized_.load()) return;

    if (naanRuntimeSupervisor_.inRecovery(now)) {
        naanRecoverySkips_.fetch_add(1);
        return;
    }

    const auto crashBefore = naanRuntimeSupervisor_.crashState();
    try {
        tickNaanCoordination(now);
        if (crashBefore.consecutiveCrashes > 0 || crashBefore.recoveryUntilTimestamp > 0) {
            naanRuntimeSupervisor_.markSuccess();
            (void)persistNaanCrashState("recovered");
        }
    } catch (const std::exception& e) {
        uint64_t backoff = naanRuntimeSupervisor_.markFailure(now);
        (void)persistNaanCrashState("failure");
        utils::Logger::error("NAAN runtime failure: " + std::string(e.what()) +
                             " (backoff=" + std::to_string(backoff) + "s)");
    } catch (...) {
        uint64_t backoff = naanRuntimeSupervisor_.markFailure(now);
        (void)persistNaanCrashState("failure_unknown");
        utils::Logger::error("NAAN runtime failure: unknown_exception"
                             " (backoff=" + std::to_string(backoff) + "s)");
    }
}

UpdateManifestAccept acceptUpdateManifest(const core::UpdateManifest& manifest, bool relay, std::string* reason = nullptr) {
    std::string verifyReason;
    if (!manifest.validateStrict(&verifyReason)) {
        if (reason) *reason = verifyReason;
        return UpdateManifestAccept::REJECTED;
    }

    std::string idHex = crypto::toHex(manifest.bundleId);
    bool inserted = false;
    {
        std::lock_guard<std::mutex> lock(invMtx_);
        auto it = updateManifestsById_.find(idHex);
        if (it != updateManifestsById_.end()) {
            knownUpdateBundles_.insert(idHex);
            if (reason) *reason = "duplicate";
            return UpdateManifestAccept::DUPLICATE;
        }
        updateManifestsById_[idHex] = manifest;
        knownUpdateBundles_.insert(idHex);
        inserted = true;
    }

    if (inserted && relay) {
        broadcastInv(synapse::InvType::UPDATE_BUNDLE, manifest.bundleId);
    }
    if (reason) *reason = "accepted";
    return UpdateManifestAccept::ACCEPTED;
}

uint64_t parseNgtAtomic(const std::string& value) const {
    if (value.empty()) {
        throw std::runtime_error("Empty amount");
    }
    std::string t = value;
    for (auto& c : t) {
        if (c == ',') c = '.';
    }
    size_t dot = t.find('.');
    std::string intPart = dot == std::string::npos ? t : t.substr(0, dot);
    std::string fracPart = dot == std::string::npos ? "" : t.substr(dot + 1);
    if (intPart.empty()) intPart = "0";
    if (fracPart.size() > 8) {
        throw std::runtime_error("Too many decimals");
    }
    unsigned __int128 iv = 0;
    for (char c : intPart) {
        if (c < '0' || c > '9') throw std::runtime_error("Invalid number");
        iv = iv * 10 + static_cast<unsigned>(c - '0');
    }
    unsigned __int128 fv = 0;
    for (char c : fracPart) {
        if (c < '0' || c > '9') throw std::runtime_error("Invalid number");
        fv = fv * 10 + static_cast<unsigned>(c - '0');
    }
    for (size_t i = fracPart.size(); i < 8; ++i) fv *= 10;
    unsigned __int128 total = iv * 100000000ULL + fv;
    if (total > std::numeric_limits<uint64_t>::max()) {
        throw std::runtime_error("Amount too large");
    }
    return static_cast<uint64_t>(total);
}

double atomsToNgt(uint64_t atoms) const {
    return static_cast<double>(atoms) / 100000000.0;
}

std::string addressFromPubKey(const crypto::PublicKey& pubKey) const {
    std::string hex = crypto::toHex(pubKey);
    if (hex.size() < 52) return {};
    return "ngt1" + hex.substr(0, 52);
}

uint64_t poeMinStakeAtoms() const {
    try {
        return parseNgtAtomic(config_.poeMinStake);
    } catch (...) {
        return 0;
    }
}

void updatePoeValidatorsFromStake() {
    if (!poeV1_ || !transfer_) return;
    if (config_.poeValidatorMode != "stake") return;

    crypto::PublicKey selfPub{};
    bool hasSelfPub = false;
    if (keys_ && keys_->isValid()) {
        auto pubV = keys_->getPublicKey();
        if (pubV.size() >= crypto::PUBLIC_KEY_SIZE) {
            std::memcpy(selfPub.data(), pubV.data(), selfPub.size());
            hasSelfPub = true;
        }
    }

    std::vector<crypto::PublicKey> candidates;
    candidates.reserve(256);

    auto addPk = [&](const crypto::PublicKey& pk) {
        if (std::all_of(pk.begin(), pk.end(), [](uint8_t b) { return b == 0; })) return;
        candidates.push_back(pk);
    };

    auto addValidatorHex = [&](const std::string& token) {
        std::string t = token;
        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
        if (t.empty()) return;

        if (t == "self") {
            if (hasSelfPub) addPk(selfPub);
            return;
        }

        if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
        auto bytes = crypto::fromHex(t);
        if (bytes.size() != crypto::PUBLIC_KEY_SIZE) return;
        crypto::PublicKey pk{};
        std::memcpy(pk.data(), bytes.data(), pk.size());
        addPk(pk);
    };

    if (!config_.poeValidators.empty()) {
        std::string raw = config_.poeValidators;
        for (char& c : raw) {
            if (c == ';') c = ',';
        }
        std::string cur;
        for (char c : raw) {
            if (c == ',') {
                addValidatorHex(cur);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        addValidatorHex(cur);
    }

    for (const auto& pk : poeV1_->getStaticValidators()) addPk(pk);

    for (const auto& sid : poeV1_->listEntryIds(0)) {
        auto e = poeV1_->getEntry(sid);
        if (e) addPk(e->authorPubKey);
    }
    for (const auto& vid : poeV1_->listVoteIds(0)) {
        auto v = poeV1_->getVoteById(vid);
        if (v) addPk(v->validatorPubKey);
    }

    std::sort(candidates.begin(), candidates.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    });
    candidates.erase(std::unique(candidates.begin(), candidates.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
        return a == b;
    }), candidates.end());

    if (candidates.empty() && hasSelfPub) candidates.push_back(selfPub);
    if (candidates.empty()) return;

    poeV1_->setStaticValidators(candidates);
    for (const auto& pk : candidates) {
        std::string addr = addressFromPubKey(pk);
        uint64_t bal = addr.empty() ? 0 : transfer_->getBalance(addr);
        poeV1_->setValidatorIdentity(pk, true);
        poeV1_->setValidatorStake(pk, bal);
    }
}

std::filesystem::path poeDbPath() const {
    std::filesystem::path path = std::filesystem::path(config_.dataDir) / "poe" / "poe.db";
    return path;
}

crypto::Hash256 rewardIdForAcceptance(const crypto::Hash256& submitId) {
    std::vector<uint8_t> buf;
    const std::string tag = "poe_v1_accept";
    buf.insert(buf.end(), tag.begin(), tag.end());
    buf.insert(buf.end(), submitId.begin(), submitId.end());
    return crypto::sha256(buf.data(), buf.size());
}

crypto::Hash256 rewardIdForEpoch(uint64_t epochId, const crypto::Hash256& contentId) {
    std::vector<uint8_t> buf;
    const std::string tag = "poe_v1_epoch";
    buf.insert(buf.end(), tag.begin(), tag.end());
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((epochId >> (8 * i)) & 0xFF));
    }
    buf.insert(buf.end(), contentId.begin(), contentId.end());
    return crypto::sha256(buf.data(), buf.size());
}

std::string handleRpcPoeSubmit(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string typeStr = params.value("type", "");
    std::string question = params.value("question", "");
    std::string answer = params.value("answer", "");
    std::string source = params.value("source", "");
    bool autoFinalize = params.value("auto_finalize", true);

    if (!poeV1_ || !transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
        throw std::runtime_error("PoE or wallet not ready");
    }

    auto lower = [](std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };

    core::poe_v1::ContentType type = core::poe_v1::ContentType::QA;
    if (!typeStr.empty()) {
        std::string t = lower(typeStr);
        if (t == "qa" || t == "qna") type = core::poe_v1::ContentType::QA;
        else if (t == "text") type = core::poe_v1::ContentType::TEXT;
        else if (t == "code" || t == "patch") type = core::poe_v1::ContentType::CODE;
        else if (t == "linklist" || t == "links") type = core::poe_v1::ContentType::LINKLIST;
        else if (t == "other") type = core::poe_v1::ContentType::OTHER;
        else throw std::runtime_error("unknown type");
    }

    std::vector<crypto::Hash256> citations;
    if (params.contains("citations")) {
        if (!params["citations"].is_array()) {
            throw std::runtime_error("citations must be array");
        }
        for (const auto& item : params["citations"]) {
            if (!item.is_string()) throw std::runtime_error("citation must be hex string");
            citations.push_back(parseHash256Hex(item.get<std::string>()));
        }
    }

    crypto::PrivateKey pk{};
    auto pkv = keys_->getPrivateKey();
    if (pkv.size() < pk.size()) {
        throw std::runtime_error("Invalid private key");
    }
    std::memcpy(pk.data(), pkv.data(), pk.size());

    std::string title;
    std::string body;
    if (type == core::poe_v1::ContentType::QA) {
        if (question.empty() || answer.empty()) {
            throw std::runtime_error("question and answer are required");
        }
        title = question;
        body = answer;
        if (!source.empty()) {
            body += "\nsource: " + source;
        }
    } else if (type == core::poe_v1::ContentType::CODE) {
        title = params.value("title", "");
        body = params.value("patch", "");
        if (body.empty()) body = params.value("body", "");
        if (title.empty() || body.empty()) {
            throw std::runtime_error("title and patch/body are required");
        }
    } else {
        title = params.value("title", "");
        body = params.value("body", "");
        if (title.empty() || body.empty()) {
            throw std::runtime_error("title and body are required");
        }
    }

    updatePoeValidatorsFromStake();
    auto submitRes = poeV1_->submit(type, title, body, citations, pk, autoFinalize);
    if (!submitRes.ok) {
        throw std::runtime_error("PoE submit failed: " + submitRes.error);
    }

    crypto::PublicKey authorPub = crypto::derivePublicKey(pk);
    std::string authorAddr = addressFromPubKey(authorPub);
    if (authorAddr.empty()) authorAddr = address_;

    uint64_t credited = 0;
    if (submitRes.finalized && submitRes.acceptanceReward > 0) {
        crypto::Hash256 rewardId = rewardIdForAcceptance(submitRes.submitId);
        if (transfer_->creditRewardDeterministic(authorAddr, rewardId, submitRes.acceptanceReward)) {
            credited = submitRes.acceptanceReward;
        }
    }

    {
        std::lock_guard<std::mutex> lock(invMtx_);
        knownPoeEntries_.insert(crypto::toHex(submitRes.submitId));
    }
    broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
    for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
        crypto::Hash256 vid = v.payloadHash();
        {
            std::lock_guard<std::mutex> lock(invMtx_);
                knownPoeVotes_.insert(crypto::toHex(vid));
        }
        broadcastInv(synapse::InvType::POE_VOTE, vid);
    }

    if (ledger_) {
        auto pub = keys_->getPublicKey();
        auto entry = poeV1_->getEntry(submitRes.submitId);
        if (entry) {
            core::Event ev{};
            ev.timestamp = entry->timestamp;
            ev.type = core::EventType::POE_ENTRY;
            ev.data = entry->serialize();
            if (pub.size() >= ev.author.size()) {
                std::memcpy(ev.author.data(), pub.data(), ev.author.size());
            }
            ledger_->append(ev);
        }

        for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
            core::Event ev{};
            ev.timestamp = std::time(nullptr);
            ev.type = core::EventType::POE_VOTE;
            ev.data = v.serialize();
            if (pub.size() >= ev.author.size()) {
                std::memcpy(ev.author.data(), pub.data(), ev.author.size());
            }
            ledger_->append(ev);
        }
    }

    json result;
    result["status"] = "ok";
    result["submitId"] = crypto::toHex(submitRes.submitId);
    result["contentId"] = crypto::toHex(submitRes.contentId);
    result["contentType"] = static_cast<int>(type);
    result["finalized"] = submitRes.finalized;
    result["acceptanceRewardAtoms"] = submitRes.acceptanceReward;
    result["acceptanceReward"] = atomsToNgt(submitRes.acceptanceReward);
    result["creditedAtoms"] = credited;
    result["credited"] = atomsToNgt(credited);

    return result.dump();
}

std::string handleRpcPoeSubmitCode(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    params["type"] = "code";
    if (!params.contains("body") && params.contains("patch")) {
        params["body"] = params["patch"];
    }
    return handleRpcPoeSubmit(params.dump());
}

std::string handleRpcPoeListCode(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    size_t limit = 25;
    if (params.contains("limit")) {
        limit = static_cast<size_t>(std::max(1, params.value("limit", 25)));
    }
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }

    json out = json::array();
    auto ids = poeV1_->listEntryIds(0);
    for (auto it = ids.rbegin(); it != ids.rend() && out.size() < limit; ++it) {
        auto e = poeV1_->getEntry(*it);
        if (!e) continue;
        if (e->contentType != core::poe_v1::ContentType::CODE) continue;
        json item;
        item["submitId"] = crypto::toHex(*it);
        item["contentId"] = crypto::toHex(e->contentId());
        item["timestamp"] = e->timestamp;
        item["title"] = e->title;
        item["finalized"] = poeV1_->isFinalized(*it);
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcPoeFetchCode(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("id", "");
    if (idHex.empty()) idHex = params.value("submitId", "");
    if (idHex.empty()) idHex = params.value("contentId", "");
    if (idHex.empty()) {
        throw std::runtime_error("id required");
    }
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }

    crypto::Hash256 id = parseHash256Hex(idHex);
    auto entry = poeV1_->getEntry(id);
    crypto::Hash256 submitId = id;
    if (!entry) {
        entry = poeV1_->getEntryByContentId(id);
        if (entry) submitId = entry->submitId();
    }
    if (!entry) {
        throw std::runtime_error("not_found");
    }
    if (entry->contentType != core::poe_v1::ContentType::CODE) {
        throw std::runtime_error("not_code_entry");
    }

    json out;
    out["submitId"] = crypto::toHex(submitId);
    out["contentId"] = crypto::toHex(entry->contentId());
    out["timestamp"] = entry->timestamp;
    out["authorPubKey"] = crypto::toHex(entry->authorPubKey);
    out["title"] = entry->title;
    out["patch"] = entry->body;
    json cites = json::array();
    for (const auto& c : entry->citations) cites.push_back(crypto::toHex(c));
    out["citations"] = cites;
    out["finalized"] = poeV1_->isFinalized(submitId);
    uint64_t expected = poeV1_->calculateAcceptanceReward(*entry);
    out["acceptanceRewardAtoms"] = expected;
    out["acceptanceReward"] = atomsToNgt(expected);
    return out.dump();
}

std::string handleRpcPoeVote(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!poeV1_ || !keys_ || !keys_->isValid()) {
        throw std::runtime_error("PoE or wallet not ready");
    }
    std::string submitHex = params.value("submitId", "");
    if (submitHex.empty()) {
        throw std::runtime_error("submitId required");
    }
    crypto::Hash256 submitId = parseHash256Hex(submitHex);

    crypto::PrivateKey pk{};
    auto pkv = keys_->getPrivateKey();
    if (pkv.size() < pk.size()) {
        throw std::runtime_error("Invalid private key");
    }
    std::memcpy(pk.data(), pkv.data(), pk.size());

    core::poe_v1::ValidationVoteV1 vote;
    vote.version = 1;
    vote.submitId = submitId;
    vote.prevBlockHash = poeV1_->chainSeed();
    vote.flags = params.value("flags", 0);
    if (params.contains("scores")) {
        const auto& scores = params["scores"];
        if (!scores.is_array() || scores.size() != 3) {
            throw std::runtime_error("scores must be array of 3 integers");
        }
        for (size_t i = 0; i < 3; ++i) {
            vote.scores[i] = static_cast<uint16_t>(scores[i].get<int>());
        }
    } else {
        vote.scores = {100, 100, 100};
    }
    core::poe_v1::signValidationVoteV1(vote, pk);
    bool added = poeV1_->addVote(vote);

    crypto::Hash256 voteId = vote.payloadHash();
    if (added) {
        {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeVotes_.insert(crypto::toHex(voteId));
        }
        broadcastInv(synapse::InvType::POE_VOTE, voteId);

        if (ledger_) {
            core::Event ev{};
            ev.timestamp = std::time(nullptr);
            ev.type = core::EventType::POE_VOTE;
            ev.data = vote.serialize();
            auto pub = keys_->getPublicKey();
            if (pub.size() >= ev.author.size()) {
                std::memcpy(ev.author.data(), pub.data(), ev.author.size());
            }
            ledger_->append(ev);
        }
    }

    uint64_t credited = maybeCreditAcceptanceReward(submitId);

    json result;
    result["status"] = added ? "vote_added" : "vote_duplicate";
    result["added"] = added;
    result["voteId"] = crypto::toHex(voteId);
    result["creditedAtoms"] = credited;
    result["credited"] = atomsToNgt(credited);
    return result.dump();
}

std::string handleRpcPoeFinalize(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }
    std::string submitHex = params.value("submitId", "");
    if (submitHex.empty()) {
        throw std::runtime_error("submitId required");
    }
    crypto::Hash256 submitId = parseHash256Hex(submitHex);
    auto fin = poeV1_->finalize(submitId);
    uint64_t credited = maybeCreditAcceptanceReward(submitId);

    json result;
    if (!fin) {
        result["status"] = "pending";
        result["finalized"] = false;
    } else {
        result["status"] = "finalized";
        result["finalized"] = true;
        result["finalizedAt"] = fin->finalizedAt;
        result["validatorSetHash"] = crypto::toHex(fin->validatorSetHash);
        result["voteCount"] = fin->votes.size();
    }
    result["creditedAtoms"] = credited;
    result["credited"] = atomsToNgt(credited);
    return result.dump();
}

	    std::string handleRpcPoeEpoch(const std::string& paramsJson) {
	        auto params = parseRpcParams(paramsJson);
	        if (!poeV1_ || !transfer_) {
	            throw std::runtime_error("PoE/transfer not ready");
    }

    uint64_t budget = 0;
    if (params.contains("budget_atoms")) {
        budget = params["budget_atoms"].get<uint64_t>();
    } else if (params.contains("budget")) {
        if (params["budget"].is_number()) {
            double v = params["budget"].get<double>();
            budget = static_cast<uint64_t>(std::llround(v * 100000000.0));
        } else if (params["budget"].is_string()) {
            budget = parseNgtAtomic(params["budget"].get<std::string>());
        } else {
            throw std::runtime_error("budget must be number or string");
        }
    } else {
        int64_t cfgBudget = utils::Config::instance().getInt64(
            "poe.epoch_budget",
            config_.dev ? 100000000LL : 1000000000LL);
        if (cfgBudget > 0) budget = static_cast<uint64_t>(cfgBudget);
    }

    uint32_t iterations = params.value("iterations",
        static_cast<uint32_t>(std::max(1, utils::Config::instance().getInt(
            "poe.epoch_iterations",
            config_.dev ? 10 : 20))));

    bool creditRewards = params.value("credit_rewards", true);

	    auto epochRes = poeV1_->runEpoch(budget, iterations);
	    if (!epochRes.ok) {
	        throw std::runtime_error("PoE epoch failed: " + epochRes.error);
	    }

	    {
	        crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
	        std::lock_guard<std::mutex> lock(invMtx_);
	        knownPoeEpochs_.insert(crypto::toHex(hid));
	    }
	    broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

	    uint64_t mintedTotal = 0;
	    uint64_t mintedMine = 0;
	    uint64_t mintedCount = 0;
	    json allocations = json::array();

    for (const auto& alloc : epochRes.allocations) {
        std::string addr = addressFromPubKey(alloc.authorPubKey);
        crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, alloc.contentId);
        bool credited = false;
        if (creditRewards && !addr.empty()) {
            if (transfer_->creditRewardDeterministic(addr, rid, alloc.amount)) {
                credited = true;
                mintedTotal += alloc.amount;
                mintedCount += 1;
                if (!address_.empty() && addr == address_) mintedMine += alloc.amount;
            }
        }
        json entry;
        entry["submitId"] = crypto::toHex(alloc.submitId);
        entry["contentId"] = crypto::toHex(alloc.contentId);
        entry["author"] = addr;
        entry["score"] = alloc.score;
        entry["amountAtoms"] = alloc.amount;
        entry["amount"] = atomsToNgt(alloc.amount);
        entry["credited"] = credited;
        allocations.push_back(entry);
    }

    json result;
    result["status"] = "ok";
    result["epochId"] = epochRes.epochId;
    result["allocationHash"] = crypto::toHex(epochRes.allocationHash);
    result["mintedAtoms"] = mintedTotal;
    result["minted"] = atomsToNgt(mintedTotal);
    result["mintedEntries"] = mintedCount;
    result["mintedSelfAtoms"] = mintedMine;
    result["mintedSelf"] = atomsToNgt(mintedMine);
    result["allocations"] = allocations;
    return result.dump();
}

std::string handleRpcPoeExport(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string pathStr = params.value("path", "");
    if (pathStr.empty()) {
        throw std::runtime_error("path required");
    }
    std::filesystem::path target(pathStr);
    bool targetIsDir = std::filesystem::exists(target) ? std::filesystem::is_directory(target)
                                                       : target.has_filename() ? false : true;
    std::filesystem::path outDb = targetIsDir ? (target / "poe.db") : target;
    std::filesystem::create_directories(outDb.parent_path());

    auto srcDb = poeDbPath();
    auto srcWal = srcDb;
    srcWal += "-wal";
    auto srcShm = srcDb;
    srcShm += "-shm";

    std::error_code ec;
    std::filesystem::copy_file(srcDb, outDb, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) throw std::runtime_error("copy DB failed: " + ec.message());

    json copied = json::array();
    copied.push_back(outDb.string());

    if (std::filesystem::exists(srcWal)) {
        auto outWal = outDb;
        outWal += "-wal";
        ec.clear();
        std::filesystem::copy_file(srcWal, outWal, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy WAL failed: " + ec.message());
        copied.push_back(outWal.string());
    }
    if (std::filesystem::exists(srcShm)) {
        auto outShm = outDb;
        outShm += "-shm";
        ec.clear();
        std::filesystem::copy_file(srcShm, outShm, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy SHM failed: " + ec.message());
        copied.push_back(outShm.string());
    }

    json result;
    result["status"] = "exported";
    result["paths"] = copied;
    return result.dump();
}

std::string handleRpcPoeImport(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string pathStr = params.value("path", "");
    if (pathStr.empty()) {
        throw std::runtime_error("path required");
    }
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }

    std::filesystem::path target(pathStr);
    bool targetIsDir = std::filesystem::exists(target) ? std::filesystem::is_directory(target)
                                                       : target.has_filename() ? false : true;
    std::filesystem::path inDb = targetIsDir ? (target / "poe.db") : target;
    if (!std::filesystem::exists(inDb)) {
        throw std::runtime_error("source DB not found");
    }
    auto inWal = inDb;
    inWal += "-wal";
    auto inShm = inDb;
    inShm += "-shm";

    auto destDb = poeDbPath();
    auto destWal = destDb;
    destWal += "-wal";
    auto destShm = destDb;
    destShm += "-shm";

    auto cfg = poeV1_->getConfig();
    auto validators = poeV1_->getStaticValidators();
    poeV1_->close();

    std::filesystem::create_directories(destDb.parent_path());
    std::error_code ec;
    std::filesystem::copy_file(inDb, destDb, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) throw std::runtime_error("copy DB failed: " + ec.message());

    if (std::filesystem::exists(inWal)) {
        ec.clear();
        std::filesystem::copy_file(inWal, destWal, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy WAL failed: " + ec.message());
    }
    if (std::filesystem::exists(inShm)) {
        ec.clear();
        std::filesystem::copy_file(inShm, destShm, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copy SHM failed: " + ec.message());
    }

    if (!poeV1_->open(destDb.string())) {
        throw std::runtime_error("Failed to reopen PoE DB");
    }
    poeV1_->setConfig(cfg);
    if (!validators.empty()) {
        poeV1_->setStaticValidators(validators);
    }

    json result;
    result["status"] = "imported";
    result["path"] = destDb.string();
    return result.dump();
}

std::string handleRpcWalletAddress(const std::string& paramsJson) {
    (void)paramsJson;
    if (!keys_ || !keys_->isValid()) {
        throw std::runtime_error("Wallet not loaded");
    }
    auto pubV = keys_->getPublicKey();
    if (pubV.size() < crypto::PUBLIC_KEY_SIZE) {
        throw std::runtime_error("Invalid public key");
    }
    crypto::PublicKey pk{};
    std::memcpy(pk.data(), pubV.data(), pk.size());
    json result;
    result["address"] = address_;
    result["pubkey"] = crypto::toHex(pk);
    return result.dump();
}

std::string handleRpcWalletBalance(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!transfer_) {
        throw std::runtime_error("Transfer not ready");
    }
    std::string addr = params.value("address", "");
    if (addr.empty()) addr = address_;
    if (addr.empty()) {
        throw std::runtime_error("address required");
    }
    uint64_t bal = transfer_->getBalance(addr);
    json result;
    result["address"] = addr;
    result["balanceAtoms"] = bal;
    result["balance"] = atomsToNgt(bal);
    result["totalSupplyAtoms"] = transfer_->totalSupply();
    result["totalSupply"] = atomsToNgt(transfer_->totalSupply());
    return result.dump();
}

static std::string modelStateToString(model::ModelState s) {
    switch (s) {
        case model::ModelState::UNLOADED: return "UNLOADED";
        case model::ModelState::LOADING: return "LOADING";
        case model::ModelState::READY: return "READY";
        case model::ModelState::GENERATING: return "GENERATING";
        case model::ModelState::ERROR: return "ERROR";
        case model::ModelState::DOWNLOADING: return "DOWNLOADING";
    }
    return "UNKNOWN";
}

std::string handleRpcModelStatus(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::lock_guard<std::mutex> lock(modelMtx_);
    auto info = modelLoader_->getInfo();
    json out;
    out["loaded"] = modelLoader_->isLoaded();
    out["state"] = modelStateToString(modelLoader_->getState());
    out["generating"] = modelLoader_->isGenerating();
    out["name"] = info.name;
    out["path"] = info.path;
    out["sizeBytes"] = info.sizeBytes;
    out["error"] = modelLoader_->getError();
    out["requests"] = modelRequests_.load();
    return out.dump();
}

std::string handleRpcModelList(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::string dir = params.value("dir", "");
    if (dir.empty()) dir = config_.dataDir + "/models";
    std::lock_guard<std::mutex> lock(modelMtx_);
    auto models = modelLoader_->listModels(dir);
    json out = json::array();
    for (const auto& m : models) {
        json item;
        item["name"] = m.name;
        item["path"] = m.path;
        item["sizeBytes"] = m.sizeBytes;
        item["format"] = static_cast<int>(m.format);
        item["quantization"] = m.quantization;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcModelLoad(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::string path = params.value("path", "");
    std::string name = params.value("name", "");
    if (path.empty() && !name.empty()) {
        path = (std::filesystem::path(config_.dataDir) / "models" / name).string();
    }
    if (path.empty()) {
        throw std::runtime_error("path required");
    }
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("model_not_found");
    }

    model::LoaderConfig cfg = modelLoader_->getConfig();
    if (params.contains("contextSize")) cfg.contextSize = static_cast<uint32_t>(std::max(256, params.value("contextSize", 2048)));
    if (params.contains("threads")) cfg.threads = static_cast<uint32_t>(std::max(1, params.value("threads", 4)));
    if (params.contains("gpuLayers")) cfg.gpuLayers = static_cast<uint32_t>(std::max(0, params.value("gpuLayers", 0)));
    if (params.contains("useGpu")) cfg.useGpu = params.value("useGpu", false);
    if (params.contains("useMmap")) cfg.useMmap = params.value("useMmap", true);
    if (params.contains("useMlock")) cfg.useMlock = params.value("useMlock", false);

    std::lock_guard<std::mutex> lock(modelMtx_);
    bool ok = modelLoader_->load(path, cfg);

    json out;
    out["ok"] = ok;
    out["state"] = modelStateToString(modelLoader_->getState());
    out["error"] = modelLoader_->getError();
    auto info = modelLoader_->getInfo();
    out["name"] = info.name;
    out["path"] = info.path;
    out["sizeBytes"] = info.sizeBytes;

    if (ok) {
        utils::Config::instance().set("model.last_path", path);
        utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
    }

    return out.dump();
}

std::string handleRpcModelUnload(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::lock_guard<std::mutex> lock(modelMtx_);
    bool ok = modelLoader_->unload();
    json out;
    out["ok"] = ok;
    out["state"] = modelStateToString(modelLoader_->getState());
    return out.dump();
}

std::string handleRpcModelRemoteList(const std::string& paramsJson) {
    (void)paramsJson;
    json out = json::array();
    const uint64_t now = std::time(nullptr);
    std::lock_guard<std::mutex> lock(remoteMtx_);
    for (const auto& [offerId, cache] : remoteOffers_) {
        const auto& o = cache.offer;
        if (o.expiresAt != 0 && o.expiresAt < now) continue;
        json item;
        item["offerId"] = offerId;
        item["peerId"] = cache.peerId;
        item["receivedAt"] = cache.receivedAt;
        item["modelId"] = o.modelId;
        item["providerAddress"] = o.providerAddress;
        item["pricePerRequestAtoms"] = o.pricePerRequestAtoms;
        item["maxSlots"] = o.maxSlots;
        item["usedSlots"] = o.usedSlots;
        item["expiresAt"] = o.expiresAt;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcModelRemoteRent(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!network_) {
        throw std::runtime_error("network_not_ready");
    }
    if (!keys_ || !keys_->isValid()) {
        throw std::runtime_error("wallet_not_ready");
    }
    const auto route = refreshTorRoutePolicy(true);
    if (!route.allowP2PDiscovery) {
        throw std::runtime_error("tor_fail_closed_remote_model");
    }

    const std::string offerId = params.value("offerId", "");
    if (offerId.empty()) {
        throw std::runtime_error("offerId required");
    }

    RemoteOfferCache offer;
    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        auto it = remoteOffers_.find(offerId);
        if (it == remoteOffers_.end()) {
            throw std::runtime_error("offer_not_found");
        }
        offer = it->second;
    }

    synapse::RemoteModelRentMessage rent;
    rent.offerId = offerId;
    rent.timestamp = std::time(nullptr);
    auto pubV = keys_->getPublicKey();
    if (pubV.size() < rent.renterPubKey.size()) {
        throw std::runtime_error("invalid_pubkey");
    }
    std::memcpy(rent.renterPubKey.data(), pubV.data(), rent.renterPubKey.size());

    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        remoteRentOkByOffer_.erase(offerId);
    }

    network_->send(offer.peerId, makeMessage("m_rent", rent.serialize()));

    const uint64_t deadline = std::time(nullptr) + (config_.dev ? 10 : 30);
    synapse::RemoteModelRentOkMessage ok;
    for (;;) {
        std::unique_lock<std::mutex> lk(remoteMtx_);
        auto it = remoteRentOkByOffer_.find(offerId);
        if (it != remoteRentOkByOffer_.end()) {
            ok = it->second;
            break;
        }
        lk.unlock();
        if (std::time(nullptr) >= deadline) {
            throw std::runtime_error("rent_timeout");
        }
        std::unique_lock<std::mutex> waitLk(remoteMtx_);
        remoteCv_.wait_for(waitLk, std::chrono::milliseconds(250));
    }

    json out;
    out["ok"] = true;
    out["offerId"] = offerId;
    out["peerId"] = offer.peerId;
    out["sessionId"] = ok.sessionId;
    out["providerAddress"] = ok.providerAddress;
    out["pricePerRequestAtoms"] = ok.pricePerRequestAtoms;
    out["expiresAt"] = ok.expiresAt;
    return out.dump();
}

std::string handleRpcModelRemoteEnd(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    const std::string sessionId = params.value("sessionId", "");
    if (sessionId.empty()) throw std::runtime_error("sessionId required");
    std::lock_guard<std::mutex> lock(remoteMtx_);
    remoteSessions_.erase(sessionId);
    json out;
    out["ok"] = true;
    return out.dump();
}

static std::string accessModeToString(model::AccessMode m) {
    switch (m) {
        case model::AccessMode::PRIVATE: return "PRIVATE";
        case model::AccessMode::SHARED: return "SHARED";
        case model::AccessMode::PAID: return "PAID";
        case model::AccessMode::COMMUNITY: return "COMMUNITY";
    }
    return "UNKNOWN";
}

static model::AccessMode parseAccessMode(const std::string& s) {
    std::string t;
    t.reserve(s.size());
    for (char c : s) t.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    if (t == "PRIVATE") return model::AccessMode::PRIVATE;
    if (t == "SHARED") return model::AccessMode::SHARED;
    if (t == "PAID") return model::AccessMode::PAID;
    if (t == "COMMUNITY" || t == "PUBLIC") return model::AccessMode::COMMUNITY;
    throw std::runtime_error("invalid access mode");
}

std::string handleRpcModelAccessGet(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelAccess_) throw std::runtime_error("model access not ready");
    json out;
    out["mode"] = accessModeToString(modelAccess_->getMode());
    out["maxSlots"] = modelAccess_->getMaxSlots();
    out["activeSlots"] = modelAccess_->getActiveSlots();
    out["availableSlots"] = modelAccess_->getAvailableSlots();
    out["pricePerHourAtoms"] = modelAccess_->getPrice();
    out["remotePricePerRequestAtoms"] = remotePricePerRequestAtoms_;
    return out.dump();
}

std::string handleRpcModelAccessSet(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelAccess_) throw std::runtime_error("model access not ready");

    bool changed = false;
    if (params.contains("mode") && params["mode"].is_string()) {
        modelAccess_->setMode(parseAccessMode(params["mode"].get<std::string>()));
        utils::Config::instance().set("model.access.mode", accessModeToString(modelAccess_->getMode()));
        changed = true;
    }
    if (params.contains("maxSlots")) {
        uint32_t slots = static_cast<uint32_t>(std::max(1, params.value("maxSlots", 3)));
        modelAccess_->setMaxSlots(slots);
        utils::Config::instance().set("model.access.max_slots", static_cast<int>(slots));
        changed = true;
    }
    if (params.contains("pricePerHourAtoms")) {
        uint64_t p = static_cast<uint64_t>(std::max<int64_t>(0, params.value("pricePerHourAtoms", 0)));
        modelAccess_->setPrice(p);
        utils::Config::instance().set("model.access.price_per_hour_atoms", static_cast<int64_t>(p));
        changed = true;
    }
    if (params.contains("remotePricePerRequestAtoms")) {
        uint64_t p = static_cast<uint64_t>(std::max<int64_t>(0, params.value("remotePricePerRequestAtoms", 0)));
        remotePricePerRequestAtoms_ = p;
        utils::Config::instance().set("model.remote.price_per_request_atoms", static_cast<int64_t>(p));
        changed = true;
    }

    if (changed) {
        utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
    }
    return handleRpcModelAccessGet("{}");
}

std::string handleRpcMarketListings(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelMarketplace_) throw std::runtime_error("marketplace_not_ready");
    bool includeInactive = params.value("includeInactive", false);
    auto listings = modelMarketplace_->getAllListings(includeInactive);
    json out = json::array();
    for (const auto& l : listings) {
        json item;
        item["modelId"] = l.modelId;
        item["ownerId"] = l.ownerId;
        item["name"] = l.name;
        item["description"] = l.description;
        item["sizeBytes"] = l.size;
        item["format"] = l.format;
        item["pricePerHourAtoms"] = l.pricePerHourAtoms;
        item["pricePerRequestAtoms"] = l.pricePerRequestAtoms;
        item["maxSlots"] = l.maxSlots;
        item["usedSlots"] = l.usedSlots;
        item["availableSlots"] = l.availableSlots;
        item["ratingMilli"] = l.ratingMilli;
        item["ratingCount"] = l.ratingCount;
        item["totalRequests"] = l.totalRequests;
        item["totalEarningsAtoms"] = l.totalEarningsAtoms;
        item["active"] = l.active;
        item["createdAt"] = l.createdAt;
        item["lastActive"] = l.lastActive;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcMarketStats(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelMarketplace_) throw std::runtime_error("marketplace_not_ready");
    auto st = modelMarketplace_->getStats();
    json out;
    out["totalListings"] = st.totalListings;
    out["activeListings"] = st.activeListings;
    out["totalRentals"] = st.totalRentals;
    out["activeRentals"] = st.activeRentals;
    out["totalSessions"] = st.totalSessions;
    out["activeSessions"] = st.activeSessions;
    out["totalRequests"] = st.totalRequests;
    out["totalVolumeAtoms"] = st.totalVolumeAtoms;
    out["totalEarningsAtoms"] = st.totalEarningsAtoms;
    out["avgPricePerRequestAtoms"] = st.avgPricePerRequestAtoms;
    return out.dump();
}

std::string createAndSubmitPaymentTx(const std::string& to, uint64_t amountAtoms, uint64_t& feeAtomsOut) {
    if (!transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
        throw std::runtime_error("wallet/transfer not ready");
    }
    if (amountAtoms == 0) {
        feeAtomsOut = 0;
        return "";
    }
    if (!transfer_->hasSufficientBalance(address_, amountAtoms)) {
        throw std::runtime_error("insufficient_balance");
    }

    uint64_t fee = transfer_->estimateFee(0);
    core::Transaction tx;
    for (int i = 0; i < 5; ++i) {
        tx = transfer_->createTransaction(address_, to, amountAtoms, fee);
        uint64_t requiredFee = transfer_->estimateFee(tx.serialize().size());
        if (requiredFee == fee) break;
        fee = requiredFee;
    }

    crypto::PrivateKey pk{};
    auto pkv = keys_->getPrivateKey();
    if (pkv.size() < pk.size()) {
        throw std::runtime_error("invalid private key");
    }
    std::memcpy(pk.data(), pkv.data(), pk.size());
    if (!transfer_->signTransaction(tx, pk)) {
        throw std::runtime_error("failed_to_sign_tx");
    }
    if (!transfer_->submitTransaction(tx)) {
        throw std::runtime_error("failed_to_submit_tx");
    }
    feeAtomsOut = fee;
    return crypto::toHex(tx.txid);
}

std::string handleRpcAiCompleteRemote(const json& params, const std::string& prompt, const model::GenerationParams& gp) {
    if (!network_) throw std::runtime_error("network_not_ready");
    if (!keys_ || !keys_->isValid()) throw std::runtime_error("wallet_not_ready");
    const auto route = refreshTorRoutePolicy(true);
    if (!route.allowP2PDiscovery) {
        throw std::runtime_error("tor_fail_closed_remote_model");
    }

    const std::string sessionId = params.value("remoteSessionId", params.value("sessionId", ""));
    if (sessionId.empty()) throw std::runtime_error("remoteSessionId required");

    RemoteSessionInfo session;
    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        auto it = remoteSessions_.find(sessionId);
        if (it == remoteSessions_.end()) throw std::runtime_error("remote_session_not_found");
        session = it->second;
    }
    const uint64_t now = std::time(nullptr);
    if (session.expiresAt != 0 && session.expiresAt < now) {
        throw std::runtime_error("remote_session_expired");
    }

    uint64_t feeAtoms = 0;
    std::string paymentTxidHex;
    if (session.pricePerRequestAtoms > 0) {
        paymentTxidHex = createAndSubmitPaymentTx(session.providerAddress, session.pricePerRequestAtoms, feeAtoms);
    }

    synapse::RemoteModelInferMessage req;
    req.sessionId = session.sessionId;
    req.requestId = randomHex16();
    req.prompt = prompt;
    req.maxTokens = gp.maxTokens;
    req.temperature = gp.temperature;
    req.topP = gp.topP;
    req.topK = gp.topK;
    req.paymentTxidHex = paymentTxidHex;
    req.timestamp = now;
    auto pubV = keys_->getPublicKey();
    if (pubV.size() >= req.renterPubKey.size()) {
        std::memcpy(req.renterPubKey.data(), pubV.data(), req.renterPubKey.size());
    }

    {
        std::lock_guard<std::mutex> lock(remoteMtx_);
        RemotePending p;
        p.done = false;
        remotePending_[req.requestId] = std::move(p);
    }

    network_->send(session.peerId, makeMessage("m_infer", req.serialize()));

    const uint64_t deadline = std::time(nullptr) + (config_.dev ? 45 : 120);
    RemotePending done;
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            auto it = remotePending_.find(req.requestId);
            if (it != remotePending_.end() && it->second.done) {
                done = it->second;
                remotePending_.erase(it);
                break;
            }
        }
        if (std::time(nullptr) >= deadline) {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            remotePending_.erase(req.requestId);
            throw std::runtime_error("remote_infer_timeout");
        }
        std::unique_lock<std::mutex> lk(remoteMtx_);
        remoteCv_.wait_for(lk, std::chrono::milliseconds(250));
    }

    json out;
    out["model"] = "remote";
    out["text"] = done.text;
    json r;
    r["peerId"] = session.peerId;
    r["sessionId"] = session.sessionId;
    r["providerAddress"] = session.providerAddress;
    r["pricePerRequestAtoms"] = session.pricePerRequestAtoms;
    r["paymentTxid"] = paymentTxidHex;
    r["feeAtoms"] = feeAtoms;
    out["remote"] = r;
    return out.dump();
}

std::string handleRpcAiComplete(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    std::string prompt = params.value("prompt", "");
    if (prompt.empty()) {
        throw std::runtime_error("prompt required");
    }
	    if (prompt.size() > 1024 * 1024) {
	        throw std::runtime_error("prompt too large");
	    }
        const bool remote = params.value("remote", false) || params.contains("remoteSessionId");
	    bool webInject = params.value("webInject", utils::Config::instance().getBool("web.inject.enabled", false));
	    bool webOnion = params.value("webOnion", utils::Config::instance().getBool("web.inject.onion", false));
	    bool webTor = params.value("webTor", utils::Config::instance().getBool("web.inject.tor_clearnet", false));
	    std::string webQuery = params.value("webQuery", "");
        bool torDegraded = false;
        const bool torRequired = agentTorRequired_.load();
        const auto route = refreshTorRoutePolicy(true);
        const bool torReachable = agentTorReachable_.load();
        if (torRequired) {
            webInject = true;
        }
        torDegraded = route.torDegraded;
        if (torRequired) {
            webTor = torReachable && route.allowWebClearnet;
            webOnion = torReachable && route.allowWebOnion;
            if (!webTor && !webOnion) {
                webInject = false;
            }
        }

    model::GenerationParams gp;
    if (params.contains("maxTokens")) gp.maxTokens = static_cast<uint32_t>(std::max(1, params.value("maxTokens", 512)));
    if (params.contains("temperature")) gp.temperature = static_cast<float>(std::max(0.0, params.value("temperature", 0.7)));
    if (params.contains("topP")) gp.topP = static_cast<float>(std::max(0.0, params.value("topP", 0.9)));
    if (params.contains("topK")) gp.topK = static_cast<uint32_t>(std::max(0, params.value("topK", 40)));
    if (params.contains("seed")) gp.seed = static_cast<uint64_t>(std::max<int64_t>(0, params.value("seed", 0)));
    if (params.contains("stopSequences") && params["stopSequences"].is_array()) {
        gp.stopSequences.clear();
        for (const auto& s : params["stopSequences"]) {
            if (s.is_string()) gp.stopSequences.push_back(s.get<std::string>());
        }
	    }
	    if (params.contains("jsonMode")) gp.jsonMode = params.value("jsonMode", false);

        if (remote) {
            return handleRpcAiCompleteRemote(params, prompt, gp);
        }

        std::lock_guard<std::mutex> lock(modelMtx_);
        if (!modelLoader_->isLoaded()) {
            throw std::runtime_error("model_not_loaded");
        }
        if (modelLoader_->isGenerating()) {
            throw std::runtime_error("model_busy");
        }
        modelRequests_.fetch_add(1);

	    std::string finalPrompt = prompt;
	    uint64_t webResults = 0;
	    uint64_t webClearnet = 0;
	    uint64_t webDarknet = 0;
	    if (webInject) {
	        if (ensureWebSubsystem()) {
	            std::lock_guard<std::mutex> wlock(webMtx_);
	            if (webAi_ && webSearch_) {
	                web::SearchConfig cfg = webSearch_->getConfig();
	                cfg.enableClearnet = torRequired ? webTor : true;
	                cfg.enableDarknet = webOnion;
	                cfg.routeClearnetThroughTor = webTor;
	                webSearch_->setConfig(cfg);
                    if (!cfg.enableClearnet && !cfg.enableDarknet) {
                        naanWebFailClosedSkips_.fetch_add(1);
                    } else {
	                    try {
	                        if (!webQuery.empty() && webDetector_) {
	                            web::QueryAnalysis analysis = webDetector_->analyze(webQuery);
	                            std::vector<web::SearchResult> results = webSearch_->search(webQuery, analysis.type);
	                            webResults = static_cast<uint64_t>(results.size());
	                            for (const auto& r : results) {
	                                if (r.isOnion) webDarknet++;
	                                else webClearnet++;
	                            }
	                            finalPrompt = webAi_->injectContext(prompt, results);
	                        } else {
	                            finalPrompt = webAi_->processQuery(prompt);
	                            auto st = webAi_->getStats();
	                            webResults = st.lastResultCount;
	                            webClearnet = st.lastClearnetResults;
	                            webDarknet = st.lastDarknetResults;
	                        }
	                    } catch (...) {
	                        finalPrompt = prompt;
	                    }
                    }
	            }
	        }
	    }

	    std::string text = modelLoader_->generate(finalPrompt, gp);
	    auto info = modelLoader_->getInfo();
	    json out;
	    out["model"] = info.name;
	    out["text"] = text;
	    out["webInject"] = webInject;
        out["torDegraded"] = torDegraded;
	    if (webInject) {
	        json w;
	        w["lastResults"] = webResults;
	        w["lastClearnetResults"] = webClearnet;
	        w["lastDarknetResults"] = webDarknet;
	        if (!webQuery.empty()) w["query"] = webQuery;
	        out["web"] = w;
	    }
	    return out.dump();
	}

std::string handleRpcAiStop(const std::string& paramsJson) {
    (void)paramsJson;
    if (!modelLoader_) {
        throw std::runtime_error("Model not ready");
    }
    modelLoader_->stopGeneration();
    json out;
    out["ok"] = true;
    return out.dump();
}

std::string handleRpcPoeValidators(const std::string& paramsJson) {
    (void)paramsJson;
    if (!poeV1_) {
        throw std::runtime_error("PoE not ready");
    }
    json out = json::array();
    for (const auto& v : poeV1_->getDeterministicValidators()) {
        out.push_back(crypto::toHex(v));
    }
    return out.dump();
}

std::string handleRpcUpdateManifestSubmit(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string manifestHex = params.value("manifest", "");
    if (manifestHex.empty()) manifestHex = params.value("manifestHex", "");
    if (manifestHex.empty()) {
        throw std::runtime_error("manifest hex required");
    }

    auto bytes = crypto::fromHex(manifestHex);
    if (bytes.empty()) {
        throw std::runtime_error("manifest hex decode failed");
    }

    auto manifestOpt = core::UpdateManifest::deserialize(bytes);
    if (!manifestOpt) {
        throw std::runtime_error("manifest_deserialize_failed");
    }

    std::string reason;
    auto status = acceptUpdateManifest(*manifestOpt, true, &reason);
    if (status == UpdateManifestAccept::REJECTED) {
        throw std::runtime_error("invalid_manifest: " + reason);
    }

    json out = updateManifestToJson(*manifestOpt, true);
    out["status"] = (status == UpdateManifestAccept::DUPLICATE) ? "duplicate" : "accepted";
    out["reason"] = reason;
    out["serialized"] = crypto::toHex(manifestOpt->serialize());
    return out.dump();
}

std::string handleRpcUpdateManifestFetch(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);

    core::UpdateManifest manifest;
    {
        std::lock_guard<std::mutex> lock(invMtx_);
        auto it = updateManifestsById_.find(idHex);
        if (it == updateManifestsById_.end()) {
            throw std::runtime_error("not_found");
        }
        manifest = it->second;
    }

    json out = updateManifestToJson(manifest, true);
    out["status"] = "ok";
    out["serialized"] = crypto::toHex(manifest.serialize());
    return out.dump();
}

std::string handleRpcUpdateManifestList(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    size_t limit = 25;
    if (params.contains("limit")) {
        limit = static_cast<size_t>(std::max(1, params.value("limit", 25)));
    }

    std::vector<core::UpdateManifest> manifests;
    {
        std::lock_guard<std::mutex> lock(invMtx_);
        manifests.reserve(updateManifestsById_.size());
        for (const auto& [_, m] : updateManifestsById_) {
            manifests.push_back(m);
        }
    }

    std::sort(manifests.begin(), manifests.end(), [](const core::UpdateManifest& a, const core::UpdateManifest& b) {
        return std::lexicographical_compare(a.bundleId.begin(), a.bundleId.end(), b.bundleId.begin(), b.bundleId.end());
    });

    if (manifests.size() > limit) {
        manifests.erase(manifests.begin(), manifests.end() - static_cast<std::ptrdiff_t>(limit));
    }

    json out = json::array();
    for (const auto& m : manifests) {
        out.push_back(updateManifestToJson(m, false));
    }
    return out.dump();
}

std::string handleRpcUpdateManifestApprove(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    std::string signerHex = params.value("signer", "");
    if (signerHex.empty()) {
        throw std::runtime_error("signer required");
    }
    std::string signatureHex = params.value("signature", "");
    if (signatureHex.empty()) {
        throw std::runtime_error("signature required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    core::DetachedSignerApproval approval;
    if (!parsePublicKeyHex(signerHex, approval.signer)) {
        throw std::runtime_error("invalid_signer");
    }
    if (!parseSignatureHex(signatureHex, approval.signature)) {
        throw std::runtime_error("invalid_signature");
    }

    const auto digest = core::ImplantCompatibility::detachedApprovalHash(bundleId);
    if (!crypto::verify(digest, approval.signature, approval.signer)) {
        throw std::runtime_error("invalid_detached_approval_signature");
    }

    upsertDetachedSignerApproval(bundleId, approval);

    std::string governanceReason;
    const bool governanceReady = validateUpdateSignerThreshold(manifest, &governanceReason);

    json out = detachedSignerApprovalsToJson(bundleId);
    out["status"] = "ok";
    out["governanceReady"] = governanceReady;
    out["governanceReason"] = governanceReason;

    json details;
    details["bundleId"] = crypto::toHex(bundleId);
    details["signer"] = crypto::toHex(approval.signer);
    details["governanceReady"] = governanceReady;
    details["governanceReason"] = governanceReason;
    emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "detached_signer_approval", "high", "update_manifest", details);
    return out.dump();
}

std::string handleRpcUpdateManifestApprovals(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    std::string governanceReason;
    const bool governanceReady = validateUpdateSignerThreshold(manifest, &governanceReason);

    json out = detachedSignerApprovalsToJson(bundleId);
    out["status"] = "ok";
    out["governanceReady"] = governanceReady;
    out["governanceReason"] = governanceReason;
    out["policy"] = implantUpdatePolicyToJson();
    return out.dump();
}

std::string handleRpcUpdateInstallState(const std::string& paramsJson) {
    (void)paramsJson;
    core::UpdateInstallerState installerState;
    {
        std::lock_guard<std::mutex> lock(updateInstallMtx_);
        installerState = updateInstaller_.state();
    }

    json out = updateInstallerStateToJson(installerState);
    out["status"] = "ok";
    out["policy"] = implantUpdatePolicyToJson();
    auto policyHashes = securityPolicyHashes();
    out["policyHashNaan"] = policyHashes.first;
    out["policyHashImplant"] = policyHashes.second;

    if (!installerState.hasPending) {
        out["pendingSignerThresholdReady"] = false;
        out["pendingSignerThresholdReason"] = "no_pending_update";
        return out.dump();
    }

    out["pendingApprovals"] = detachedSignerApprovalsToJson(installerState.pendingBundle);
    out["pendingSignerThresholdReady"] = false;
    out["pendingSignerThresholdReason"] = "manifest_not_found";

    core::UpdateManifest pendingManifest;
    if (fetchStoredUpdateManifest(installerState.pendingBundle, pendingManifest)) {
        out["pendingManifest"] = updateManifestToJson(pendingManifest, false);
        std::string thresholdReason;
        out["pendingSignerThresholdReady"] = validateUpdateSignerThreshold(pendingManifest, &thresholdReason);
        out["pendingSignerThresholdReason"] = thresholdReason;
    }

    return out.dump();
}

std::string handleRpcUpdateInstallPrepare(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);

    core::UpdateManifest manifest;
    {
        std::lock_guard<std::mutex> lock(invMtx_);
        auto it = updateManifestsById_.find(idHex);
        if (it == updateManifestsById_.end()) {
            throw std::runtime_error("manifest_not_found");
        }
        manifest = it->second;
    }

    std::string reason;
    if (!validateUpdateSignerThreshold(manifest, &reason)) {
        json details;
        details["bundleId"] = idHex;
        details["reason"] = reason;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "update_signer_threshold_failed", "high", "update.install.prepare", details);
        throw std::runtime_error("update_signer_threshold_failed: " + reason);
    }
    {
        std::lock_guard<std::mutex> lock(updateInstallMtx_);
        auto policy = installerPolicyForManifest(manifest);
        if (!updateInstaller_.installManifest(manifest, policy, &reason)) {
            throw std::runtime_error("install_prepare_failed: " + reason);
        }
        json out = updateInstallerStateToJson(updateInstaller_.state());
        out["status"] = "ok";
        out["reason"] = reason;
        out["bundleId"] = idHex;
        return out.dump();
    }
}

std::string handleRpcUpdateInstallAdvance(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);

    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    std::string reason;
    if (!validateUpdateSignerThreshold(manifest, &reason)) {
        json details;
        details["bundleId"] = idHex;
        details["reason"] = reason;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "update_signer_threshold_failed", "high", "update.install.advance", details);
        throw std::runtime_error("update_signer_threshold_failed: " + reason);
    }

    std::lock_guard<std::mutex> lock(updateInstallMtx_);
    if (!updateInstaller_.advanceRollout(bundleId, &reason)) {
        throw std::runtime_error("install_advance_failed: " + reason);
    }

    json out = updateInstallerStateToJson(updateInstaller_.state());
    out["status"] = "ok";
    out["reason"] = reason;
    out["bundleId"] = idHex;
    return out.dump();
}

std::string handleRpcUpdateInstallCommit(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);

    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    std::string reason;
    if (!validateUpdateSignerThreshold(manifest, &reason)) {
        json details;
        details["bundleId"] = idHex;
        details["reason"] = reason;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "update_signer_threshold_failed", "high", "update.install.commit", details);
        throw std::runtime_error("update_signer_threshold_failed: " + reason);
    }

    std::lock_guard<std::mutex> lock(updateInstallMtx_);
    if (!updateInstaller_.commitPending(bundleId, &reason)) {
        throw std::runtime_error("install_commit_failed: " + reason);
    }

    json out = updateInstallerStateToJson(updateInstaller_.state());
    out["status"] = "ok";
    out["reason"] = reason;
    out["bundleId"] = idHex;
    return out.dump();
}

std::string handleRpcUpdateInstallRollback(const std::string& paramsJson) {
    (void)paramsJson;
    std::string reason;
    std::lock_guard<std::mutex> lock(updateInstallMtx_);
    if (!updateInstaller_.rollback(&reason)) {
        throw std::runtime_error("install_rollback_failed: " + reason);
    }

    json out = updateInstallerStateToJson(updateInstaller_.state());
    out["status"] = "ok";
    out["reason"] = reason;
    return out.dump();
}

std::string handleRpcImplantUpdateState(const std::string& paramsJson) {
    (void)paramsJson;

    core::UpdateInstallerState installerState;
    {
        std::lock_guard<std::mutex> lock(updateInstallMtx_);
        installerState = updateInstaller_.state();
    }

    json out;
    out["status"] = "ok";
    out["installer"] = updateInstallerStateToJson(installerState);
    out["policy"] = implantUpdatePolicyToJson();
    auto policyHashes = securityPolicyHashes();
    out["policyHashNaan"] = policyHashes.first;
    out["policyHashImplant"] = policyHashes.second;

    if (installerState.hasPending) {
        core::UpdateManifest pendingManifest;
        if (fetchStoredUpdateManifest(installerState.pendingBundle, pendingManifest)) {
            out["pendingManifest"] = updateManifestToJson(pendingManifest, false);
            out["pendingApprovals"] = detachedSignerApprovalsToJson(installerState.pendingBundle);
            std::string thresholdReason;
            out["pendingSignerThresholdReady"] = validateUpdateSignerThreshold(pendingManifest, &thresholdReason);
            out["pendingSignerThresholdReason"] = thresholdReason;
        }

        auto safetyRecord = getImplantSafetyRecord(installerState.pendingBundle);
        if (safetyRecord) {
            out["safetyRecord"] = implantSafetyRecordToJson(*safetyRecord);
        }

        std::string safetyReason;
        bool safetyCommitReady = false;
        {
            std::lock_guard<std::mutex> lock(implantSafetyMtx_);
            safetyCommitReady = implantSafetyPipeline_.canCommit(installerState.pendingBundle, &safetyReason);
        }
        out["safetyCommitReady"] = safetyCommitReady;
        out["safetyCommitReason"] = safetyReason;
    }

    return out.dump();
}

std::string handleRpcImplantUpdatePrepare(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    bool safetyGatePassed = params.value("safetyGatePassed", false);
    if (!params.contains("safetyGatePassed")) {
        safetyGatePassed = params.value("safety_gate_passed", false);
    }
    bool deterministicTestsPassed = params.value("deterministicTestsPassed", false);
    if (!params.contains("deterministicTestsPassed")) {
        deterministicTestsPassed = params.value("deterministic_tests_passed", false);
    }
    bool sandboxBoundariesPassed = params.value("sandboxBoundariesPassed", false);
    if (!params.contains("sandboxBoundariesPassed")) {
        sandboxBoundariesPassed = params.value("sandbox_boundaries_passed", false);
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);

    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    std::string reason;
    if (!validateImplantDistributionManifest(manifest, safetyGatePassed, &reason)) {
        json details;
        details["bundleId"] = idHex;
        details["reason"] = reason;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "implant_policy_rejected", "high", "implant.update.prepare", details);
        throw std::runtime_error("implant_policy_rejected: " + reason);
    }

    {
        std::lock_guard<std::mutex> lock(implantSafetyMtx_);
        if (!implantSafetyPipeline_.markPrepare(bundleId, deterministicTestsPassed, sandboxBoundariesPassed, &reason)) {
            throw std::runtime_error("safety_pipeline_rejected: " + reason);
        }
    }

    std::lock_guard<std::mutex> lock(updateInstallMtx_);
    auto policy = installerPolicyForManifest(manifest);
    if (!updateInstaller_.installManifest(manifest, policy, &reason)) {
        throw std::runtime_error("install_prepare_failed: " + reason);
    }

    json out;
    out["status"] = "ok";
    out["reason"] = reason;
    out["bundleId"] = idHex;
    out["target"] = manifest.target;
    out["signer"] = crypto::toHex(manifest.signer);
    out["installer"] = updateInstallerStateToJson(updateInstaller_.state());
    auto safetyRecord = getImplantSafetyRecord(bundleId);
    if (safetyRecord) out["safetyRecord"] = implantSafetyRecordToJson(*safetyRecord);
    return out.dump();
}

std::string handleRpcImplantUpdateAdvance(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);
    bool canaryHealthPassed = params.value("canaryHealthPassed", false);
    if (!params.contains("canaryHealthPassed")) {
        canaryHealthPassed = params.value("canary_health_passed", false);
    }
    bool wideHealthPassed = params.value("wideHealthPassed", false);
    if (!params.contains("wideHealthPassed")) {
        wideHealthPassed = params.value("wide_health_passed", false);
    }

    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    std::string reason;
    if (!validateImplantDistributionManifest(manifest, true, &reason)) {
        json details;
        details["bundleId"] = idHex;
        details["reason"] = reason;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "implant_policy_rejected", "high", "implant.update.advance", details);
        throw std::runtime_error("implant_policy_rejected: " + reason);
    }

    core::UpdateInstallerState installerBefore;
    {
        std::lock_guard<std::mutex> lock(updateInstallMtx_);
        installerBefore = updateInstaller_.state();
    }
    if (!installerBefore.hasPending) {
        throw std::runtime_error("install_advance_failed: no_pending_update");
    }
    if (installerBefore.pendingBundle != bundleId) {
        throw std::runtime_error("install_advance_failed: bundle_mismatch");
    }

    {
        std::lock_guard<std::mutex> lock(implantSafetyMtx_);
        if (installerBefore.pendingStage == core::UpdateRolloutStage::CANARY) {
            if (!implantSafetyPipeline_.markCanaryHealth(bundleId, canaryHealthPassed, &reason)) {
                throw std::runtime_error("safety_pipeline_rejected: " + reason);
            }
        } else if (installerBefore.pendingStage == core::UpdateRolloutStage::WIDE) {
            if (!implantSafetyPipeline_.markWideHealth(bundleId, wideHealthPassed, &reason)) {
                throw std::runtime_error("safety_pipeline_rejected: " + reason);
            }
        } else {
            throw std::runtime_error("install_advance_failed: already_complete");
        }
    }

    std::lock_guard<std::mutex> lock(updateInstallMtx_);
    if (!updateInstaller_.advanceRollout(bundleId, &reason)) {
        throw std::runtime_error("install_advance_failed: " + reason);
    }

    json out;
    out["status"] = "ok";
    out["reason"] = reason;
    out["bundleId"] = idHex;
    out["installer"] = updateInstallerStateToJson(updateInstaller_.state());
    auto safetyRecord = getImplantSafetyRecord(bundleId);
    if (safetyRecord) out["safetyRecord"] = implantSafetyRecordToJson(*safetyRecord);
    return out.dump();
}

std::string handleRpcImplantUpdateCommit(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("bundleId", "");
    if (idHex.empty()) idHex = params.value("id", "");
    if (idHex.empty()) {
        throw std::runtime_error("bundleId required");
    }

    crypto::Hash256 bundleId = parseHash256Hex(idHex);
    idHex = crypto::toHex(bundleId);

    core::UpdateManifest manifest;
    if (!fetchStoredUpdateManifest(bundleId, manifest)) {
        throw std::runtime_error("manifest_not_found");
    }

    std::string reason;
    if (!validateImplantDistributionManifest(manifest, true, &reason)) {
        json details;
        details["bundleId"] = idHex;
        details["reason"] = reason;
        emitSecurityEvent(static_cast<uint64_t>(std::time(nullptr)), "implant_policy_rejected", "high", "implant.update.commit", details);
        throw std::runtime_error("implant_policy_rejected: " + reason);
    }

    {
        std::lock_guard<std::mutex> lock(implantSafetyMtx_);
        if (!implantSafetyPipeline_.canCommit(bundleId, &reason)) {
            throw std::runtime_error("safety_pipeline_rejected: " + reason);
        }
    }

    std::lock_guard<std::mutex> lock(updateInstallMtx_);
    if (!updateInstaller_.commitPending(bundleId, &reason)) {
        throw std::runtime_error("install_commit_failed: " + reason);
    }

    json out;
    out["status"] = "ok";
    out["reason"] = reason;
    out["bundleId"] = idHex;
    out["installer"] = updateInstallerStateToJson(updateInstaller_.state());
    auto safetyRecord = getImplantSafetyRecord(bundleId);
    if (safetyRecord) out["safetyRecord"] = implantSafetyRecordToJson(*safetyRecord);
    return out.dump();
}

std::string handleRpcImplantUpdateRollback(const std::string& paramsJson) {
    (void)paramsJson;

    crypto::Hash256 pendingBundle{};
    bool hadPending = false;
    core::UpdateInstallerState installerAfter;

    std::string reason;
    {
        std::lock_guard<std::mutex> lock(updateInstallMtx_);
        const auto& st = updateInstaller_.state();
        if (st.hasPending) {
            hadPending = true;
            pendingBundle = st.pendingBundle;
        }
        if (!updateInstaller_.rollback(&reason)) {
            throw std::runtime_error("install_rollback_failed: " + reason);
        }
        installerAfter = updateInstaller_.state();
    }

    if (hadPending) {
        std::string clearReason;
        std::lock_guard<std::mutex> lock(implantSafetyMtx_);
        implantSafetyPipeline_.clearRecord(pendingBundle, &clearReason);
    }

    json out;
    out["status"] = "ok";
    out["reason"] = reason;
    out["installer"] = updateInstallerStateToJson(installerAfter);
    return out.dump();
}

std::string handleRpcNaanStatus(const std::string& paramsJson) {
    (void)paramsJson;

    json rooms;
    auto toArray = [](const std::vector<std::string>& items) {
        json arr = json::array();
        for (const auto& item : items) arr.push_back(item);
        return arr;
    };
    rooms["tasks"] = toArray(agentCoordination_.listRooms(core::RoomType::TASKS));
    rooms["reviews"] = toArray(agentCoordination_.listRooms(core::RoomType::REVIEWS));
    rooms["disputes"] = toArray(agentCoordination_.listRooms(core::RoomType::DISPUTES));
    rooms["alerts"] = toArray(agentCoordination_.listRooms(core::RoomType::ALERTS));
    auto webEngineToString = [](web::SearchEngine engine) {
        switch (engine) {
            case web::SearchEngine::GOOGLE: return "google";
            case web::SearchEngine::BING: return "bing";
            case web::SearchEngine::DUCKDUCKGO: return "duckduckgo";
            case web::SearchEngine::BRAVE: return "brave";
            case web::SearchEngine::AHMIA: return "ahmia";
            case web::SearchEngine::TORCH: return "torch";
            case web::SearchEngine::NOTEVIL: return "notevil";
            case web::SearchEngine::DARKSEARCH: return "darksearch";
            case web::SearchEngine::DEEPSEARCH: return "deepsearch";
            case web::SearchEngine::CUSTOM: return "custom";
        }
        return "custom";
    };

    json out;
    auto score = agentScore_.snapshot();
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    const auto runtimeState = naanRuntimeInitialized_.load()
        ? currentNaanFailoverState(now)
        : core::AgentRuntimeFailoverState::RECOVERY;
    const auto crashState = naanRuntimeSupervisor_.crashState();
    const auto schedulerState = naanTaskScheduler_.snapshot();
    out["status"] = "ok";
    out["agentId"] = crypto::toHex(attachedAgentIdentity_.id);
    out["runtimeState"] = core::failoverStateToString(runtimeState);
    out["runtimeInitialized"] = naanRuntimeInitialized_.load();
    out["runtimeStartedAt"] = naanRuntimeStartedAt_.load();
    out["runtimeCrashCount"] = crashState.totalCrashes;
    out["runtimeConsecutiveCrashes"] = crashState.consecutiveCrashes;
    out["runtimeLastCrashAt"] = crashState.lastCrashTimestamp;
    out["runtimeRecoveryUntil"] = crashState.recoveryUntilTimestamp;
    out["runtimeRecoverySkips"] = naanRecoverySkips_.load();
    out["schedulerTick"] = schedulerState.tick;
    out["schedulerEpochStartTick"] = schedulerState.epochStartTick;
    out["schedulerEpochIndex"] = schedulerState.epochIndex;
    out["schedulerRoundRobinCursor"] = schedulerState.roundRobinCursor;
    json schedulerBudget;
    schedulerBudget["cpu"] = schedulerState.remaining.cpu;
    schedulerBudget["ram"] = schedulerState.remaining.ram;
    schedulerBudget["network"] = schedulerState.remaining.network;
    out["schedulerBudgetRemaining"] = schedulerBudget;
    out["humanWritable"] = false;
    out["rooms"] = rooms;
    out["totalMessages"] = agentCoordination_.totalMessages();
    out["draftQueueSize"] = agentDraftQueue_.size();
    out["queuedDrafts"] = agentDraftQueue_.listByStatus(core::DraftStatus::QUEUED, 1000000).size();
    out["reviewDrafts"] = agentDraftQueue_.listByStatus(core::DraftStatus::REVIEW_REQUIRED, 1000000).size();
    out["approvedDrafts"] = agentDraftQueue_.listByStatus(core::DraftStatus::APPROVED, 1000000).size();
    out["rejectedDrafts"] = agentDraftQueue_.listByStatus(core::DraftStatus::REJECTED, 1000000).size();
    out["submittedDrafts"] = agentDraftQueue_.listByStatus(core::DraftStatus::SUBMITTED, 1000000).size();
    out["pipelineRuns"] = naanPipelineRuns_.load();
    out["pipelineApproved"] = naanPipelineApproved_.load();
    out["pipelineSubmitted"] = naanPipelineSubmitted_.load();
    out["pipelineRejected"] = naanPipelineRejected_.load();
    out["lastPipelineAt"] = naanLastPipelineTs_.load();
    out["agentScore"] = score.score;
    out["agentScoreBand"] = core::agentScoreBandToString(score.band);
    out["agentThrottled"] = score.throttled;
    out["agentReviewOnly"] = score.reviewOnly;
    out["agentLocalDraftOnly"] = score.localDraftOnly;
    out["agentQuarantined"] = score.quarantined;
    std::string quarantineReason = "none";
    uint64_t quarantineReasonSince = 0;
    if (score.quarantined) {
        quarantineReasonSince = naanConnectorAbuseLastAt_.load();
        if (quarantineReasonSince > 0) {
            quarantineReason = "connector_auto_quarantine";
        } else if (score.localDraftOnly) {
            quarantineReason = "score_policy_local_draft_only";
        } else if (score.reviewOnly) {
            quarantineReason = "score_policy_review_only";
        } else if (score.throttled) {
            quarantineReason = "score_policy_throttled";
        } else {
            quarantineReason = "score_policy";
        }
    }
    out["agentQuarantineReason"] = quarantineReason;
    out["agentQuarantineReasonSince"] = quarantineReasonSince;
    out["pipelineBatchLimit"] = score.batchLimit;
    auto pipelineCfg = agentSubmissionPipeline_.config();
    out["reviewDiversityMinDistinctReviewers"] = pipelineCfg.minDistinctReviewers;
    out["reviewDiversityRequireNonAuthor"] = pipelineCfg.requireNonAuthorReviewer;
    out["reviewDiversityIncludeReviewRequired"] = pipelineCfg.includeReviewRequired;
    out["duplicateGateContentId"] = pipelineCfg.duplicateGateContentId;
    out["duplicateGateNoveltyBuckets"] = pipelineCfg.duplicateGateNoveltyBuckets;
    out["duplicateGateCitationGraph"] = pipelineCfg.duplicateGateCitationGraph;
    out["duplicateGateCitationGraphMaxHamming"] = pipelineCfg.duplicateCitationGraphMaxHamming;
    out["citationSanityMaxCitations"] = pipelineCfg.citationSanityMaxCitations;
    out["citationSanityRejectDuplicateCitations"] = pipelineCfg.citationSanityRejectDuplicateCitations;
    out["citationSanityRequireKnownCitations"] = pipelineCfg.citationSanityRequireKnownCitations;
    out["citationSanityRejectSelfReference"] = pipelineCfg.citationSanityRejectSelfReference;
    out["citationSanityRejectIntraSetCycles"] = pipelineCfg.citationSanityRejectIntraSetCycles;
    out["citationSanityMaxIntraSetEdges"] = pipelineCfg.citationSanityMaxIntraSetEdges;
    out["citationSanityMinCorroboratingCitations"] = pipelineCfg.citationSanityMinCorroboratingCitations;
    out["citationSanityMinDistinctAuthors"] = pipelineCfg.citationSanityMinDistinctCitationAuthors;
    const auto schedule = agentAdaptiveScheduler_.schedule(score.throttled, score.quarantined);
    out["schedulerState"] = core::schedulingStateToString(schedule.state);
    out["draftIntervalSec"] = schedule.draftIntervalSeconds;
    out["pipelineIntervalSec"] = schedule.pipelineIntervalSeconds;
    out["heartbeatIntervalSec"] = schedule.heartbeatIntervalSeconds;
    out["agentScoreSteps"] = score.steps;
    out["agentScoreCleanSteps"] = score.cleanSteps;
    out["agentAcceptedTotal"] = score.acceptedTotal;
    out["agentRejectedTotal"] = score.rejectedTotal;
    out["agentViolationsTotal"] = score.violationsTotal;
    out["agentScoreDecayIntervalSec"] = naanScoreDecayIntervalSeconds_.load();
    out["agentScoreLastDecayAt"] = naanScoreLastDecayTs_.load();
    out["agentScoreLastViolationTick"] = naanScoreLastViolationTick_.load();
    out["agentScoreBandTransitions"] = naanScoreBandTransitions_.load();
    out["agentQuarantineRecoveries"] = naanQuarantineRecoveryTransitions_.load();
    out["agentQuarantineRecoveryLastAt"] = naanQuarantineRecoveryLastAt_.load();
    out["agentAbuseSpamPenalty"] = naanAbuseSpamPenalty_.load();
    out["agentAbuseCitationPenalty"] = naanAbuseCitationPenalty_.load();
    out["agentAbusePolicyPenalty"] = naanAbusePolicyPenalty_.load();
    auto policyHashes = securityPolicyHashes();
    out["policyHashNaan"] = policyHashes.first;
    out["policyHashImplant"] = policyHashes.second;
    out["securityEvents"] = naanSecurityEvents_.load();
    out["securityHighSeverityEvents"] = naanSecurityHighSeverityEvents_.load();
    out["securityLastEventAt"] = naanSecurityLastEventAt_.load();
    auto storageStats = naanAuditLog_.stats();
    out["storageRoot"] = storageStats.rootDir;
    out["storageAuditSegments"] = storageStats.segmentCount;
    out["storageAuditRetainedEvents"] = storageStats.retainedEvents;
    out["storageAuditLastSeq"] = storageStats.lastSequence;
    out["storageAuditLastHash"] = crypto::toHex(storageStats.lastHash);
    out["storageAuditRecoveredLines"] = naanStorageRecoveredLines_.load();
    out["storageAuditDroppedSegments"] = naanStorageDroppedSegments_.load();
    out["storageIndexRecoveryRuns"] = naanIndexRecoveryRuns_.load();
    out["storageIndexRecoveryLastAt"] = naanIndexRecoveryLastAt_.load();
    out["storageConsistencyChecks"] = naanConsistencyChecks_.load();
    out["storageConsistencyRepairs"] = naanConsistencyRepairs_.load();
    out["storageConsistencyLastAt"] = naanConsistencyLastAt_.load();
    out["connectorAutoQuarantineEvents"] = naanConnectorAbuseEvents_.load();
    out["connectorAutoQuarantineLastAt"] = naanConnectorAbuseLastAt_.load();
    out["connectorAutoQuarantineLastPolicyDelta"] = naanConnectorAbuseLastPolicyDelta_.load();
    out["connectorAutoQuarantineLastFailureDelta"] = naanConnectorAbuseLastFailureDelta_.load();
    out["connectorAutoQuarantineLastViolations"] = naanConnectorAbuseLastViolations_.load();
    out["taskRunsResearch"] = naanTaskResearchRuns_.load();
    out["taskRunsVerify"] = naanTaskVerifyRuns_.load();
    out["taskRunsReview"] = naanTaskReviewRuns_.load();
    out["taskRunsDraft"] = naanTaskDraftRuns_.load();
    out["taskRunsSubmit"] = naanTaskSubmitRuns_.load();
    out["lastResearchAt"] = naanLastResearchTs_.load();
    out["lastVerifyAt"] = naanLastVerifyTs_.load();
    out["lastReviewAt"] = naanLastReviewTs_.load();
    out["lastActionAt"] = naanLastActionTs_.load();
    out["lastHeartbeatAt"] = naanLastHeartbeatTs_.load();
    out["lastDraftAt"] = naanLastDraftTs_.load();
    out["ticks"] = naanTickCount_.load();

    json connectorStatus;
    connectorStatus["available"] = false;
    json activeEngines;
    activeEngines["clearnet"] = json::array();
    activeEngines["darknet"] = json::array();
    activeEngines["customClearnetCount"] = 0;
    activeEngines["customDarknetCount"] = 0;
    activeEngines["directOnionCount"] = 0;
    json fetchCounts;
    fetchCounts["totalSearches"] = 0;
    fetchCounts["clearnetSearches"] = 0;
    fetchCounts["darknetSearches"] = 0;
    fetchCounts["successfulFetches"] = 0;
    fetchCounts["failedFetches"] = 0;
    fetchCounts["pagesExtracted"] = 0;
    fetchCounts["bytesDownloaded"] = 0;
    fetchCounts["avgResponseTime"] = 0.0;
    fetchCounts["routePolicyChecks"] = 0;
    fetchCounts["routePolicyPassed"] = 0;
    fetchCounts["routePolicyBlocked"] = 0;
    fetchCounts["routePolicyPassRate"] = 0.0;
    json policyBlocks;
    policyBlocks["clearnet"] = 0;
    policyBlocks["tor"] = 0;
    policyBlocks["onion"] = 0;
    policyBlocks["total"] = 0;
    json configValidation;
    configValidation["totalLines"] = naanWebConfigTotalLines_.load();
    configValidation["appliedLines"] = naanWebConfigAppliedLines_.load();
    configValidation["invalidLines"] = naanWebConfigInvalidLines_.load();
    configValidation["unknownKeys"] = naanWebConfigUnknownKeys_.load();
    configValidation["sanitizedWrites"] = naanWebConfigSanitizedWrites_.load();
    configValidation["unknownKeySamples"] = json::array();
    {
        std::lock_guard<std::mutex> lock(webMtx_);
        for (const auto& key : naanWebConfigUnknownKeySamples_) {
            configValidation["unknownKeySamples"].push_back(key);
        }
        if (webSearch_) {
            auto toHealthJson = [](const web::ConnectorHealthSnapshot& snap) {
                json h;
                h["state"] = web::connectorHealthStateToString(snap.state);
                h["transitions"] = snap.transitions;
                h["successes"] = snap.successes;
                h["failures"] = snap.failures;
                h["policyBlocks"] = snap.policyBlocks;
                h["consecutiveSuccesses"] = snap.consecutiveSuccesses;
                h["consecutiveFailures"] = snap.consecutiveFailures;
                return h;
            };
            auto toEngineArray = [&](const std::vector<web::SearchEngine>& engines) {
                json arr = json::array();
                for (auto engine : engines) {
                    arr.push_back(webEngineToString(engine));
                }
                return arr;
            };

            auto health = webSearch_->getConnectorHealth();
            auto cfg = webSearch_->getConfig();
            auto stats = webSearch_->getStats();
            connectorStatus["available"] = true;
            connectorStatus["clearnet"] = toHealthJson(health.clearnet);
            connectorStatus["tor"] = toHealthJson(health.tor);
            connectorStatus["onion"] = toHealthJson(health.onion);
            connectorStatus["allowlistCount"] = cfg.fetchAllowlistRoutes.size();
            connectorStatus["denylistCount"] = cfg.fetchDenylistRoutes.size();
            connectorStatus["clearnetSiteAllowCount"] = cfg.clearnetSiteAllowlist.size();
            connectorStatus["clearnetSiteDenyCount"] = cfg.clearnetSiteDenylist.size();
            connectorStatus["onionSiteAllowCount"] = cfg.onionSiteAllowlist.size();
            connectorStatus["onionSiteDenyCount"] = cfg.onionSiteDenylist.size();
            connectorStatus["clearnetBypassHostCount"] = cfg.clearnetRouteBypassHosts.size();
            connectorStatus["onionBypassHostCount"] = cfg.onionRouteBypassHosts.size();
            connectorStatus["bypassOnionHttpsFallback"] = cfg.bypassOnionHttpsFallback;
            connectorStatus["sitePolicyPath"] = config_.dataDir + "/naan_agent_web.conf";
            activeEngines["clearnet"] = toEngineArray(cfg.clearnetEngines);
            activeEngines["darknet"] = toEngineArray(cfg.darknetEngines);
            activeEngines["customClearnetCount"] = cfg.customClearnetUrls.size();
            activeEngines["customDarknetCount"] = cfg.customDarknetUrls.size();
            activeEngines["directOnionCount"] = cfg.directOnionLinks.size();
            fetchCounts["totalSearches"] = stats.totalSearches;
            fetchCounts["clearnetSearches"] = stats.clearnetSearches;
            fetchCounts["darknetSearches"] = stats.darknetSearches;
            fetchCounts["successfulFetches"] = stats.successfulFetches;
            fetchCounts["failedFetches"] = stats.failedFetches;
            fetchCounts["pagesExtracted"] = stats.pagesExtracted;
            fetchCounts["bytesDownloaded"] = stats.bytesDownloaded;
            fetchCounts["avgResponseTime"] = stats.avgResponseTime;
            fetchCounts["routePolicyChecks"] = stats.routePolicyChecks;
            fetchCounts["routePolicyPassed"] = stats.routePolicyPassed;
            fetchCounts["routePolicyBlocked"] = stats.routePolicyBlocked;
            if (stats.routePolicyChecks == 0) {
                fetchCounts["routePolicyPassRate"] = 0.0;
            } else {
                fetchCounts["routePolicyPassRate"] =
                    static_cast<double>(stats.routePolicyPassed) / static_cast<double>(stats.routePolicyChecks);
            }
            policyBlocks["clearnet"] = health.clearnet.policyBlocks;
            policyBlocks["tor"] = health.tor.policyBlocks;
            policyBlocks["onion"] = health.onion.policyBlocks;
            policyBlocks["total"] = health.clearnet.policyBlocks + health.tor.policyBlocks + health.onion.policyBlocks;
        }
    }
    out["activeEngines"] = activeEngines;
    out["fetchCounts"] = fetchCounts;
    out["policyBlocks"] = policyBlocks;
    out["webConfigValidation"] = configValidation;
    out["webFailClosedSkips"] = naanWebFailClosedSkips_.load();
    out["miningFailClosedSkips"] = miningFailClosedSkips_.load();
    const auto route = refreshTorRoutePolicy(true);
    const bool torRequired = agentTorRequired_.load();
    const bool torReachable = agentTorReachable_.load();
    const bool torReadyForWeb = agentTorWebReady_.load();
    const bool torManaged = agentTorManaged_.load();
    const std::string torRuntimeMode = configuredTorRuntimeMode();
    const uint16_t torSocksPort = configuredTorSocksPort();
    const uint16_t torControlPort = configuredTorControlPort();
    const bool torControlReachable = probeTorControl();
    const bool onionServiceActive = isOnionServiceActive();
    const bool torConflictHint9050 = likelyTor9050vs9150ConflictHint(torReachable);
    const std::string torBootstrapState = core::evaluateTorBootstrapState(
        {torRequired, torReachable, torReadyForWeb, route.torDegraded});
    const uint32_t torBootstrapPercent = core::evaluateTorBootstrapPercent(
        {torRequired, torReachable, torReadyForWeb, route.torDegraded});
    const bool torReadyForOnion = core::evaluateTorReadyForOnion(
        {torRequired, torReachable, torReadyForWeb, route.torDegraded});
    const std::string torWebProbeLastError = getTorWebProbeLastError();
    const std::string torBootstrapReasonCode = core::evaluateTorBootstrapReasonCode(
        {torRequired, torReachable, torReadyForWeb, route.torDegraded},
        torWebProbeLastError);
    const core::TorOnionServiceStateInput onionSvcIn{
        torRequired,
        torReachable,
        torReadyForWeb,
        route.torDegraded,
        config_.privacyMode,
        torControlReachable,
        onionServiceActive};
    const std::string torOnionServiceState = core::evaluateTorOnionServiceState(onionSvcIn);
    const bool torReadyForOnionService = core::evaluateTorReadyForOnionService(onionSvcIn);
    const std::string torLastBootstrapError = torReadyForWeb
        ? std::string()
        : (torWebProbeLastError.empty() ? torBootstrapReasonCode : torWebProbeLastError);
    const bool allowFallback = agentAllowClearnetFallback_.load();
    const bool allowP2PFallback = agentAllowP2PFallback_.load();
    out["torRequired"] = torRequired;
    out["torSocksReachable"] = torReachable;
    out["torReachable"] = torReachable;
    out["torReadyForWeb"] = torReadyForWeb;
    out["torManaged"] = torManaged;
    out["torManagedPid"] = managedTorPid_.load();
    out["torRuntimeMode"] = torRuntimeMode;
    out["torSocksPort"] = torSocksPort;
    out["torControlPort"] = torControlPort;
    out["torControlReachable"] = torControlReachable;
    out["torConflictHint9050"] = torConflictHint9050;
    out["torBootstrapState"] = torBootstrapState;
    out["torBootstrapPercent"] = torBootstrapPercent;
    out["torReadyForOnion"] = torReadyForOnion;
    out["torReadyForOnionService"] = torReadyForOnionService;
    out["torOnionServiceActive"] = onionServiceActive;
    out["torOnionServiceState"] = torOnionServiceState;
    out["torBootstrapReasonCode"] = torBootstrapReasonCode;
    out["torLastBootstrapError"] = torLastBootstrapError;
    out["torDegraded"] = route.torDegraded;
    out["torWebProbeLastAt"] = agentTorWebProbeLastAt_.load();
    out["torWebProbeLastOkAt"] = agentTorWebProbeLastOkAt_.load();
    out["torWebProbeExitCode"] = agentTorWebProbeExitCode_.load();
    out["torWebProbeLastError"] = torWebProbeLastError;
    out["torWebProbeConsecutiveFailures"] = agentTorWebProbeConsecutiveFailures_.load();
    out["torWebProbeConsecutiveSuccesses"] = agentTorWebProbeConsecutiveSuccesses_.load();
    out["torBridgeSubsetPersistCount"] = agentTorBridgeSubsetPersistCount_.load();
    out["torBridgeSubsetLastPersistAt"] = agentTorBridgeSubsetLastPersistAt_.load();
    out["torBridgeSubsetLastEpoch"] = agentTorBridgeSubsetLastEpoch_.load();
    out["torBridgeSubsetLastCount"] = agentTorBridgeSubsetLastCount_.load();
    out["torBridgeSubsetPath"] = torLastKnownGoodBridgeSubsetPath().string();
    out["torBridgeRemoteLastFetchAt"] = agentTorBridgeRemoteLastFetchAt_.load();
    out["torBridgeRemoteFetchAttempts"] = agentTorBridgeRemoteFetchAttempts_.load();
    out["torBridgeRemoteFetchSuccesses"] = agentTorBridgeRemoteFetchSuccesses_.load();
    out["torBridgeRemoteRateLimitedSkips"] = agentTorBridgeRemoteRateLimitedSkips_.load();
    const json torBridgeProviderMeta = getTorBridgeProviderMetaSnapshot();
    const uint64_t torBridgeProviderUpdatedAt = torBridgeProviderMetaUpdatedAt_.load();
    out["torBridgeProvider"] = torBridgeProviderMeta;
    out["torBridgeProviderUpdatedAt"] = torBridgeProviderUpdatedAt;
    if (torBridgeProviderMeta.contains("cacheSavedAt") && torBridgeProviderMeta["cacheSavedAt"].is_number_unsigned()) {
        const uint64_t cacheSavedAt = torBridgeProviderMeta.value("cacheSavedAt", static_cast<uint64_t>(0));
        const uint64_t nowTs = static_cast<uint64_t>(std::time(nullptr));
        if (cacheSavedAt != 0 && nowTs >= cacheSavedAt) {
            out["torBridgeCacheAgeSeconds"] = nowTs - cacheSavedAt;
        } else {
            out["torBridgeCacheAgeSeconds"] = 0;
        }
    } else {
        out["torBridgeCacheAgeSeconds"] = 0;
    }
    out["routeMode"] = route.routeMode;
    out["clearnetFallbackAllowed"] = allowFallback;
    out["p2pFallbackAllowed"] = allowP2PFallback;
    json torRoute;
    torRoute["mode"] = route.routeMode;
    torRoute["required"] = torRequired;
    torRoute["socksReachable"] = torReachable;
    torRoute["reachable"] = torReachable;
    torRoute["webReady"] = torReadyForWeb;
    torRoute["managed"] = torManaged;
    torRoute["managedPid"] = managedTorPid_.load();
    torRoute["runtimeMode"] = torRuntimeMode;
    torRoute["socksPort"] = torSocksPort;
    torRoute["controlPort"] = torControlPort;
    torRoute["controlReachable"] = torControlReachable;
    torRoute["conflictHint9050"] = torConflictHint9050;
    torRoute["bootstrapState"] = torBootstrapState;
    torRoute["bootstrapPercent"] = torBootstrapPercent;
    torRoute["readyForOnion"] = torReadyForOnion;
    torRoute["readyForOnionService"] = torReadyForOnionService;
    torRoute["onionServiceActive"] = onionServiceActive;
    torRoute["onionServiceState"] = torOnionServiceState;
    torRoute["webProbeConsecutiveFailures"] = agentTorWebProbeConsecutiveFailures_.load();
    torRoute["webProbeConsecutiveSuccesses"] = agentTorWebProbeConsecutiveSuccesses_.load();
    torRoute["reasonCode"] = torBootstrapReasonCode;
    torRoute["lastBootstrapError"] = torLastBootstrapError;
    torRoute["degraded"] = route.torDegraded;
    torRoute["bridgeSubsetPersistCount"] = agentTorBridgeSubsetPersistCount_.load();
    torRoute["bridgeSubsetLastPersistAt"] = agentTorBridgeSubsetLastPersistAt_.load();
    torRoute["bridgeSubsetLastEpoch"] = agentTorBridgeSubsetLastEpoch_.load();
    torRoute["bridgeSubsetLastCount"] = agentTorBridgeSubsetLastCount_.load();
    torRoute["bridgeSubsetPath"] = torLastKnownGoodBridgeSubsetPath().string();
    torRoute["bridgeRemoteLastFetchAt"] = agentTorBridgeRemoteLastFetchAt_.load();
    torRoute["bridgeRemoteFetchAttempts"] = agentTorBridgeRemoteFetchAttempts_.load();
    torRoute["bridgeRemoteFetchSuccesses"] = agentTorBridgeRemoteFetchSuccesses_.load();
    torRoute["bridgeRemoteRateLimitedSkips"] = agentTorBridgeRemoteRateLimitedSkips_.load();
    torRoute["bridgeProvider"] = torBridgeProviderMeta;
    torRoute["bridgeProviderUpdatedAt"] = torBridgeProviderUpdatedAt;
    torRoute["bridgeCacheAgeSeconds"] = out.value("torBridgeCacheAgeSeconds", static_cast<uint64_t>(0));
    torRoute["allowWebClearnet"] = route.allowWebClearnet;
    torRoute["allowWebOnion"] = route.allowWebOnion;
    torRoute["allowP2PDiscovery"] = route.allowP2PDiscovery;
    torRoute["clearnetFallbackAllowed"] = allowFallback;
    torRoute["p2pFallbackAllowed"] = allowP2PFallback;
    torRoute["failClosedActive"] = torRequired && (!route.allowP2PDiscovery || !torReadyForWeb);
    out["torRoute"] = torRoute;
    connectorStatus["activeEngines"] = activeEngines;
    connectorStatus["fetchCounts"] = fetchCounts;
    connectorStatus["policyBlocks"] = policyBlocks;
    connectorStatus["configValidation"] = configValidation;
    connectorStatus["torRoute"] = torRoute;
    out["connectorStatus"] = connectorStatus;
    json networkHealth;
    networkHealth["available"] = false;
    if (network_) {
        auto netStats = network_->getStats();
        const uint64_t peerPressure = config_.maxPeers == 0 ? 0 : (netStats.totalPeers * 100ULL / config_.maxPeers);
        const uint64_t inboundPressure = config_.maxInbound == 0 ? 0 : (netStats.inboundPeers * 100ULL / config_.maxInbound);
        const uint64_t outboundPressure = config_.maxOutbound == 0 ? 0 : (netStats.outboundPeers * 100ULL / config_.maxOutbound);
        const uint64_t ledgerHeight = ledger_ ? ledger_->height() : 0;
        const uint64_t netHeight = networkHeight_.load();
        const uint64_t consensusLag = (netHeight > ledgerHeight) ? (netHeight - ledgerHeight) : 0;
        networkHealth["available"] = true;
        networkHealth["peerPressurePercent"] = peerPressure;
        networkHealth["inboundPressurePercent"] = inboundPressure;
        networkHealth["outboundPressurePercent"] = outboundPressure;
        networkHealth["overloadMode"] = netStats.overloadMode;
        networkHealth["bufferedRxBytes"] = netStats.bufferedRxBytes;
        networkHealth["rejectedConnections"] = netStats.rejectedConnections;
        networkHealth["evictedPeers"] = netStats.evictedPeers;
        networkHealth["tempBans"] = netStats.tempBans;
        networkHealth["malformedMessages"] = netStats.malformedMessages;
        networkHealth["rateLimitedEvents"] = netStats.rateLimitedEvents;
        networkHealth["overloadTransitions"] = netStats.overloadTransitions;
        networkHealth["activeBans"] = network_->getBannedPeers().size();
        networkHealth["invBackpressureDrops"] = invBackpressureDrops_.load();
        networkHealth["getdataBackpressureDrops"] = getDataBackpressureDrops_.load();
        networkHealth["gossipSuppressed"] = gossipSuppressed_.load();
        networkHealth["gossipSubsetRouted"] = gossipSubsetRouted_.load();
        networkHealth["consensusLag"] = consensusLag;
    }
    out["networkHealth"] = networkHealth;
    uint64_t rewardObserved = 0;
    uint64_t rewardFinalized = 0;
    uint64_t rewardCredited = 0;
    uint64_t rewardExpectedAtoms = 0;
    uint64_t rewardCreditedAtoms = 0;
    if (poeV1_ && attachedAgentIdentity_.valid()) {
        auto submitted = agentDraftQueue_.listByStatus(core::DraftStatus::SUBMITTED, 1000000);
        for (const auto& rec : submitted) {
            auto dry = agentSubmissionPipeline_.dryRun(rec, attachedAgentIdentity_.privateKey, *poeV1_);
            if (!dry.ok) continue;
            rewardObserved += 1;
            const uint64_t expectedAtoms = poeV1_->calculateAcceptanceReward(dry.entry);
            if (UINT64_MAX - rewardExpectedAtoms < expectedAtoms) rewardExpectedAtoms = UINT64_MAX;
            else rewardExpectedAtoms += expectedAtoms;
            if (poeV1_->isFinalized(dry.entry.submitId())) {
                rewardFinalized += 1;
            }
            const bool credited = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(dry.entry.submitId())) : false;
            if (credited) {
                rewardCredited += 1;
                if (UINT64_MAX - rewardCreditedAtoms < expectedAtoms) rewardCreditedAtoms = UINT64_MAX;
                else rewardCreditedAtoms += expectedAtoms;
            }
        }
    }
    out["agentRewardVisibilityDeterministic"] = true;
    out["agentRewardObservedSubmissions"] = rewardObserved;
    out["agentRewardFinalizedSubmissions"] = rewardFinalized;
    out["agentRewardCreditedSubmissions"] = rewardCredited;
    out["agentRewardExpectedAtoms"] = rewardExpectedAtoms;
    out["agentRewardCreditedAtoms"] = rewardCreditedAtoms;
    out["redactionCount"] = naanRedactionCount_.load();
    return out.dump();
}

std::string handleRpcNaanObservatoryArtifacts(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);

    uint64_t sinceTimestamp = 0;
    if (params.contains("sinceTimestamp")) {
        sinceTimestamp = static_cast<uint64_t>(std::max<int64_t>(0, params.value("sinceTimestamp", 0)));
    } else if (params.contains("since")) {
        sinceTimestamp = static_cast<uint64_t>(std::max<int64_t>(0, params.value("since", 0)));
    }

    uint32_t limit = 100;
    if (params.contains("limit")) {
        int64_t raw = params.value("limit", 100);
        if (raw < 1) raw = 1;
        if (raw > 500) raw = 500;
        limit = static_cast<uint32_t>(raw);
    }

    auto feed = agentCoordination_.getObservatoryFeed(sinceTimestamp, limit);
    json items = json::array();
    for (const auto& entry : feed) {
        items.push_back(observatoryEntryToJson(entry));
    }

    json out;
    out["status"] = "ok";
    out["count"] = items.size();
    out["items"] = items;
    return out.dump();
}

std::string handleRpcNaanObservatoryArtifactGet(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string hashHex = params.value("hash", "");
    if (hashHex.empty()) {
        hashHex = params.value("id", "");
    }
    if (hashHex.empty()) {
        throw std::runtime_error("hash required");
    }

    crypto::Hash256 hash = parseHash256Hex(hashHex);
    auto artifact = agentCoordination_.getArtifact(hash);
    if (!artifact) {
        throw std::runtime_error("not_found");
    }

    json out = signedArtifactToJson(*artifact, true);
    out["status"] = "ok";
    return out.dump();
}

std::string handleRpcNaanObservatoryDrafts(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);

    uint32_t limit = 100;
    if (params.contains("limit")) {
        int64_t raw = params.value("limit", 100);
        if (raw < 1) raw = 1;
        if (raw > 500) raw = 500;
        limit = static_cast<uint32_t>(raw);
    }

    bool includeRejected = true;
    if (params.contains("includeRejected")) {
        includeRejected = params.value("includeRejected", true);
    }

    std::vector<core::AgentDraftRecord> records;
    if (params.contains("status") && params["status"].is_string()) {
        records = agentDraftQueue_.listByStatus(core::stringToDraftStatus(params["status"].get<std::string>()), limit);
        if (!includeRejected && params["status"].get<std::string>() == "rejected") {
            records.clear();
        }
    } else {
        records = agentDraftQueue_.list(limit, includeRejected);
    }

    json out;
    out["status"] = "ok";
    out["count"] = records.size();
    out["items"] = json::array();
    for (const auto& rec : records) {
        out["items"].push_back(draftRecordToJson(rec, false));
    }
    return out.dump();
}

std::string handleRpcNaanObservatoryDraftGet(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    std::string idHex = params.value("draftId", "");
    if (idHex.empty()) {
        idHex = params.value("id", "");
    }
    if (idHex.empty()) {
        throw std::runtime_error("draftId required");
    }

    crypto::Hash256 draftId = parseHash256Hex(idHex);
    auto record = agentDraftQueue_.get(draftId);
    if (!record) {
        throw std::runtime_error("not_found");
    }

    json out = draftRecordToJson(*record, true);
    out["status"] = "ok";
    return out.dump();
}

std::string handleRpcNaanPipelineDryRun(const std::string& paramsJson) {
    if (!naanRuntimeInitialized_.load()) {
        throw std::runtime_error("naan_runtime_uninitialized");
    }
    if (!poeV1_) {
        throw std::runtime_error("poe_unavailable");
    }
    if (!attachedAgentIdentity_.valid()) {
        throw std::runtime_error("agent_identity_unavailable");
    }

    auto params = parseRpcParams(paramsJson);
    uint32_t limit = 64;
    if (params.contains("limit")) {
        int64_t raw = params.value("limit", 64);
        if (raw < 1) raw = 1;
        if (raw > 500) raw = 500;
        limit = static_cast<uint32_t>(raw);
    }

    std::vector<core::AgentDraftRecord> records;
    auto queued = agentDraftQueue_.listByStatus(core::DraftStatus::QUEUED, 1000000);
    auto review = agentDraftQueue_.listByStatus(core::DraftStatus::REVIEW_REQUIRED, 1000000);
    auto approved = agentDraftQueue_.listByStatus(core::DraftStatus::APPROVED, 1000000);
    records.reserve(queued.size() + review.size() + approved.size());
    records.insert(records.end(), queued.begin(), queued.end());
    records.insert(records.end(), review.begin(), review.end());
    records.insert(records.end(), approved.begin(), approved.end());
    std::sort(records.begin(), records.end(), [](const core::AgentDraftRecord& a, const core::AgentDraftRecord& b) {
        const std::string ah = crypto::toHex(a.proposal.draftId());
        const std::string bh = crypto::toHex(b.proposal.draftId());
        if (ah != bh) return ah < bh;
        return a.proposal.createdAt < b.proposal.createdAt;
    });

    json out;
    out["status"] = "ok";
    out["count"] = 0;
    out["items"] = json::array();
    for (const auto& rec : records) {
        if (out["items"].size() >= limit) break;
        auto dry = agentSubmissionPipeline_.dryRun(rec, attachedAgentIdentity_.privateKey, *poeV1_);
        out["items"].push_back(draftDryRunToJson(dry));
    }
    auto score = agentScore_.snapshot();
    const auto schedule = agentAdaptiveScheduler_.schedule(score.throttled, score.quarantined);
    out["count"] = out["items"].size();
    out["agentScore"] = score.score;
    out["agentThrottled"] = score.throttled;
    out["agentQuarantined"] = score.quarantined;
    out["pipelineBatchLimit"] = score.batchLimit;
    out["schedulerState"] = core::schedulingStateToString(schedule.state);
    out["draftIntervalSec"] = schedule.draftIntervalSeconds;
    out["pipelineIntervalSec"] = schedule.pipelineIntervalSeconds;
    out["heartbeatIntervalSec"] = schedule.heartbeatIntervalSeconds;
    return out.dump();
}

std::string handleRpcNaanPipelineDrain(const std::string& paramsJson) {
    if (!naanRuntimeInitialized_.load()) {
        throw std::runtime_error("naan_runtime_uninitialized");
    }
    if (!poeV1_) {
        throw std::runtime_error("poe_unavailable");
    }
    if (!attachedAgentIdentity_.valid()) {
        throw std::runtime_error("agent_identity_unavailable");
    }

    auto params = parseRpcParams(paramsJson);
    uint32_t limit = 0;
    if (params.contains("limit")) {
        int64_t raw = params.value("limit", 0);
        if (raw < 1) raw = 1;
        if (raw > 500) raw = 500;
        limit = static_cast<uint32_t>(raw);
    }

    uint64_t atTimestamp = static_cast<uint64_t>(std::time(nullptr));
    if (params.contains("atTimestamp")) {
        int64_t rawTs = params.value("atTimestamp", static_cast<int64_t>(atTimestamp));
        if (rawTs > 0) atTimestamp = static_cast<uint64_t>(rawTs);
    }

    bool skippedQuarantine = false;
    uint32_t effectiveLimit = 0;
    auto batch = runNaanPipelineDrain(atTimestamp, limit, &skippedQuarantine, &effectiveLimit);
    auto score = agentScore_.snapshot();
    const auto schedule = agentAdaptiveScheduler_.schedule(score.throttled, score.quarantined);

    json out;
    out["status"] = "ok";
    out["count"] = batch.size();
    if (limit == 0) {
        out["requestedLimit"] = nullptr;
    } else {
        out["requestedLimit"] = limit;
    }
    out["effectiveLimit"] = effectiveLimit;
    out["skipped"] = skippedQuarantine ? "quarantined" : "no";
    out["items"] = json::array();
    for (const auto& item : batch) {
        out["items"].push_back(draftBatchItemToJson(item));
    }
    out["pipelineRuns"] = naanPipelineRuns_.load();
    out["pipelineApproved"] = naanPipelineApproved_.load();
    out["pipelineSubmitted"] = naanPipelineSubmitted_.load();
    out["pipelineRejected"] = naanPipelineRejected_.load();
    out["lastPipelineAt"] = naanLastPipelineTs_.load();
    out["agentScore"] = score.score;
    out["agentThrottled"] = score.throttled;
    out["agentQuarantined"] = score.quarantined;
    out["pipelineBatchLimit"] = score.batchLimit;
    out["schedulerState"] = core::schedulingStateToString(schedule.state);
    out["draftIntervalSec"] = schedule.draftIntervalSeconds;
    out["pipelineIntervalSec"] = schedule.pipelineIntervalSeconds;
    out["heartbeatIntervalSec"] = schedule.heartbeatIntervalSeconds;
    return out.dump();
}

static std::string peerStateToString(network::PeerState s) {
    switch (s) {
        case network::PeerState::CONNECTING: return "CONNECTING";
        case network::PeerState::HANDSHAKING: return "HANDSHAKING";
        case network::PeerState::CONNECTED: return "CONNECTED";
        case network::PeerState::DISCONNECTING: return "DISCONNECTING";
        case network::PeerState::DISCONNECTED: return "DISCONNECTED";
        case network::PeerState::BANNED: return "BANNED";
    }
    return "UNKNOWN";
}

static std::string quantumSecurityLevelToString(quantum::SecurityLevel level) {
    switch (level) {
        case quantum::SecurityLevel::STANDARD: return "standard";
        case quantum::SecurityLevel::HIGH: return "high";
        case quantum::SecurityLevel::PARANOID: return "paranoid";
        case quantum::SecurityLevel::QUANTUM_READY: return "quantum-ready";
    }
    return "standard";
}

static std::string quantumAlgorithmToString(quantum::CryptoAlgorithm algo) {
    switch (algo) {
        case quantum::CryptoAlgorithm::CLASSIC_ED25519: return "classic_ed25519";
        case quantum::CryptoAlgorithm::CLASSIC_X25519: return "classic_x25519";
        case quantum::CryptoAlgorithm::CLASSIC_AES256GCM: return "classic_aes256gcm";
        case quantum::CryptoAlgorithm::LATTICE_KYBER768: return "lattice_kyber768";
        case quantum::CryptoAlgorithm::LATTICE_DILITHIUM65: return "lattice_dilithium65";
        case quantum::CryptoAlgorithm::HASH_SPHINCS128S: return "hash_sphincs128s";
        case quantum::CryptoAlgorithm::OTP_VERNAM: return "otp_vernam";
        case quantum::CryptoAlgorithm::QKD_BB84: return "qkd_bb84";
        case quantum::CryptoAlgorithm::HYBRID_KEM: return "hybrid_kem";
        case quantum::CryptoAlgorithm::HYBRID_SIG: return "hybrid_sig";
    }
    return "classic_ed25519";
}

std::string handleRpcNodeStatus(const std::string& paramsJson) {
    (void)paramsJson;
    NodeStats st = getStats();
    const auto route = refreshTorRoutePolicy(true);
    json out;
    out["running"] = running_.load();
    out["networkType"] = config_.networkType;
    out["p2pPort"] = network_ ? network_->getPort() : config_.port;
    out["rpcPort"] = config_.rpcPort;
    out["peersConnected"] = st.peersConnected;
    out["uptimeSeconds"] = st.uptime;
    out["uptime"] = formatUptime(st.uptime);
    out["syncProgress"] = st.syncProgress;
    if (ledger_) {
        out["ledgerHeight"] = ledger_->height();
        out["ledgerEvents"] = ledger_->eventCount();
        out["tipHash"] = crypto::toHex(ledger_->tipHash());
    }
    out["knowledgeEntries"] = st.knowledgeEntries;
    out["walletAddress"] = address_;
    out["privacyMode"] = config_.privacyMode;
    out["quantumSecurity"] = config_.quantumSecurity;
    json quantumStatus;
    quantumStatus["enabled"] = config_.quantumSecurity;
    quantumStatus["requestedLevel"] = config_.securityLevel;
    quantumStatus["managerInitialized"] = false;
    quantumStatus["isQuantumSafe"] = false;
    quantumStatus["effectiveLevel"] = "standard";
    quantumStatus["qkdConnected"] = false;
    quantumStatus["qkdSessionActive"] = false;
    quantumStatus["selectedKEM"] = "classic_x25519";
    quantumStatus["selectedSignature"] = "classic_ed25519";
    quantumStatus["selectedEncryption"] = "classic_aes256gcm";
    quantumStatus["qkdEncryptOperations"] = 0;
    quantumStatus["hybridEncryptOperations"] = 0;
    quantumStatus["qkdDecryptOperations"] = 0;
    quantumStatus["hybridDecryptOperations"] = 0;
    quantumStatus["qkdFallbackDecryptOperations"] = 0;
    json quantumCounters;
    quantumCounters["hybridOperations"] = 0;
    quantumCounters["qkdSessionsEstablished"] = 0;
    quantumCounters["kyberEncapsulations"] = 0;
    quantumCounters["kyberDecapsulations"] = 0;
    quantumCounters["dilithiumSignatures"] = 0;
    quantumCounters["dilithiumVerifications"] = 0;
    quantumCounters["sphincsSignatures"] = 0;
    quantumCounters["sphincsVerifications"] = 0;
    quantumCounters["otpBytesUsed"] = 0;
    quantumStatus["counters"] = quantumCounters;
    if (quantumManager_) {
        const auto runtime = quantumManager_->getRuntimeStatus();
        const auto counters = quantumManager_->getStats();
        quantumStatus["managerInitialized"] = runtime.initialized;
        quantumStatus["isQuantumSafe"] = quantumManager_->isQuantumSafe();
        quantumStatus["effectiveLevel"] = quantumSecurityLevelToString(runtime.level);
        quantumStatus["qkdConnected"] = runtime.qkdConnected;
        quantumStatus["qkdSessionActive"] = runtime.qkdSessionActive;
        quantumStatus["selectedKEM"] = quantumAlgorithmToString(runtime.selectedKEM);
        quantumStatus["selectedSignature"] = quantumAlgorithmToString(runtime.selectedSignature);
        quantumStatus["selectedEncryption"] = quantumAlgorithmToString(runtime.selectedEncryption);
        quantumStatus["qkdEncryptOperations"] = runtime.qkdEncryptOperations;
        quantumStatus["hybridEncryptOperations"] = runtime.hybridEncryptOperations;
        quantumStatus["qkdDecryptOperations"] = runtime.qkdDecryptOperations;
        quantumStatus["hybridDecryptOperations"] = runtime.hybridDecryptOperations;
        quantumStatus["qkdFallbackDecryptOperations"] = runtime.qkdFallbackDecryptOperations;
        quantumCounters["hybridOperations"] = counters.hybridOperations;
        quantumCounters["qkdSessionsEstablished"] = counters.qkdSessionsEstablished;
        quantumCounters["kyberEncapsulations"] = counters.kyberEncapsulations;
        quantumCounters["kyberDecapsulations"] = counters.kyberDecapsulations;
        quantumCounters["dilithiumSignatures"] = counters.dilithiumSignatures;
        quantumCounters["dilithiumVerifications"] = counters.dilithiumVerifications;
        quantumCounters["sphincsSignatures"] = counters.sphincsSignatures;
        quantumCounters["sphincsVerifications"] = counters.sphincsVerifications;
        quantumCounters["otpBytesUsed"] = counters.otpBytesUsed;
        quantumStatus["counters"] = quantumCounters;
    }
    out["quantum"] = quantumStatus;
    const bool torRequiredNode = agentTorRequired_.load();
    const bool torReachableNode = agentTorReachable_.load();
    const bool torReadyForWebNode = agentTorWebReady_.load();
    const bool torControlReachableNode = probeTorControl();
    const bool onionServiceActiveNode = isOnionServiceActive();
    const core::TorBootstrapStateInput torBootstrapNode{
        torRequiredNode, torReachableNode, torReadyForWebNode, route.torDegraded};
    const std::string torWebProbeLastErrorNode = getTorWebProbeLastError();
    const std::string torBootstrapReasonCodeNode =
        core::evaluateTorBootstrapReasonCode(torBootstrapNode, torWebProbeLastErrorNode);
    const core::TorOnionServiceStateInput onionSvcNode{
        torRequiredNode,
        torReachableNode,
        torReadyForWebNode,
        route.torDegraded,
        config_.privacyMode,
        torControlReachableNode,
        onionServiceActiveNode};
    const std::string torLastBootstrapErrorNode = torReadyForWebNode
        ? std::string()
        : (torWebProbeLastErrorNode.empty() ? torBootstrapReasonCodeNode : torWebProbeLastErrorNode);
    out["torRequired"] = torRequiredNode;
    out["torSocksReachable"] = torReachableNode;
    out["torReachable"] = torReachableNode;
    out["torReadyForWeb"] = torReadyForWebNode;
    out["torReadyForOnion"] = core::evaluateTorReadyForOnion(torBootstrapNode);
    out["torManaged"] = agentTorManaged_.load();
    out["torManagedPid"] = managedTorPid_.load();
    out["torRuntimeMode"] = configuredTorRuntimeMode();
    out["torSocksHost"] = configuredTorSocksHost();
    out["torSocksPort"] = configuredTorSocksPort();
    out["torControlPort"] = configuredTorControlPort();
    out["torControlReachable"] = torControlReachableNode;
    out["torConflictHint9050"] = likelyTor9050vs9150ConflictHint(torReachableNode);
    out["torBootstrapState"] = core::evaluateTorBootstrapState(torBootstrapNode);
    out["torBootstrapPercent"] = core::evaluateTorBootstrapPercent(torBootstrapNode);
    out["torReadyForOnionService"] = core::evaluateTorReadyForOnionService(onionSvcNode);
    out["torOnionServiceActive"] = onionServiceActiveNode;
    out["torOnionServiceState"] = core::evaluateTorOnionServiceState(onionSvcNode);
    out["torBootstrapReasonCode"] = torBootstrapReasonCodeNode;
    out["torLastBootstrapError"] = torLastBootstrapErrorNode;
    out["torDegraded"] = route.torDegraded;
    out["torWebProbeLastAt"] = agentTorWebProbeLastAt_.load();
    out["torWebProbeLastOkAt"] = agentTorWebProbeLastOkAt_.load();
    out["torWebProbeExitCode"] = agentTorWebProbeExitCode_.load();
    out["torWebProbeLastError"] = torWebProbeLastErrorNode;
    out["torWebProbeConsecutiveFailures"] = agentTorWebProbeConsecutiveFailures_.load();
    out["torWebProbeConsecutiveSuccesses"] = agentTorWebProbeConsecutiveSuccesses_.load();
    out["torBridgeSubsetPersistCount"] = agentTorBridgeSubsetPersistCount_.load();
    out["torBridgeSubsetLastPersistAt"] = agentTorBridgeSubsetLastPersistAt_.load();
    out["torBridgeSubsetLastEpoch"] = agentTorBridgeSubsetLastEpoch_.load();
    out["torBridgeSubsetLastCount"] = agentTorBridgeSubsetLastCount_.load();
    out["torBridgeSubsetPath"] = torLastKnownGoodBridgeSubsetPath().string();
    out["torBridgeRemoteLastFetchAt"] = agentTorBridgeRemoteLastFetchAt_.load();
    out["torBridgeRemoteFetchAttempts"] = agentTorBridgeRemoteFetchAttempts_.load();
    out["torBridgeRemoteFetchSuccesses"] = agentTorBridgeRemoteFetchSuccesses_.load();
    out["torBridgeRemoteRateLimitedSkips"] = agentTorBridgeRemoteRateLimitedSkips_.load();
    const json torBridgeProviderMetaNode = getTorBridgeProviderMetaSnapshot();
    const uint64_t torBridgeProviderUpdatedAtNode = torBridgeProviderMetaUpdatedAt_.load();
    out["torBridgeProvider"] = torBridgeProviderMetaNode;
    out["torBridgeProviderUpdatedAt"] = torBridgeProviderUpdatedAtNode;
    if (torBridgeProviderMetaNode.contains("cacheSavedAt") && torBridgeProviderMetaNode["cacheSavedAt"].is_number_unsigned()) {
        const uint64_t cacheSavedAt = torBridgeProviderMetaNode.value("cacheSavedAt", static_cast<uint64_t>(0));
        const uint64_t nowTs = static_cast<uint64_t>(std::time(nullptr));
        if (cacheSavedAt != 0 && nowTs >= cacheSavedAt) {
            out["torBridgeCacheAgeSeconds"] = nowTs - cacheSavedAt;
        } else {
            out["torBridgeCacheAgeSeconds"] = 0;
        }
    } else {
        out["torBridgeCacheAgeSeconds"] = 0;
    }
    out["routeMode"] = route.routeMode;
    out["clearnetFallbackAllowed"] = agentAllowClearnetFallback_.load();
    out["p2pFallbackAllowed"] = agentAllowP2PFallback_.load();
    out["allowWebClearnet"] = route.allowWebClearnet;
    out["allowWebOnion"] = route.allowWebOnion;
    out["allowP2PDiscovery"] = route.allowP2PDiscovery;
    json networkHealth;
    networkHealth["available"] = false;
    if (network_) {
        auto ns = network_->getStats();
        const uint64_t peerPressure = config_.maxPeers == 0 ? 0 : (ns.totalPeers * 100ULL / config_.maxPeers);
        const uint64_t inboundPressure = config_.maxInbound == 0 ? 0 : (ns.inboundPeers * 100ULL / config_.maxInbound);
        const uint64_t outboundPressure = config_.maxOutbound == 0 ? 0 : (ns.outboundPeers * 100ULL / config_.maxOutbound);
        const uint64_t ledgerHeight = ledger_ ? ledger_->height() : 0;
        const uint64_t netHeight = networkHeight_.load();
        const uint64_t consensusLag = (netHeight > ledgerHeight) ? (netHeight - ledgerHeight) : 0;
        networkHealth["available"] = true;
        networkHealth["totalPeers"] = ns.totalPeers;
        networkHealth["inboundPeers"] = ns.inboundPeers;
        networkHealth["outboundPeers"] = ns.outboundPeers;
        networkHealth["peerPressurePercent"] = peerPressure;
        networkHealth["inboundPressurePercent"] = inboundPressure;
        networkHealth["outboundPressurePercent"] = outboundPressure;
        networkHealth["bytesSent"] = ns.bytesSent;
        networkHealth["bytesReceived"] = ns.bytesReceived;
        networkHealth["messagesSent"] = ns.messagesSent;
        networkHealth["messagesReceived"] = ns.messagesReceived;
        networkHealth["overloadMode"] = ns.overloadMode;
        networkHealth["bufferedRxBytes"] = ns.bufferedRxBytes;
        networkHealth["rejectedConnections"] = ns.rejectedConnections;
        networkHealth["evictedPeers"] = ns.evictedPeers;
        networkHealth["tempBans"] = ns.tempBans;
        networkHealth["malformedMessages"] = ns.malformedMessages;
        networkHealth["rateLimitedEvents"] = ns.rateLimitedEvents;
        networkHealth["overloadTransitions"] = ns.overloadTransitions;
        networkHealth["activeBans"] = network_->getBannedPeers().size();
        networkHealth["invBackpressureDrops"] = invBackpressureDrops_.load();
        networkHealth["getdataBackpressureDrops"] = getDataBackpressureDrops_.load();
        networkHealth["gossipSuppressed"] = gossipSuppressed_.load();
        networkHealth["gossipSubsetRouted"] = gossipSubsetRouted_.load();
        networkHealth["consensusLag"] = consensusLag;
    }
    out["networkHealth"] = networkHealth;
    return out.dump();
}

std::string handleRpcNodePeers(const std::string& paramsJson) {
    (void)paramsJson;
    json out = json::array();
    if (!network_) return out.dump();
    for (const auto& p : network_->getPeers()) {
        json item;
        item["id"] = p.id;
        item["address"] = p.address;
        item["port"] = p.port;
        item["connectedAt"] = p.connectedAt;
        item["lastSeen"] = p.lastSeen;
        item["bytesRecv"] = p.bytesRecv;
        item["bytesSent"] = p.bytesSent;
        item["version"] = p.version;
        item["startHeight"] = p.startHeight;
        item["outbound"] = p.isOutbound;
        item["state"] = peerStateToString(p.state);
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcNodeLogs(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    size_t limit = 100;
    if (params.contains("limit")) {
        limit = static_cast<size_t>(std::max(1, params.value("limit", 100)));
    }
    auto logs = utils::Logger::getRecentLogs(limit);
    json out = json::array();
    for (const auto& e : logs) {
        json item;
        item["timestamp"] = e.timestamp;
        item["level"] = static_cast<int>(e.level);
        item["category"] = e.category;
        item["message"] = e.message;
        out.push_back(item);
    }
    return out.dump();
}

std::string handleRpcNodeSeeds(const std::string& paramsJson) {
    (void)paramsJson;
    json out;
    out["bootstrap"] = json::array();
    out["dnsSeeds"] = json::array();
    if (!discovery_) return out.dump();

    for (const auto& bn : discovery_->getBootstrapNodes()) {
        json item;
        item["address"] = bn.address;
        item["port"] = bn.port;
        item["active"] = bn.active;
        item["failures"] = bn.failures;
        item["lastSeen"] = bn.lastSeen;
        item["healthScore"] = bn.healthScore;
        item["quarantineUntil"] = bn.quarantineUntil;
        item["lastFailureAt"] = bn.lastFailureAt;
        out["bootstrap"].push_back(item);
    }
    for (const auto& seed : discovery_->getDnsSeeds()) {
        out["dnsSeeds"].push_back(seed);
    }
    return out.dump();
}

std::string handleRpcNodeDiscoveryStats(const std::string& paramsJson) {
    (void)paramsJson;
    json out;
    if (!discovery_) {
        out["running"] = false;
        out["knownPeers"] = 0;
        out["connectedPeers"] = 0;
        out["dnsSeeds"] = 0;
        out["bootstrapNodes"] = 0;
        out["activeBootstrapNodes"] = 0;
        out["quarantinedBootstrapNodes"] = 0;
        out["dnsQueries"] = 0;
        out["peerExchanges"] = 0;
        out["lastPeerRefresh"] = 0;
        out["lastAnnounce"] = 0;
        return out.dump();
    }
    auto st = discovery_->getStats();
    out["running"] = discovery_->isRunning();
    out["knownPeers"] = st.knownPeersCount;
    out["connectedPeers"] = st.connectedPeers;
    out["dnsSeeds"] = discovery_->getDnsSeeds().size();
    out["bootstrapNodes"] = discovery_->getBootstrapNodes().size();
    out["activeBootstrapNodes"] = st.activeBootstrapNodes;
    out["quarantinedBootstrapNodes"] = st.quarantinedBootstrapNodes;
    out["dnsQueries"] = st.dnsQueries;
    out["peerExchanges"] = st.peerExchanges;
    out["peerExchangeSuccessRate"] = st.peerExchangeSuccessRate;
    out["lastPeerRefresh"] = st.lastRefreshTime;
    out["lastAnnounce"] = st.lastAnnounceTime;
    out["networkSizeEstimate"] = st.networkSize;
    out["totalDiscovered"] = st.totalDiscovered;
    out["totalConnected"] = st.totalConnected;
    out["totalFailed"] = st.totalFailed;
    return out.dump();
}

std::string handleRpcNodeTorControl(const std::string& paramsJson) {
    auto params = parseRpcParams(paramsJson);
    const std::string actionRaw = params.value("action", "");
    if (actionRaw.empty()) {
        throw std::runtime_error("action required");
    }

    auto normalizeAction = [](std::string action) {
        std::transform(action.begin(), action.end(), action.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (action == "refresh") action = "refresh_bridges";
        if (action == "refresh-bridges") action = "refresh_bridges";
        if (action == "restart") action = "restart_managed_tor";
        if (action == "restart-managed") action = "restart_managed_tor";
        if (action == "restart-managed-tor") action = "restart_managed_tor";
        if (action == "switch") action = "switch_mode";
        if (action == "switch-mode") action = "switch_mode";
        return action;
    };

    auto validatePortOrDefault = [](const json& p, const char* key, uint16_t fallback) -> uint16_t {
        if (!p.contains(key)) return fallback;
        int64_t raw = 0;
        try {
            raw = p.at(key).is_string() ? std::stoll(p.at(key).get<std::string>())
                                        : p.at(key).get<int64_t>();
        } catch (...) {
            throw std::runtime_error(std::string("invalid ") + key);
        }
        if (raw < 1 || raw > 65535) {
            throw std::runtime_error(std::string("invalid ") + key);
        }
        return static_cast<uint16_t>(raw);
    };

    auto buildTorControlStatus = [&](json& out, const core::TorRoutePolicyDecision& route) {
        const bool torRequired = agentTorRequired_.load();
        const bool torReachable = agentTorReachable_.load();
        const bool torReadyForWeb = agentTorWebReady_.load();
        const bool torControlReachable = probeTorControl();
        const bool onionServiceActive = isOnionServiceActive();
        const core::TorBootstrapStateInput bootIn{torRequired, torReachable, torReadyForWeb, route.torDegraded};
        const core::TorOnionServiceStateInput onionSvcIn{
            torRequired,
            torReachable,
            torReadyForWeb,
            route.torDegraded,
            config_.privacyMode,
            torControlReachable,
            onionServiceActive};
        out["torRuntimeMode"] = configuredTorRuntimeMode();
        out["torSocksHost"] = configuredTorSocksHost();
        out["torSocksPort"] = configuredTorSocksPort();
        out["torControlPort"] = configuredTorControlPort();
        out["torControlReachable"] = torControlReachable;
        out["torManagedPid"] = managedTorPid_.load();
        out["torRequired"] = torRequired;
        out["torSocksReachable"] = torReachable;
        out["torReadyForWeb"] = torReadyForWeb;
        out["torReadyForOnion"] = core::evaluateTorReadyForOnion(bootIn);
        out["torReadyForOnionService"] = core::evaluateTorReadyForOnionService(onionSvcIn);
        out["torOnionServiceActive"] = onionServiceActive;
        out["torOnionServiceState"] = core::evaluateTorOnionServiceState(onionSvcIn);
        out["torDegraded"] = route.torDegraded;
        out["routeMode"] = route.routeMode;
        out["torBootstrapState"] = core::evaluateTorBootstrapState(bootIn);
        out["torBootstrapPercent"] = core::evaluateTorBootstrapPercent(bootIn);
        out["torBootstrapReasonCode"] = core::evaluateTorBootstrapReasonCode(bootIn, getTorWebProbeLastError());
        out["torConflictHint9050"] = likelyTor9050vs9150ConflictHint(torReachable);
        const json bridgeProviderMeta = getTorBridgeProviderMetaSnapshot();
        const uint64_t bridgeProviderUpdatedAt = torBridgeProviderMetaUpdatedAt_.load();
        out["torBridgeProvider"] = bridgeProviderMeta;
        out["torBridgeProviderUpdatedAt"] = bridgeProviderUpdatedAt;
        if (bridgeProviderMeta.contains("cacheSavedAt") && bridgeProviderMeta["cacheSavedAt"].is_number_unsigned()) {
            const uint64_t cacheSavedAt = bridgeProviderMeta.value("cacheSavedAt", static_cast<uint64_t>(0));
            const uint64_t nowTs = static_cast<uint64_t>(std::time(nullptr));
            if (cacheSavedAt != 0 && nowTs >= cacheSavedAt) {
                out["torBridgeCacheAgeSeconds"] = nowTs - cacheSavedAt;
            } else {
                out["torBridgeCacheAgeSeconds"] = 0;
            }
        } else {
            out["torBridgeCacheAgeSeconds"] = 0;
        }
    };

    auto writeRuntimeTorConfig = [&](const std::string& mode,
                                     const std::string& socksHost,
                                     uint16_t socksPort,
                                     uint16_t controlPort) {
        auto& cfg = utils::Config::instance();
        cfg.set("agent.tor.mode", mode);
        cfg.set("tor.socks.host", socksHost);
        cfg.set("tor.socks.port", static_cast<int>(socksPort));
        cfg.set("tor.control.port", static_cast<int>(controlPort));
        cfg.set("agent.tor.socks_host", socksHost);
        cfg.set("agent.tor.socks_port", static_cast<int>(socksPort));
        cfg.set("agent.routing.allow_clearnet_fallback", false);
        cfg.set("agent.routing.allow_p2p_clearnet_fallback", false);
    };

    auto reloadNaanWebConfig = [&](bool persistSanitized) -> json {
        if (!ensureWebSubsystem()) {
            throw std::runtime_error("web_subsystem_init_failed");
        }

        json meta;
        std::lock_guard<std::mutex> lock(webMtx_);
        if (!webSearch_ || !webExtractor_) {
            throw std::runtime_error("web_subsystem_not_ready");
        }

        web::SearchConfig cfg;
        const std::string webCfgPath = config_.dataDir + "/web_search.conf";
        (void)web::loadSearchConfig(webCfgPath, cfg);

        const std::string ahmiaOnion = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/";
        const std::string naanWebCfgPath = config_.dataDir + "/naan_agent_web.conf";
        if (!std::filesystem::exists(naanWebCfgPath)) {
            std::ofstream naanCfg(naanWebCfgPath);
            if (naanCfg.is_open()) {
                naanCfg << "clearnet_engines=duckduckgo\n";
                naanCfg << "darknet_engines=ahmia,torch,darksearch,deepsearch\n";
                naanCfg << "custom_darknet_urls=" << ahmiaOnion << "\n";
                naanCfg << "route_clearnet_through_tor=1\n";
                naanCfg << "naan_force_tor_mode=1\n";
                naanCfg << "naan_auto_search_enabled=1\n";
                naanCfg << "naan_auto_search_mode=both\n";
                naanCfg << "naan_auto_search_queries=latest space engineering research,latest ai research papers,open source systems engineering best practices\n";
                naanCfg << "naan_auto_search_max_results=4\n";
                naanCfg << "clearnet_site_allowlist=\n";
                naanCfg << "clearnet_site_denylist=\n";
                naanCfg << "onion_site_allowlist=\n";
                naanCfg << "onion_site_denylist=\n";
                naanCfg << "clearnet_route_bypass_hosts=\n";
                naanCfg << "onion_route_bypass_hosts=\n";
                naanCfg << "bypass_onion_https_fallback=1\n";
            }
        }

        web::SearchConfigValidationStats validation{};
        (void)web::loadSearchConfigOverlay(naanWebCfgPath, cfg, &validation);
        web::sanitizeSearchConfig(cfg);
        cfg.tor.bridgeManualLines = core::sanitizeAndDedupeObfs4BridgeLines(cfg.tor.bridgeManualLines);

        const std::string bridgeFilePath = config_.dataDir + "/tor/bridges.obfs4.txt";
        const std::string bridgeCachePath = config_.dataDir + "/tor/bridge_pool_cache.json";
        const uint64_t bridgeNow = static_cast<uint64_t>(std::time(nullptr));
        auto& runtimeCfg = utils::Config::instance();
        const uint64_t bridgeCacheTtlSeconds = static_cast<uint64_t>(std::max<int64_t>(
            60, runtimeCfg.getInt64("agent.tor.bridge.cache_ttl_seconds", 86400)));
        const bool bridgeAllowStaleCacheFallback =
            runtimeCfg.getBool("agent.tor.bridge.allow_stale_cache_fallback", true);
        const bool bridgeRemoteAdapterEnabled =
            runtimeCfg.getBool("agent.tor.bridge.remote_adapter_enabled", true);
        const uint64_t bridgeRemoteMinIntervalSeconds = static_cast<uint64_t>(std::max<int64_t>(
            30, runtimeCfg.getInt64("agent.tor.bridge.remote_min_interval_seconds", 300)));
        const uint32_t bridgeRemoteTimeoutSeconds = static_cast<uint32_t>(std::max<int64_t>(
            5, std::min<int64_t>(120, runtimeCfg.getInt64("agent.tor.bridge.remote_timeout_seconds", 30))));
        const size_t bridgeRemoteMaxBytes = static_cast<size_t>(std::max<int64_t>(
            4096, std::min<int64_t>(4 * 1024 * 1024, runtimeCfg.getInt64("agent.tor.bridge.remote_max_bytes", 512 * 1024))));
        json bridgeProviderMeta;
        bridgeProviderMeta["transport"] = cfg.tor.bridgeTransport;
        bridgeProviderMeta["requestedSource"] = cfg.tor.bridgeSource;
        bridgeProviderMeta["filePath"] = bridgeFilePath;
        bridgeProviderMeta["cachePath"] = bridgeCachePath;
        bridgeProviderMeta["cacheTtlSeconds"] = bridgeCacheTtlSeconds;
        bridgeProviderMeta["allowStaleCacheFallback"] = bridgeAllowStaleCacheFallback;
        bridgeProviderMeta["remoteAdapterEnabled"] = bridgeRemoteAdapterEnabled;
        bridgeProviderMeta["remoteMinIntervalSeconds"] = bridgeRemoteMinIntervalSeconds;
        bridgeProviderMeta["remoteTimeoutSeconds"] = bridgeRemoteTimeoutSeconds;
        bridgeProviderMeta["remoteMaxBytes"] = bridgeRemoteMaxBytes;

        auto remoteBridgeFetch = [&](const std::string& url,
                                     std::vector<std::string>& lines,
                                     std::string& errorOut) -> bool {
            const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
            const uint64_t lastFetchAt = agentTorBridgeRemoteLastFetchAt_.load();
            if (lastFetchAt != 0 && now >= lastFetchAt && (now - lastFetchAt) < bridgeRemoteMinIntervalSeconds) {
                const uint64_t retryAfter = bridgeRemoteMinIntervalSeconds - (now - lastFetchAt);
                agentTorBridgeRemoteRateLimitedSkips_.fetch_add(1);
                errorOut = "rate_limited: retry_after_seconds=" + std::to_string(retryAfter);
                return false;
            }

            web::CurlFetchOptions opts;
            opts.timeoutSeconds = bridgeRemoteTimeoutSeconds;
            opts.maxBytes = bridgeRemoteMaxBytes;
            opts.userAgent = "SynapseNet/0.2 bridge-remote-fetch";
            opts.followRedirects = true;

            const bool torRequiredNow = agentTorRequired_.load();
            const bool torReachableNow = agentTorReachable_.load();
            if (torRequiredNow) {
                if (!torReachableNow) {
                    errorOut = "tor_unreachable: required for remote bridge source";
                    return false;
                }
                opts.socksProxyHostPort = configuredTorSocksHost() + ":" + std::to_string(configuredTorSocksPort());
            } else if (cfg.routeClearnetThroughTor && torReachableNow) {
                opts.socksProxyHostPort = configuredTorSocksHost() + ":" + std::to_string(configuredTorSocksPort());
            }

            agentTorBridgeRemoteFetchAttempts_.fetch_add(1);
            agentTorBridgeRemoteLastFetchAt_.store(now);
            const auto fetched = web::curlFetch(url, opts);
            if (fetched.exitCode != 0) {
                errorOut = "remote_fetch_failed: curl_exit=" + std::to_string(fetched.exitCode);
                if (!fetched.error.empty()) {
                    errorOut += " " + fetched.error;
                }
                return false;
            }

            auto trimAscii = [](std::string s) {
                while (!s.empty() &&
                       (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t')) {
                    s.pop_back();
                }
                size_t start = 0;
                while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) {
                    ++start;
                }
                if (start > 0) s.erase(0, start);
                return s;
            };
            auto toLowerAscii = [](std::string s) {
                for (char& c : s) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                return s;
            };

            std::istringstream iss(fetched.body);
            std::string line;
            while (std::getline(iss, line)) {
                line = trimAscii(std::move(line));
                if (line.empty() || line[0] == '#') continue;
                lines.push_back(line);
            }
            if (!lines.empty()) {
                agentTorBridgeRemoteFetchSuccesses_.fetch_add(1);
                return true;
            }

            const std::string lowerBody = toLowerAscii(fetched.body);
            const bool looksInteractive =
                lowerBody.find("captcha") != std::string::npos ||
                lowerBody.find("verify you are human") != std::string::npos ||
                lowerBody.find("javascript required") != std::string::npos ||
                lowerBody.find("challenge") != std::string::npos ||
                lowerBody.find("<html") != std::string::npos;
            if (looksInteractive) {
                errorOut =
                    "manual_step_required: remote source requires interactive verification; "
                    "fetch bridges manually and set agent.tor.bridge.manual_lines or use "
                    + bridgeFilePath;
            } else {
                errorOut = "remote_fetch_failed: empty_bridge_material";
            }
            return false;
        };

        if (cfg.tor.bridgeTransport == "obfs4") {
            core::TorBridgeProviderResolveInput bridgeInput;
            bridgeInput.requestedSource = cfg.tor.bridgeSource;
            bridgeInput.transport = cfg.tor.bridgeTransport;
            bridgeInput.manualLines = cfg.tor.bridgeManualLines;
            bridgeInput.filePath = bridgeFilePath;
            bridgeInput.cachePath = bridgeCachePath;
            bridgeInput.remoteUrl = cfg.tor.bridgeRemoteUrl;
            bridgeInput.now = bridgeNow;
            bridgeInput.cacheTtlSeconds = bridgeCacheTtlSeconds;
            bridgeInput.minPoolSize = cfg.tor.bridgeMinPoolSize;
            bridgeInput.allowStaleCacheFallback = bridgeAllowStaleCacheFallback;

            const auto bridgeResolved = bridgeRemoteAdapterEnabled
                ? core::resolveObfs4BridgePool(bridgeInput, remoteBridgeFetch)
                : core::resolveObfs4BridgePool(bridgeInput);
            bridgeProviderMeta["ok"] = bridgeResolved.ok;
            bridgeProviderMeta["resolvedSource"] = bridgeResolved.source;
            bridgeProviderMeta["usedFallback"] = bridgeResolved.usedFallback;
            bridgeProviderMeta["cacheHit"] = bridgeResolved.cacheHit;
            bridgeProviderMeta["cacheFresh"] = bridgeResolved.cacheFresh;
            bridgeProviderMeta["cacheUpdated"] = bridgeResolved.cacheUpdated;
            bridgeProviderMeta["cacheSavedAt"] = bridgeResolved.cacheSavedAt;
            bridgeProviderMeta["reasonCode"] = bridgeResolved.reasonCode;
            bridgeProviderMeta["error"] = bridgeResolved.error;
            bridgeProviderMeta["triedSources"] = bridgeResolved.triedSources;
            bridgeProviderMeta["poolChecksum"] = bridgeResolved.checksum;
            bridgeProviderMeta["poolCount"] = bridgeResolved.lines.size();
            bridgeProviderMeta["remoteLastFetchAt"] = agentTorBridgeRemoteLastFetchAt_.load();
            bridgeProviderMeta["remoteFetchAttempts"] = agentTorBridgeRemoteFetchAttempts_.load();
            bridgeProviderMeta["remoteFetchSuccesses"] = agentTorBridgeRemoteFetchSuccesses_.load();
            bridgeProviderMeta["remoteRateLimitedSkips"] = agentTorBridgeRemoteRateLimitedSkips_.load();
            if (bridgeResolved.ok) {
                cfg.tor.bridgeManualLines = bridgeResolved.lines;
            }
        }

        cfg.tor.runtimeMode = configuredTorRuntimeMode();
        cfg.tor.socksHost = configuredTorSocksHost();
        cfg.tor.socksPort = configuredTorSocksPort();
        cfg.tor.controlHost = "127.0.0.1";
        cfg.tor.controlPort = configuredTorControlPort();

        naanWebConfigTotalLines_.store(validation.totalLines);
        naanWebConfigAppliedLines_.store(validation.appliedLines);
        naanWebConfigInvalidLines_.store(validation.invalidLines);
        naanWebConfigUnknownKeys_.store(validation.unknownKeys);
        naanWebConfigUnknownKeySamples_ = validation.unknownKeySamples;
        naanWebConfigSanitizedWrites_.fetch_add(1);

        bool hasAhmiaOnion = false;
        for (const auto& url : cfg.customDarknetUrls) {
            if (web::normalizeUrl(url) == web::normalizeUrl(ahmiaOnion)) {
                hasAhmiaOnion = true;
                break;
            }
        }
        if (!hasAhmiaOnion) {
            cfg.customDarknetUrls.push_back(ahmiaOnion);
        }
        if (cfg.connectorAuditDir.empty()) {
            cfg.connectorAuditDir = config_.dataDir + "/audit/connectors";
        }

        if (persistSanitized && !web::saveSearchConfig(cfg, naanWebCfgPath)) {
            throw std::runtime_error("failed_to_save_naan_web_config");
        }

        webExtractor_->setRemoveAds(cfg.removeAds);
        webExtractor_->setRemoveScripts(cfg.removeScripts);
        webExtractor_->setRemoveStyles(cfg.removeStyles);
        webExtractor_->setRiskPolicy(cfg.extractionRisk);

        const bool torRequired = agentTorRequired_.load();
        const auto route = refreshTorRoutePolicy(true);
        const bool torReachable = agentTorReachable_.load();
        const bool hardTorOnly = torRequired || cfg.naanForceTorMode;
        const bool onionOptIn = utils::Config::instance().getBool("web.inject.onion", false);
        const bool torClearnetOptIn = utils::Config::instance().getBool("web.inject.tor_clearnet", false);
        if (hardTorOnly) {
            cfg.routeClearnetThroughTor = true;
            cfg.enableClearnet = torReachable && route.allowWebClearnet;
            cfg.enableDarknet = torReachable && route.allowWebOnion;
        } else {
            cfg.enableClearnet = true;
            cfg.enableDarknet = onionOptIn;
            cfg.routeClearnetThroughTor = torClearnetOptIn;
        }
        webSearch_->init(cfg);

        json validationJson;
        validationJson["totalLines"] = validation.totalLines;
        validationJson["appliedLines"] = validation.appliedLines;
        validationJson["invalidLines"] = validation.invalidLines;
        validationJson["duplicateKeys"] = validation.duplicateKeys;
        validationJson["unknownKeys"] = validation.unknownKeys;
        validationJson["malformedBridgeLines"] = validation.malformedBridgeLines;
        meta["path"] = naanWebCfgPath;
        meta["persistSanitized"] = persistSanitized;
        meta["validation"] = validationJson;
        meta["bridgeTransport"] = cfg.tor.bridgeTransport;
        meta["bridgeSource"] = cfg.tor.bridgeSource;
        meta["bridgeManualLinesCount"] = cfg.tor.bridgeManualLines.size();
        meta["bridgeProvider"] = bridgeProviderMeta;
        meta["torRuntimeMode"] = cfg.tor.runtimeMode;
        meta["torSocksHost"] = cfg.tor.socksHost;
        meta["torSocksPort"] = cfg.tor.socksPort;
        meta["torControlPort"] = cfg.tor.controlPort;
        meta["webClearnetEnabled"] = cfg.enableClearnet;
        meta["webOnionEnabled"] = cfg.enableDarknet;
        setTorBridgeProviderMetaSnapshot(bridgeProviderMeta);
        return meta;
    };

    const std::string action = normalizeAction(actionRaw);
    json out;
    out["ok"] = true;
    out["action"] = action;

    if (action == "refresh_bridges") {
        const bool persistSanitized = params.value("persistSanitized", true);
        out["bridgeRefresh"] = reloadNaanWebConfig(persistSanitized);
        const auto route = refreshTorRoutePolicy(true);
        buildTorControlStatus(out, route);
        out["lastKnownGoodBridgeSubsetPersisted"] =
            persistLastKnownGoodBridgeSubset("node.tor.control.refresh_bridges");
        return out.dump();
    }

    if (action == "restart_managed_tor" || action == "switch_mode") {
        bool expected = false;
        if (!agentTorManagedRestartInFlight_.compare_exchange_strong(expected, true)) {
            throw std::runtime_error("tor_restart_in_progress");
        }
        struct InFlightReset {
            std::atomic<bool>& flag;
            ~InFlightReset() { flag.store(false); }
        } inFlightReset{agentTorManagedRestartInFlight_};

        if (action == "switch_mode") {
            const std::string requestedMode = params.value("mode", "");
            if (requestedMode.empty()) {
                throw std::runtime_error("mode required");
            }
            const std::string mode = core::normalizeTorRuntimeMode(requestedMode);
            if (mode != "auto" && mode != "external" && mode != "managed") {
                throw std::runtime_error("invalid mode");
            }
            const bool persist = params.value("persist", true);
            const std::string socksHost = params.value("socksHost", std::string("127.0.0.1"));
            const uint16_t defaultSocksPort = (mode == "external") ? 9150 : 9050;
            const uint16_t defaultControlPort = (mode == "external") ? 9151 : 9051;
            const uint16_t socksPort = validatePortOrDefault(params, "socksPort", defaultSocksPort);
            const uint16_t controlPort = validatePortOrDefault(params, "controlPort", defaultControlPort);
            const bool reloadWeb = params.value("reloadWebConfig", true);

            writeRuntimeTorConfig(mode, socksHost, socksPort, controlPort);
            out["modeSwitch"] = {
                {"requestedMode", requestedMode},
                {"appliedMode", mode},
                {"socksHost", socksHost},
                {"socksPort", socksPort},
                {"controlPort", controlPort},
                {"persisted", persist}
            };

            bool stoppedManaged = false;
            bool startedManaged = false;
            if (mode == "external") {
                stoppedManaged = stopManagedTorRuntimeIfOwned(true);
                resetManagedTorRestartBackoffState();
            } else if (mode == "managed") {
                resetManagedTorRestartBackoffState();
                startedManaged = startManagedTorRuntime();
            }
            out["modeSwitch"]["stoppedManagedTor"] = stoppedManaged;
            out["modeSwitch"]["startedManagedTor"] = startedManaged;

            if (persist) {
                out["modeSwitch"]["configSaved"] =
                    utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
                out["modeSwitch"]["configPath"] = config_.dataDir + "/synapsenet.conf";
            }
            if (reloadWeb) {
                out["bridgeRefresh"] = reloadNaanWebConfig(false);
            }

            const auto route = refreshTorRoutePolicy(true);
            buildTorControlStatus(out, route);
            out["lastKnownGoodBridgeSubsetPersisted"] =
                persistLastKnownGoodBridgeSubset("node.tor.control.switch_mode");
            return out.dump();
        }

        if (configuredTorRuntimeMode() == "external") {
            throw std::runtime_error("tor_mode_external");
        }
        const bool reloadWeb = params.value("reloadWebConfig", true);
        const bool stoppedManaged = stopManagedTorRuntimeIfOwned(true);
        resetManagedTorRestartBackoffState();
        const bool startedManaged = startManagedTorRuntime();
        out["managedRestart"] = {
            {"stoppedManagedTor", stoppedManaged},
            {"startedManagedTor", startedManaged},
            {"mode", configuredTorRuntimeMode()}
        };
        if (reloadWeb) {
            out["bridgeRefresh"] = reloadNaanWebConfig(false);
        }
        const auto route = refreshTorRoutePolicy(true);
        buildTorControlStatus(out, route);
        out["lastKnownGoodBridgeSubsetPersisted"] =
            persistLastKnownGoodBridgeSubset("node.tor.control.restart_managed_tor");
        return out.dump();
    }

    throw std::runtime_error("unknown action");
}

		public:
		    int runCommand(const std::vector<std::string>& args) {
	        if (args.empty()) return 0;
            if (args[0] == "tor") {
                if (args.size() == 1 || args[1] == "help") {
                    std::cout << "Usage:\n";
                    std::cout << "  synapsed tor status\n";
                    std::cout << "  synapsed tor refresh-bridges [--persist-sanitized 0|1]\n";
                    std::cout << "  synapsed tor restart-managed [--reload-web 0|1]\n";
                    std::cout << "  synapsed tor mode <auto|external|managed> [--socks-host H] [--socks-port N] [--control-port N] [--persist 0|1] [--reload-web 0|1]\n";
                    return 0;
                }
                try {
                    const std::string sub = args[1];
                    if (sub == "status") {
                        std::cout << handleRpcNodeStatus("{}") << "\n";
                        return 0;
                    }
                    json params;
                    if (sub == "refresh" || sub == "refresh-bridges") {
                        params["action"] = "refresh_bridges";
                        for (size_t i = 2; i < args.size(); ++i) {
                            if (args[i] == "--persist-sanitized" && i + 1 < args.size()) {
                                params["persistSanitized"] = (std::stoi(args[i + 1]) != 0);
                                i++;
                            }
                        }
                        std::cout << handleRpcNodeTorControl(params.dump()) << "\n";
                        return 0;
                    }
                    if (sub == "restart" || sub == "restart-managed") {
                        params["action"] = "restart_managed_tor";
                        for (size_t i = 2; i < args.size(); ++i) {
                            if ((args[i] == "--reload-web" || args[i] == "--reload-web-config") &&
                                i + 1 < args.size()) {
                                params["reloadWebConfig"] = (std::stoi(args[i + 1]) != 0);
                                i++;
                            }
                        }
                        std::cout << handleRpcNodeTorControl(params.dump()) << "\n";
                        return 0;
                    }
                    if (sub == "mode") {
                        if (args.size() < 3) {
                            std::cerr << "Usage: synapsed tor mode <auto|external|managed> [--socks-host H] [--socks-port N] [--control-port N] [--persist 0|1] [--reload-web 0|1]\n";
                            return 1;
                        }
                        params["action"] = "switch_mode";
                        params["mode"] = args[2];
                        for (size_t i = 3; i < args.size(); ++i) {
                            if (args[i] == "--socks-host" && i + 1 < args.size()) {
                                params["socksHost"] = args[i + 1];
                                i++;
                            } else if (args[i] == "--socks-port" && i + 1 < args.size()) {
                                params["socksPort"] = std::stoi(args[i + 1]);
                                i++;
                            } else if (args[i] == "--control-port" && i + 1 < args.size()) {
                                params["controlPort"] = std::stoi(args[i + 1]);
                                i++;
                            } else if (args[i] == "--persist" && i + 1 < args.size()) {
                                params["persist"] = (std::stoi(args[i + 1]) != 0);
                                i++;
                            } else if ((args[i] == "--reload-web" || args[i] == "--reload-web-config") &&
                                       i + 1 < args.size()) {
                                params["reloadWebConfig"] = (std::stoi(args[i + 1]) != 0);
                                i++;
                            }
                        }
                        std::cout << handleRpcNodeTorControl(params.dump()) << "\n";
                        return 0;
                    }
                } catch (const std::exception& e) {
                    std::cerr << e.what() << "\n";
                    return 1;
                }
                std::cerr << "Unknown tor subcommand: " << args[1] << "\n";
                return 1;
            }
	        if (args[0] == "model") {
	            if (args.size() == 1 || args[1] == "help") {
	                std::cout << "Usage:\n";
	                std::cout << "  synapsed model status\n";
	                std::cout << "  synapsed model list [--dir PATH]\n";
	                std::cout << "  synapsed model load (--path PATH | --name FILENAME)\n";
	                std::cout << "    [--context N] [--threads N] [--gpu-layers N] [--use-gpu 0|1] [--mmap 0|1]\n";
	                std::cout << "  synapsed model unload\n";
	                return 0;
	            }
	            std::string sub = args[1];
	            try {
	                if (sub == "status") {
	                    std::cout << handleRpcModelStatus("{}") << "\n";
	                    return 0;
	                }
	                if (sub == "list") {
	                    json params;
	                    for (size_t i = 2; i < args.size(); ++i) {
	                        if (args[i] == "--dir" && i + 1 < args.size()) {
	                            params["dir"] = args[i + 1];
	                            i++;
	                        }
	                    }
	                    std::cout << handleRpcModelList(params.dump()) << "\n";
	                    return 0;
	                }
	                if (sub == "load") {
	                    json params;
	                    for (size_t i = 2; i < args.size(); ++i) {
	                        if (args[i] == "--path" && i + 1 < args.size()) {
	                            params["path"] = args[i + 1];
	                            i++;
	                        } else if (args[i] == "--name" && i + 1 < args.size()) {
	                            params["name"] = args[i + 1];
	                            i++;
	                        } else if (args[i] == "--context" && i + 1 < args.size()) {
	                            params["contextSize"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--threads" && i + 1 < args.size()) {
	                            params["threads"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--gpu-layers" && i + 1 < args.size()) {
	                            params["gpuLayers"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--use-gpu" && i + 1 < args.size()) {
	                            params["useGpu"] = (std::stoi(args[i + 1]) != 0);
	                            i++;
	                        } else if (args[i] == "--mmap" && i + 1 < args.size()) {
	                            params["useMmap"] = (std::stoi(args[i + 1]) != 0);
	                            i++;
	                        }
	                    }
	                    std::cout << handleRpcModelLoad(params.dump()) << "\n";
	                    return 0;
	                }
	                if (sub == "unload") {
	                    std::cout << handleRpcModelUnload("{}") << "\n";
	                    return 0;
	                }
	            } catch (const std::exception& e) {
	                std::cerr << e.what() << "\n";
	                return 1;
	            }
	            std::cerr << "Unknown model subcommand: " << sub << "\n";
	            return 1;
	        }
	        if (args[0] == "ai") {
	            if (args.size() == 1 || args[1] == "help") {
	                std::cout << "Usage:\n";
	                std::cout << "  synapsed ai complete --prompt TEXT [--max-tokens N] [--temperature X]\n";
	                std::cout << "  synapsed ai stop\n";
	                return 0;
	            }
	            std::string sub = args[1];
	            try {
	                if (sub == "stop") {
	                    std::cout << handleRpcAiStop("{}") << "\n";
	                    return 0;
	                }
	                if (sub == "complete") {
	                    json params;
	                    for (size_t i = 2; i < args.size(); ++i) {
	                        if (args[i] == "--prompt" && i + 1 < args.size()) {
	                            params["prompt"] = args[i + 1];
	                            i++;
	                        } else if (args[i] == "--max-tokens" && i + 1 < args.size()) {
	                            params["maxTokens"] = std::stoi(args[i + 1]);
	                            i++;
	                        } else if (args[i] == "--temperature" && i + 1 < args.size()) {
	                            params["temperature"] = std::stod(args[i + 1]);
	                            i++;
	                        }
	                    }
	                    std::cout << handleRpcAiComplete(params.dump()) << "\n";
	                    return 0;
	                }
	            } catch (const std::exception& e) {
	                std::cerr << e.what() << "\n";
	                return 1;
	            }
	            std::cerr << "Unknown ai subcommand: " << sub << "\n";
	            return 1;
	        }
	        if (args[0] != "poe") {
	            std::cerr << "Unknown command: " << args[0] << "\n";
	            return 1;
	        }
	        if (args.size() == 1 || args[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed poe submit --question Q --answer A [--source S]\n";
	            std::cout << "  synapsed poe submit-code --title T (--patch P | --patch-file PATH)\n";
	            std::cout << "  synapsed poe list-code [--limit N]\n";
	            std::cout << "  synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	            std::cout << "  synapsed poe vote <submitIdHex>\n";
	            std::cout << "  synapsed poe finalize <submitIdHex>\n";
	            std::cout << "  synapsed poe epoch [--budget NGT] [--iters N]\n";
	            std::cout << "  synapsed poe export <path>\n";
            std::cout << "  synapsed poe import <path>\n";
            std::cout << "  synapsed poe pubkey\n";
            std::cout << "  synapsed poe validators\n";
            return 0;
        }

        auto parseHash256 = [](const std::string& hex, crypto::Hash256& out) -> bool {
            auto bytes = crypto::fromHex(hex);
            if (bytes.size() != out.size()) return false;
            std::memcpy(out.data(), bytes.data(), out.size());
            return true;
        };

        auto parseNgtAtomic = [](const std::string& s, uint64_t& out) -> bool {
            if (s.empty()) return false;
            std::string t = s;
            for (auto& c : t) if (c == ',') c = '.';
            size_t dot = t.find('.');
            std::string intPart = dot == std::string::npos ? t : t.substr(0, dot);
            std::string fracPart = dot == std::string::npos ? "" : t.substr(dot + 1);
            if (intPart.empty()) intPart = "0";
            if (fracPart.size() > 8) return false;
            for (char c : intPart) if (c < '0' || c > '9') return false;
            for (char c : fracPart) if (c < '0' || c > '9') return false;
            unsigned __int128 iv = 0;
            for (char c : intPart) iv = iv * 10 + static_cast<unsigned>(c - '0');
            unsigned __int128 fv = 0;
            for (char c : fracPart) fv = fv * 10 + static_cast<unsigned>(c - '0');
            for (size_t i = fracPart.size(); i < 8; ++i) fv *= 10;
            unsigned __int128 total = iv * 100000000ULL + fv;
            if (total > std::numeric_limits<uint64_t>::max()) return false;
            out = static_cast<uint64_t>(total);
            return true;
        };

        auto rewardIdForEpoch = [](uint64_t epochId, const crypto::Hash256& contentId) -> crypto::Hash256 {
            std::vector<uint8_t> buf;
            const std::string tag = "poe_v1_epoch";
            buf.insert(buf.end(), tag.begin(), tag.end());
            for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((epochId >> (8 * i)) & 0xFF));
            buf.insert(buf.end(), contentId.begin(), contentId.end());
            return crypto::sha256(buf.data(), buf.size());
        };

        auto addressFromPubKey = [](const crypto::PublicKey& pubKey) -> std::string {
            std::string hex = crypto::toHex(pubKey);
            if (hex.size() < 52) return {};
            return "ngt1" + hex.substr(0, 52);
        };

        const std::string sub = args[1];
        if (sub == "pubkey") {
            if (!keys_ || !keys_->isValid()) {
                std::cerr << "Wallet not loaded\n";
                return 1;
            }
            auto pubV = keys_->getPublicKey();
            if (pubV.size() < crypto::PUBLIC_KEY_SIZE) {
                std::cerr << "Invalid public key\n";
                return 1;
            }
            crypto::PublicKey pk{};
            std::memcpy(pk.data(), pubV.data(), pk.size());
            std::cout << crypto::toHex(pk) << "\n";
            return 0;
        }
        if (sub == "validators") {
            if (!poeV1_) {
                std::cerr << "PoE not ready\n";
                return 1;
            }
            auto vals = poeV1_->getStaticValidators();
            for (const auto& v : vals) {
                std::cout << crypto::toHex(v) << "\n";
            }
            if (vals.empty()) {
                std::cout << "(none)\n";
            }
            return 0;
        }
	        if (sub == "submit") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < args.size(); ++i) {
	                if (args[i].rfind("--", 0) != 0) continue;
                std::string k = args[i].substr(2);
                std::string v;
                if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
                    v = args[i + 1];
                    i++;
                }
                opts[k] = v;
            }

            std::string q = opts["question"];
            std::string a = opts["answer"];
            std::string s = opts["source"];
            if (q.empty() || a.empty()) {
                std::cerr << "Missing --question/--answer\n";
                return 1;
            }
            if (!poeV1_ || !transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
                std::cerr << "PoE/wallet not ready\n";
                return 1;
            }

            crypto::PrivateKey pk{};
            auto pkv = keys_->getPrivateKey();
            if (pkv.size() < pk.size()) {
                std::cerr << "Invalid private key\n";
                return 1;
            }
            std::memcpy(pk.data(), pkv.data(), pk.size());

            std::string body = a;
            if (!s.empty()) body += "\nsource: " + s;
            updatePoeValidatorsFromStake();
            auto submitRes = poeV1_->submit(core::poe_v1::ContentType::QA, q, body, {}, pk, true);
            if (!submitRes.ok) {
                std::cerr << "PoE submit failed: " << submitRes.error << "\n";
                return 1;
            }
            std::cout << "submitId=" << crypto::toHex(submitRes.submitId) << "\n";
            std::cout << "contentId=" << crypto::toHex(submitRes.contentId) << "\n";

            crypto::PublicKey authorPub = crypto::derivePublicKey(pk);
            std::string authorAddr = addressFromPubKey(authorPub);
            if (authorAddr.empty()) authorAddr = address_;

            uint64_t rewardAmt = 0;
            if (submitRes.finalized && submitRes.acceptanceReward > 0) {
                std::vector<uint8_t> ridBuf;
                const std::string tag = "poe_v1_accept";
                ridBuf.insert(ridBuf.end(), tag.begin(), tag.end());
                ridBuf.insert(ridBuf.end(), submitRes.submitId.begin(), submitRes.submitId.end());
                crypto::Hash256 rewardId = crypto::sha256(ridBuf.data(), ridBuf.size());
                if (transfer_->creditRewardDeterministic(authorAddr, rewardId, submitRes.acceptanceReward)) {
                    rewardAmt = submitRes.acceptanceReward;
                }
            }
            std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8)
                      << (static_cast<double>(rewardAmt) / 100000000.0) << " NGT\n";

            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownPoeEntries_.insert(crypto::toHex(submitRes.submitId));
            }
            broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
            for (const auto& vv : poeV1_->getVotesForSubmit(submitRes.submitId)) {
                crypto::Hash256 vid = vv.payloadHash();
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    knownPoeVotes_.insert(crypto::toHex(vid));
                }
                broadcastInv(synapse::InvType::POE_VOTE, vid);
            }
	            return 0;
	        }

	        if (sub == "submit-code") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < args.size(); ++i) {
	                if (args[i].rfind("--", 0) != 0) continue;
	                std::string k = args[i].substr(2);
	                std::string v;
	                if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
	                    v = args[i + 1];
	                    i++;
	                }
	                opts[k] = v;
	            }

	            std::string title = opts["title"];
	            std::string patch = opts["patch"];
	            std::string patchFile = opts["patch-file"];
	            if (patch.empty() && !patchFile.empty()) {
	                std::ifstream in(patchFile, std::ios::binary);
	                if (!in) {
	                    std::cerr << "Failed to read --patch-file\n";
	                    return 1;
	                }
	                std::ostringstream ss;
	                ss << in.rdbuf();
	                patch = ss.str();
	            }

	            if (title.empty() || patch.empty()) {
	                std::cerr << "Missing --title and --patch/--patch-file\n";
	                return 1;
	            }
	            if (!poeV1_ || !transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
	                std::cerr << "PoE/wallet not ready\n";
	                return 1;
	            }

	            std::vector<crypto::Hash256> citations;
	            std::string cites = opts["citations"];
	            if (!cites.empty()) {
	                for (char& c : cites) if (c == ';') c = ',';
	                std::string cur;
	                for (size_t i = 0; i <= cites.size(); ++i) {
	                    if (i == cites.size() || cites[i] == ',') {
	                        std::string t = cur;
	                        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
	                        if (!t.empty()) {
	                            crypto::Hash256 h{};
	                            if (!parseHash256(t, h)) {
	                                std::cerr << "Invalid --citations entry\n";
	                                return 1;
	                            }
	                            citations.push_back(h);
	                        }
	                        cur.clear();
	                    } else {
	                        cur.push_back(cites[i]);
	                    }
	                }
	            }

	            crypto::PrivateKey pk{};
	            auto pkv = keys_->getPrivateKey();
	            if (pkv.size() < pk.size()) {
	                std::cerr << "Invalid private key\n";
	                return 1;
	            }
	            std::memcpy(pk.data(), pkv.data(), pk.size());

	            updatePoeValidatorsFromStake();
	            auto submitRes = poeV1_->submit(core::poe_v1::ContentType::CODE, title, patch, citations, pk, true);
	            if (!submitRes.ok) {
	                std::cerr << "PoE submit failed: " << submitRes.error << "\n";
	                return 1;
	            }
	            std::cout << "submitId=" << crypto::toHex(submitRes.submitId) << "\n";
	            std::cout << "contentId=" << crypto::toHex(submitRes.contentId) << "\n";

	            crypto::PublicKey authorPub = crypto::derivePublicKey(pk);
	            std::string authorAddr = addressFromPubKey(authorPub);
	            if (authorAddr.empty()) authorAddr = address_;

	            uint64_t rewardAmt = 0;
	            if (submitRes.finalized && submitRes.acceptanceReward > 0) {
	                std::vector<uint8_t> ridBuf;
	                const std::string tag = "poe_v1_accept";
	                ridBuf.insert(ridBuf.end(), tag.begin(), tag.end());
	                ridBuf.insert(ridBuf.end(), submitRes.submitId.begin(), submitRes.submitId.end());
	                crypto::Hash256 rewardId = crypto::sha256(ridBuf.data(), ridBuf.size());
	                if (transfer_->creditRewardDeterministic(authorAddr, rewardId, submitRes.acceptanceReward)) {
	                    rewardAmt = submitRes.acceptanceReward;
	                }
	            }
	            std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8)
	                      << (static_cast<double>(rewardAmt) / 100000000.0) << " NGT\n";

	            {
	                std::lock_guard<std::mutex> lock(invMtx_);
	                knownPoeEntries_.insert(crypto::toHex(submitRes.submitId));
	            }
	            broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
	            for (const auto& vv : poeV1_->getVotesForSubmit(submitRes.submitId)) {
	                crypto::Hash256 vid = vv.payloadHash();
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    knownPoeVotes_.insert(crypto::toHex(vid));
	                }
	                broadcastInv(synapse::InvType::POE_VOTE, vid);
	            }
	            return 0;
	        }

	        if (sub == "list-code") {
	            if (!poeV1_) {
	                std::cerr << "PoE not ready\n";
	                return 1;
	            }
	            size_t limit = 25;
	            for (size_t i = 2; i < args.size(); ++i) {
	                if (args[i] == "--limit" && i + 1 < args.size()) {
	                    limit = static_cast<size_t>(std::max(1, std::stoi(args[i + 1])));
	                    i++;
	                }
	            }
	            auto ids = poeV1_->listEntryIds(0);
	            size_t shown = 0;
	            for (auto it = ids.rbegin(); it != ids.rend() && shown < limit; ++it) {
	                auto e = poeV1_->getEntry(*it);
	                if (!e) continue;
	                if (e->contentType != core::poe_v1::ContentType::CODE) continue;
	                std::cout << crypto::toHex(*it) << "  " << e->title << "\n";
	                shown++;
	            }
	            if (shown == 0) std::cout << "(none)\n";
	            return 0;
	        }

	        if (sub == "fetch-code") {
	            if (args.size() < 3) {
	                std::cerr << "Usage: synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	                return 1;
	            }
	            if (!poeV1_) {
	                std::cerr << "PoE not ready\n";
	                return 1;
	            }
	            crypto::Hash256 id{};
	            if (!parseHash256(args[2], id)) {
	                std::cerr << "Invalid id\n";
	                return 1;
	            }
	            auto entry = poeV1_->getEntry(id);
	            crypto::Hash256 submitId = id;
	            if (!entry) {
	                entry = poeV1_->getEntryByContentId(id);
	                if (entry) submitId = entry->submitId();
	            }
	            if (!entry) {
	                std::cerr << "not_found\n";
	                return 1;
	            }
	            if (entry->contentType != core::poe_v1::ContentType::CODE) {
	                std::cerr << "not_code_entry\n";
	                return 1;
	            }
	            std::cout << "submitId=" << crypto::toHex(submitId) << "\n";
	            std::cout << "contentId=" << crypto::toHex(entry->contentId()) << "\n";
	            std::cout << "timestamp=" << entry->timestamp << "\n";
	            std::cout << "title=" << entry->title << "\n";
	            std::cout << "finalized=" << (poeV1_->isFinalized(submitId) ? "true" : "false") << "\n";
	            std::cout << "patch:\n";
	            std::cout << entry->body << "\n";
	            return 0;
	        }

	        if (sub == "vote") {
	            if (args.size() < 3) {
	                std::cerr << "Usage: synapsed poe vote <submitIdHex>\n";
	                return 1;
            }
            if (!poeV1_ || !keys_ || !keys_->isValid()) {
                std::cerr << "PoE/wallet not ready\n";
                return 1;
            }
            crypto::Hash256 submitId{};
            if (!parseHash256(args[2], submitId)) {
                std::cerr << "Invalid submitId\n";
                return 1;
            }
            crypto::PrivateKey pk{};
            auto pkv = keys_->getPrivateKey();
            if (pkv.size() < pk.size()) {
                std::cerr << "Invalid private key\n";
                return 1;
            }
            std::memcpy(pk.data(), pkv.data(), pk.size());

            core::poe_v1::ValidationVoteV1 v;
            v.version = 1;
            v.submitId = submitId;
            v.prevBlockHash = poeV1_->chainSeed();
            v.flags = 0;
            v.scores = {100, 100, 100};
            core::poe_v1::signValidationVoteV1(v, pk);
            bool ok = poeV1_->addVote(v);
            crypto::Hash256 voteId = v.payloadHash();
            if (ok) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    knownPoeVotes_.insert(crypto::toHex(voteId));
                }
                broadcastInv(synapse::InvType::POE_VOTE, voteId);
            }

            uint64_t credited = maybeCreditAcceptanceReward(submitId);
            std::cout << (ok ? "vote_added\n" : "vote_duplicate\n");
            if (credited > 0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8)
                          << (static_cast<double>(credited) / 100000000.0) << " NGT\n";
            }
            return ok ? 0 : 1;
        }

        if (sub == "finalize") {
            if (args.size() < 3) {
                std::cerr << "Usage: synapsed poe finalize <submitIdHex>\n";
                return 1;
            }
            if (!poeV1_) {
                std::cerr << "PoE not ready\n";
                return 1;
            }
            crypto::Hash256 submitId{};
            if (!parseHash256(args[2], submitId)) {
                std::cerr << "Invalid submitId\n";
                return 1;
            }
            auto fin = poeV1_->finalize(submitId);
            if (!fin.has_value()) {
                std::cerr << "not_finalized\n";
                return 1;
            }
            std::cout << "finalized\n";
            uint64_t credited = maybeCreditAcceptanceReward(submitId);
            if (credited > 0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8)
                          << (static_cast<double>(credited) / 100000000.0) << " NGT\n";
            }
            return 0;
        }

	        if (sub == "epoch") {
	            uint64_t budget = 0;
	            uint32_t iters = static_cast<uint32_t>(utils::Config::instance().getInt("poe.epoch_iterations", 20));
	            int64_t cfgBudget = utils::Config::instance().getInt64("poe.epoch_budget", 100000000LL);
            if (cfgBudget > 0) budget = static_cast<uint64_t>(cfgBudget);

            for (size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--budget" && i + 1 < args.size()) {
                    uint64_t v = 0;
                    if (!parseNgtAtomic(args[i + 1], v)) {
                        std::cerr << "Invalid --budget\n";
                        return 1;
                    }
                    budget = v;
                    i++;
                } else if (args[i] == "--iters" && i + 1 < args.size()) {
                    iters = static_cast<uint32_t>(std::max(1, std::stoi(args[i + 1])));
                    i++;
                }
            }

            if (!poeV1_ || !transfer_) {
                std::cerr << "PoE/transfer not ready\n";
                return 1;
            }
	            auto epochRes = poeV1_->runEpoch(budget, iters);
	            if (!epochRes.ok) {
	                std::cerr << "PoE epoch failed: " << epochRes.error << "\n";
	                return 1;
	            }

	            {
	                crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
	                std::lock_guard<std::mutex> lock(invMtx_);
	                knownPoeEpochs_.insert(crypto::toHex(hid));
	            }
	            broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

	            uint64_t mintedTotal = 0;
	            uint64_t mintedMine = 0;
	            uint64_t mintedCount = 0;
	            for (const auto& a : epochRes.allocations) {
                std::string addr = addressFromPubKey(a.authorPubKey);
                if (addr.empty()) continue;
                crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, a.contentId);
                if (transfer_->creditRewardDeterministic(addr, rid, a.amount)) {
                    mintedTotal += a.amount;
                    mintedCount += 1;
                    if (!address_.empty() && addr == address_) mintedMine += a.amount;
                }
            }

            std::cout << "epochId=" << epochRes.epochId << "\n";
            std::cout << "allocationHash=" << crypto::toHex(epochRes.allocationHash) << "\n";
            std::cout << "minted=" << std::fixed << std::setprecision(8)
                      << (static_cast<double>(mintedTotal) / 100000000.0) << " NGT\n";
            std::cout << "mintedEntries=" << mintedCount << "\n";
            if (mintedMine > 0) {
                std::cout << "youEarned=" << std::fixed << std::setprecision(8)
                          << (static_cast<double>(mintedMine) / 100000000.0) << " NGT\n";
            }
            return 0;
        }

        if (sub == "export" || sub == "import") {
            if (args.size() < 3) {
                std::cerr << "Usage: synapsed poe " << sub << " <path>\n";
                return 1;
            }
            std::filesystem::path poeDb = std::filesystem::path(config_.dataDir) / "poe" / "poe.db";
            std::filesystem::path poeWal = poeDb;
            poeWal += "-wal";
            std::filesystem::path poeShm = poeDb;
            poeShm += "-shm";

            std::filesystem::path target = args[2];
            bool targetIsDir = std::filesystem::is_directory(target);
            if (sub == "export") {
                std::filesystem::path outDb = targetIsDir ? (target / "poe.db") : target;
                std::filesystem::create_directories(outDb.parent_path());
                std::error_code ec2;
                std::filesystem::copy_file(poeDb, outDb, std::filesystem::copy_options::overwrite_existing, ec2);
                if (ec2) {
                    std::cerr << "copy_failed\n";
                    return 1;
                }
                std::filesystem::path outWal = outDb;
                outWal += "-wal";
                std::filesystem::path outShm = outDb;
                outShm += "-shm";
                if (std::filesystem::exists(poeWal)) {
                    std::filesystem::copy_file(poeWal, outWal, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                if (std::filesystem::exists(poeShm)) {
                    std::filesystem::copy_file(poeShm, outShm, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                std::cout << "exported\n";
                return 0;
            } else {
                std::filesystem::path inDb = targetIsDir ? (target / "poe.db") : target;
                std::filesystem::path inWal = inDb;
                inWal += "-wal";
                std::filesystem::path inShm = inDb;
                inShm += "-shm";

                if (poeV1_) poeV1_->close();
                std::filesystem::create_directories(poeDb.parent_path());
                std::error_code ec2;
                std::filesystem::copy_file(inDb, poeDb, std::filesystem::copy_options::overwrite_existing, ec2);
                if (ec2) {
                    std::cerr << "copy_failed\n";
                    return 1;
                }
                if (std::filesystem::exists(inWal)) {
                    std::filesystem::copy_file(inWal, poeWal, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                if (std::filesystem::exists(inShm)) {
                    std::filesystem::copy_file(inShm, poeShm, std::filesystem::copy_options::overwrite_existing, ec2);
                }
                std::cout << "imported\n";
                return 0;
            }
        }

        std::cerr << "Unknown poe subcommand: " << sub << "\n";
        return 1;
    }
    
    int run() {
        running_ = true;
        startTime_ = std::time(nullptr);
        
        utils::Logger::info("Node starting...");
        
        // Check if we're in Kiro environment or non-interactive terminal
        const char* kiro_env = std::getenv("KIRO_SESSION");
        bool in_kiro = (kiro_env != nullptr);
        bool interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
        
        const bool daemonRuntime = config_.daemon || in_kiro || !interactive;
        g_daemonMode = daemonRuntime;
        if (daemonRuntime) {
            if (in_kiro) {
                std::cout << "Detected Kiro environment - starting in daemon mode..." << std::endl;
            } else if (!interactive) {
                std::cout << "Non-interactive terminal - starting in daemon mode..." << std::endl;
            } else {
                std::cout << "Starting in daemon mode..." << std::endl;
            }
            return runDaemon();
        }
        
        if (!config_.tui) std::cout << "Starting with TUI..." << std::endl;
        return runWithTUI();
    }
    
    void shutdown() {
        if (!running_) return;
        
        utils::Logger::info("Initiating shutdown sequence...");
        running_ = false;
        (void)persistNaanSchedulerState("shutdown");
        (void)persistNaanCrashState("shutdown");
        naanRuntimeInitialized_.store(false);
        
	        if (network_) network_->stop();
	        if (discovery_) discovery_->stop();
	        if (rpc_) rpc_->stop();
	        {
	            std::lock_guard<std::mutex> lock(webMtx_);
	            if (webAi_) webAi_->shutdown();
	            if (webSearch_) webSearch_->shutdown();
	            webAi_.reset();
	            webSearch_.reset();
	            webDetector_.reset();
	            webExtractor_.reset();
	        }
	        if (privacy_) privacy_->shutdown();
            (void)stopManagedTorRuntimeIfOwned(false);
	        if (quantumManager_) quantumManager_->shutdown();
	        if (db_) db_->close();
        
        stopThreads();
        
        saveState();
        
        utils::Config::instance().save(config_.dataDir + "/synapsenet.conf");
        utils::Logger::info("Shutdown complete");
        utils::Logger::shutdown();
    }
    
    void reload() {
        utils::Logger::info("Reloading configuration...");
        loadConfiguration();
    }
    
    NodeStats getStats() const {
        NodeStats stats;
        stats.uptime = std::time(nullptr) - startTime_;
        stats.peersConnected = network_ ? network_->peerCount() : 0;
	        stats.knowledgeEntries = poeV1_ ? poeV1_->totalEntries() : (knowledge_ ? knowledge_->totalEntries() : 0);
	        stats.syncProgress = syncProgress_;
	        stats.memoryUsage = getMemoryUsage();
	        stats.diskUsage = getDiskUsage();
	        stats.modelRequests = modelRequests_.load();
	        return stats;
	    }
    
    SystemInfo getSystemInfo() const {
        SystemInfo info;
        info.osName = "Unknown";
        info.cpuCores = std::thread::hardware_concurrency();
        return info;
    }
    
    bool isRunning() const { return running_; }
    const NodeConfig& getConfig() const { return config_; }
    
	private:
	    void saveState() {}

	    void setLogLevel(const std::string& level) {
	        if (level == "debug") utils::Logger::setLevel(utils::LogLevel::DEBUG);
	        else if (level == "info") utils::Logger::setLevel(utils::LogLevel::INFO);
	        else if (level == "warn") utils::Logger::setLevel(utils::LogLevel::WARN);
        else if (level == "error") utils::Logger::setLevel(utils::LogLevel::ERROR);
        else utils::Logger::setLevel(utils::LogLevel::INFO);
    }
    
    bool loadConfiguration() {
        std::string configPath = config_.configPath.empty() ? 
            config_.dataDir + "/synapsenet.conf" : config_.configPath;
        
        if (!utils::Config::instance().load(configPath)) {
            utils::Logger::info("No config file found, using defaults");
            utils::Config::instance().loadDefaults();
        }
        
        auto& cfg = utils::Config::instance();
        auto readBoundedU32 = [&](const std::string& key, int fallback, uint32_t minValue, uint32_t maxValue) {
            int64_t v = cfg.getInt64(key, fallback);
            if (v < static_cast<int64_t>(minValue)) v = static_cast<int64_t>(minValue);
            if (v > static_cast<int64_t>(maxValue)) v = static_cast<int64_t>(maxValue);
            return static_cast<uint32_t>(v);
        };
        auto readBoundedU64 = [&](const std::string& key, int64_t fallback, uint64_t minValue, uint64_t maxValue) {
            int64_t v = cfg.getInt64(key, fallback);
            if (v < 0) v = 0;
            uint64_t out = static_cast<uint64_t>(v);
            if (out < minValue) out = minValue;
            if (out > maxValue) out = maxValue;
            return out;
        };

        if (!config_.securityLevelSetByCli) {
            const std::string configuredSecurityLevel = cfg.getString("security.level", config_.securityLevel);
            if (!configuredSecurityLevel.empty()) {
                config_.securityLevel = configuredSecurityLevel;
            }
        }
        if (!config_.quantumSecuritySetByCli) {
            config_.quantumSecurity = cfg.getBool("security.quantum_enabled", config_.quantumSecurity);
        }
        if (config_.securityLevelSetByCli && config_.securityLevel == "standard" && !config_.quantumSecuritySetByCli) {
            config_.quantumSecurity = false;
        }

        if (config_.port == 8333) {
            config_.port = cfg.getInt("port", 8333);
        }
        if (config_.rpcPort == 8332) {
            config_.rpcPort = cfg.getInt("rpcport", 8332);
        }
        config_.maxPeers = readBoundedU32("maxpeers", cfg.getInt("network.max_peers", 125), 1, 100000);
        config_.maxInbound = readBoundedU32("maxinbound", cfg.getInt("network.max_inbound", 100), 0, 100000);
        config_.maxOutbound = readBoundedU32("maxoutbound", cfg.getInt("network.max_outbound", 25), 0, 100000);
        if (config_.maxInbound > config_.maxPeers) config_.maxInbound = config_.maxPeers;
        if (config_.maxOutbound > config_.maxPeers) config_.maxOutbound = config_.maxPeers;
        config_.networkAdaptiveAdmission = cfg.getBool("network.scale.adaptive_admission", true);
        config_.networkDeterministicEviction = cfg.getBool("network.scale.deterministic_eviction", true);
        config_.networkMaxPeersPerIp = readBoundedU32("network.scale.max_peers_per_ip", 8, 1, 100000);
        config_.networkMaxPeersPerSubnet = readBoundedU32("network.scale.max_peers_per_subnet", 32, 1, 100000);
        config_.networkSubnetPrefixBits = readBoundedU32("network.scale.subnet_prefix_bits", 24, 8, 32);
        config_.networkTokenBucketEnabled = cfg.getBool("network.scale.token_bucket_enabled", true);
        config_.networkTokenBucketBytesPerSecond = readBoundedU32(
            "network.scale.token_bucket_bytes_per_sec",
            static_cast<int>(network::MAX_MESSAGE_SIZE * 2),
            1024,
            1024 * 1024 * 128);
        config_.networkTokenBucketBytesBurst = readBoundedU32(
            "network.scale.token_bucket_bytes_burst",
            static_cast<int>(network::MAX_MESSAGE_SIZE * 4),
            1024,
            1024 * 1024 * 256);
        config_.networkTokenBucketMessagesPerSecond = readBoundedU32(
            "network.scale.token_bucket_msgs_per_sec",
            500,
            1,
            200000);
        config_.networkTokenBucketMessagesBurst = readBoundedU32(
            "network.scale.token_bucket_msgs_burst",
            1000,
            1,
            400000);
        config_.networkMalformedPenalty = readBoundedU32("network.scale.penalty_malformed", 20, 1, 10000);
        config_.networkRatePenalty = readBoundedU32("network.scale.penalty_rate", 10, 1, 10000);
        config_.networkPenaltyHalfLifeSeconds = readBoundedU32("network.scale.penalty_half_life_seconds", 900, 1, 86400 * 7);
        config_.networkBaseBanSeconds = readBoundedU32("network.scale.base_ban_seconds", 120, 1, 86400 * 30);
        config_.networkMaxBanSeconds = readBoundedU32("network.scale.max_ban_seconds", 3600, 1, 86400 * 30);
        if (config_.networkMaxBanSeconds < config_.networkBaseBanSeconds) {
            config_.networkMaxBanSeconds = config_.networkBaseBanSeconds;
        }
        config_.networkOverloadMode = cfg.getBool("network.scale.overload_mode", true);
        config_.networkOverloadEnterPeerPercent = readBoundedU32("network.scale.overload_enter_peer_percent", 90, 1, 100);
        config_.networkOverloadExitPeerPercent = readBoundedU32("network.scale.overload_exit_peer_percent", 70, 0, 100);
        if (config_.networkOverloadExitPeerPercent > config_.networkOverloadEnterPeerPercent) {
            config_.networkOverloadExitPeerPercent = config_.networkOverloadEnterPeerPercent;
        }
        config_.networkOverloadEnterBufferedRxBytes = readBoundedU64(
            "network.scale.overload_enter_buffer_bytes",
            static_cast<int64_t>(network::MAX_MESSAGE_SIZE * 32),
            network::MAX_MESSAGE_SIZE,
            network::MAX_MESSAGE_SIZE * 1024);
        config_.networkOverloadExitBufferedRxBytes = readBoundedU64(
            "network.scale.overload_exit_buffer_bytes",
            static_cast<int64_t>(network::MAX_MESSAGE_SIZE * 16),
            network::MAX_MESSAGE_SIZE,
            network::MAX_MESSAGE_SIZE * 1024);
        if (config_.networkOverloadExitBufferedRxBytes > config_.networkOverloadEnterBufferedRxBytes) {
            config_.networkOverloadExitBufferedRxBytes = config_.networkOverloadEnterBufferedRxBytes;
        }
        config_.networkInvMaxItems = readBoundedU32("network.scale.inv_max_items", 256, 1, 5000);
        config_.networkInvOverloadItems = readBoundedU32("network.scale.inv_overload_items", 32, 1, 1000);
        if (config_.networkInvOverloadItems > config_.networkInvMaxItems) {
            config_.networkInvOverloadItems = config_.networkInvMaxItems;
        }
        config_.networkGetDataMaxItems = readBoundedU32("network.scale.getdata_max_items", 128, 1, 5000);
        config_.networkGetDataOverloadItems = readBoundedU32("network.scale.getdata_overload_items", 32, 1, 1000);
        if (config_.networkGetDataOverloadItems > config_.networkGetDataMaxItems) {
            config_.networkGetDataOverloadItems = config_.networkGetDataMaxItems;
        }
        config_.networkGossipFanoutLimit = readBoundedU32("network.scale.gossip_fanout_limit", 64, 1, 100000);
        config_.networkGossipDedupWindowSeconds = readBoundedU32("network.scale.gossip_dedup_window_seconds", 5, 1, 3600);
        config_.networkVoteDedupWindowSeconds = readBoundedU32("network.scale.vote_dedup_window_seconds", 600, 1, 86400);
        config_.networkVoteDedupMaxEntries = readBoundedU32("network.scale.vote_dedup_max_entries", 20000, 64, 2000000);
        config_.dbCacheSize = cfg.getInt("dbcache", 450);

        // Remote model routing (opt-in)
        remotePricePerRequestAtoms_ = static_cast<uint64_t>(
            std::max<int64_t>(0, cfg.getInt64("model.remote.price_per_request_atoms", 0))
        );
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            if (localOfferId_.empty()) {
                localOfferId_ = cfg.getString("model.remote.offer_id", "");
                if (localOfferId_.empty()) localOfferId_ = randomHex16();
            }
        }

        reloadImplantUpdatePoliciesFromConfig();
        refreshSecurityPolicyHashes("config_load");

        const bool torRequired = cfg.getBool("agent.tor.required", true);
        const bool allowClearnetFallback = cfg.getBool("agent.routing.allow_clearnet_fallback", false);
        const bool allowP2PFallback = cfg.getBool("agent.routing.allow_p2p_clearnet_fallback", false);

        agentTorRequired_.store(torRequired);
        agentAllowClearnetFallback_.store(allowClearnetFallback);
        agentAllowP2PFallback_.store(allowP2PFallback);
        int64_t ownedManagedPid = 0;
        bool ownedManagedTor = false;
        if (readManagedTorPidFile(&ownedManagedPid)) {
#ifndef _WIN32
            ownedManagedTor = managedTorProcessMatchesOwnership(ownedManagedPid);
#else
            ownedManagedTor = false;
#endif
        }
        managedTorPid_.store(ownedManagedTor ? ownedManagedPid : 0);
        agentTorManaged_.store(ownedManagedTor);

        if (torRequired) {
            config_.privacyMode = true;
        }

        refreshTorRoutePolicy(true);
        
        return true;
    }
    
    bool initDatabase() {
        if (config_.amnesia) {
            utils::Logger::info("Amnesia mode: using in-memory database");
            return true;
        }
        
        std::string dbPath = config_.dataDir + "/chaindata";
        std::filesystem::create_directories(dbPath);
        
        db_ = std::make_unique<database::Database>();
        if (!db_->open(dbPath + "/chain.db")) {
            utils::Logger::error("Failed to open database at " + dbPath);
            return false;
        }
        
        utils::Logger::info("Database initialized: " + dbPath);
        return true;
    }
    
    bool initCrypto() {
        keys_ = std::make_unique<crypto::Keys>();
        
        std::string walletPath = config_.dataDir + "/wallet.dat";
        
        if (std::filesystem::exists(walletPath)) {
            if (!keys_->load(walletPath, "")) {
                utils::Logger::error("Failed to load wallet");
                return false;
            }
            utils::Logger::info("Wallet loaded successfully");
        } else if (config_.tui) {
            utils::Logger::info("Wallet not found, waiting for TUI creation");
            return true;
        } else {
            utils::Logger::info("Generating new wallet...");
            if (!keys_->generate()) {
                utils::Logger::error("Failed to generate keys");
                return false;
            }
            if (!keys_->save(walletPath, "")) {
                utils::Logger::error("Failed to save wallet");
                return false;
            }
            utils::Logger::info("New wallet created");
        }
        
        if (keys_->isValid()) {
            address_ = keys_->getAddress();
            utils::Logger::info("Wallet address: " + address_.substr(0, 16) + "...");
            updateSignerFromKeys();
        }
        return true;
    }
    
    bool initQuantumSecurity() {
        std::string requestedLevel = config_.securityLevel;
        std::transform(requestedLevel.begin(), requestedLevel.end(), requestedLevel.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::replace(requestedLevel.begin(), requestedLevel.end(), '_', '-');

        if (requestedLevel == "quantumready") {
            requestedLevel = "quantum-ready";
        }
        if (requestedLevel != "standard" && requestedLevel != "high" &&
            requestedLevel != "paranoid" && requestedLevel != "quantum-ready") {
            utils::Logger::warn("Unknown security level '" + config_.securityLevel + "', falling back to standard");
            requestedLevel = "standard";
        }
        config_.securityLevel = requestedLevel;
        if (config_.securityLevel != "standard") {
            config_.quantumSecurity = true;
        }
        if (config_.quantumSecurity && config_.securityLevel == "standard") {
            config_.securityLevel = "high";
        }

        if (!config_.quantumSecurity) {
            utils::Logger::info("Quantum security: disabled");
            return true;
        }
        
        quantumManager_ = std::make_unique<quantum::QuantumManager>();
        
        quantum::SecurityLevel level = quantum::SecurityLevel::STANDARD;
        if (config_.securityLevel == "high") {
            level = quantum::SecurityLevel::HIGH;
        } else if (config_.securityLevel == "paranoid") {
            level = quantum::SecurityLevel::PARANOID;
        } else if (config_.securityLevel == "quantum-ready") {
            level = quantum::SecurityLevel::QUANTUM_READY;
        }
        
        if (!quantumManager_->init(level)) {
            utils::Logger::error("Failed to initialize quantum security");
            return false;
        }
        
        utils::Logger::info("Quantum security initialized: " + config_.securityLevel);
        return true;
    }
    
    bool initNetwork() {
        network_ = std::make_unique<network::Network>();
        discovery_ = std::make_unique<network::Discovery>();
        
        network::NetworkConfig netCfg;
        netCfg.maxPeers = config_.maxPeers;
        netCfg.maxInbound = config_.maxInbound;
        netCfg.maxOutbound = config_.maxOutbound;
        netCfg.adaptiveAdmission = config_.networkAdaptiveAdmission;
        netCfg.deterministicEviction = config_.networkDeterministicEviction;
        netCfg.maxPeersPerIp = config_.networkMaxPeersPerIp;
        netCfg.maxPeersPerSubnet = config_.networkMaxPeersPerSubnet;
        netCfg.subnetPrefixBits = static_cast<uint8_t>(config_.networkSubnetPrefixBits);
        netCfg.enableTokenBucketDosGuard = config_.networkTokenBucketEnabled;
        netCfg.tokenBucketBytesPerSecond = config_.networkTokenBucketBytesPerSecond;
        netCfg.tokenBucketBytesBurst = config_.networkTokenBucketBytesBurst;
        netCfg.tokenBucketMessagesPerSecond = config_.networkTokenBucketMessagesPerSecond;
        netCfg.tokenBucketMessagesBurst = config_.networkTokenBucketMessagesBurst;
        netCfg.malformedPenaltyScore = config_.networkMalformedPenalty;
        netCfg.ratePenaltyScore = config_.networkRatePenalty;
        netCfg.penaltyHalfLifeSeconds = config_.networkPenaltyHalfLifeSeconds;
        netCfg.baseBanSeconds = config_.networkBaseBanSeconds;
        netCfg.maxBanSeconds = config_.networkMaxBanSeconds;
        netCfg.enableOverloadMode = config_.networkOverloadMode;
        netCfg.overloadEnterPeerPercent = config_.networkOverloadEnterPeerPercent;
        netCfg.overloadExitPeerPercent = config_.networkOverloadExitPeerPercent;
        netCfg.overloadEnterBufferedRxBytes = config_.networkOverloadEnterBufferedRxBytes;
        netCfg.overloadExitBufferedRxBytes = config_.networkOverloadExitBufferedRxBytes;

        const bool torRequired = agentTorRequired_.load();
        bool torReachable = probeTorSocks();
        if (torRequired && !torReachable) {
            torReachable = maybeStartManagedTorRuntimeWithBackoff(true, "init_network");
            if (torReachable) {
                agentTorManaged_.store(true);
            }
        }
        if (torReachable) {
            resetManagedTorRestartBackoffState();
        }
        agentTorReachable_.store(torReachable);
        refreshTorWebReadiness(torReachable, false);
        core::TorRoutePolicyInput routeIn;
        routeIn.torRequired = torRequired;
        routeIn.torReachable = torReachable;
        routeIn.allowClearnetFallback = agentAllowClearnetFallback_.load();
        routeIn.allowP2PFallback = agentAllowP2PFallback_.load();
        const auto route = core::evaluateTorRoutePolicy(routeIn);
        agentTorDegraded_.store(route.torDegraded);
        updateAndLogTorReadinessState(torRequired, torReachable, agentTorWebReady_.load(), route.torDegraded);

        if (torRequired) {
            netCfg.useSocksProxy = torReachable;
            netCfg.socksProxyHost = configuredTorSocksHost();
            netCfg.socksProxyPort = configuredTorSocksPort();
            if (!route.allowP2PDiscovery) {
                netCfg.maxOutbound = 0;
            }
        }
        network_->setConfig(netCfg);
        
        network::DiscoveryConfig discCfg;
        discCfg.maxPeers = config_.maxPeers;
        discCfg.minPeers = std::min<uint32_t>(8, config_.maxOutbound);
        discCfg.bootstrapQuarantineSeconds = static_cast<uint32_t>(std::max<int64_t>(
            30, utils::Config::instance().getInt64("network.discovery.bootstrap_quarantine_seconds", 600)));
        discovery_->setConfig(discCfg);
        
        if (config_.testnet) {
            discovery_->addBootstrap("testnet-seed1.synapsenet.io", 18333);
            discovery_->addBootstrap("testnet-seed2.synapsenet.io", 18333);
            discovery_->addDnsSeed("testnet-seed1.synapsenet.io");
            discovery_->addDnsSeed("testnet-seed2.synapsenet.io");
        } else if (config_.regtest) {
            utils::Logger::info("Regtest mode: no bootstrap nodes");
        } else {
            // Primary seed node (VPS - Finland)
            discovery_->addBootstrap("144.31.169.103", 8333);
            // DNS-based seeds (future)
            discovery_->addBootstrap("seed1.synapsenet.io", 8333);
            discovery_->addBootstrap("seed2.synapsenet.io", 8333);
            discovery_->addBootstrap("seed3.synapsenet.io", 8333);
            discovery_->addBootstrap("seed4.synapsenet.io", 8333);
            discovery_->addDnsSeed("seed1.synapsenet.io");
            discovery_->addDnsSeed("seed2.synapsenet.io");
            discovery_->addDnsSeed("seed3.synapsenet.io");
            discovery_->addDnsSeed("seed4.synapsenet.io");
        }
        
        for (const auto& node : config_.seedNodes) {
            size_t colonPos = node.find(':');
            if (colonPos != std::string::npos) {
                std::string host = node.substr(0, colonPos);
                uint16_t port = std::stoi(node.substr(colonPos + 1));
                discovery_->addBootstrap(host, port);
                discovery_->addDnsSeed(host);
            }
        }
        
        network_->onMessage([this](const std::string& peerId, const network::Message& msg) {
            handleMessage(peerId, msg);
        });
        
        network_->onPeerConnected([this](const network::Peer& peer) {
            handlePeerConnected(peer);
        });
        
        network_->onPeerDisconnected([this](const network::Peer& peer) {
            handlePeerDisconnected(peer);
        });
        
        // Setup Discovery callbacks for peer exchange
        discovery_->setSendMessageCallback([this](const std::string& peerId, const std::string& command, const std::vector<uint8_t>& payload) -> bool {
            if (!network_) return false;
            auto msg = makeMessage(command, payload);
            return network_->send(peerId, msg);
        });
        
        discovery_->setGetConnectedPeersCallback([this]() -> std::vector<std::string> {
            if (!network_) return {};
            std::vector<std::string> peerIds;
            for (const auto& peer : network_->getPeers()) {
                if (peer.state == network::PeerState::CONNECTED) {
                    peerIds.push_back(peer.id);
                }
            }
            return peerIds;
        });
        
        // Try to determine external IP from version messages or config
        // For now, we'll rely on peers telling us our address via version messages
        // In the future, can add STUN or other methods here
        std::string externalIP = config_.bindAddress;
        if (externalIP == "0.0.0.0" || externalIP.empty()) {
            // Try to get from config or leave empty (will be discovered)
            externalIP = "";
        }
        if (!externalIP.empty()) {
            discovery_->setExternalAddress(externalIP);
        }
        
        uint16_t port = config_.testnet ? 18333 : config_.port;
        if (!network_->start(port)) {
            utils::Logger::info("Network offline mode - port " + std::to_string(port) + " unavailable");
            offlineMode_ = true;
        } else {
            offlineMode_ = false;
            uint16_t bound = network_->getPort();
            if (bound != 0) config_.port = bound;
            utils::Logger::info("Network started on port " + std::to_string(bound));
            const auto route = refreshTorRoutePolicy(true);
            if (route.allowP2PDiscovery) {
                discovery_->start(bound);
                discovery_->refreshFromDNS();
            } else {
                utils::Logger::warn("NAAN Tor-required mode active: outbound P2P discovery is suspended (degraded)");
            }
        }
        
        return true;
    }
    
    bool initCore() {
        if (!config_.tui) std::cout << "Creating core components..." << std::endl;
        ledger_ = std::make_unique<core::Ledger>();
        knowledge_ = std::make_unique<core::KnowledgeNetwork>();
        transfer_ = std::make_unique<core::TransferManager>();
        consensus_ = std::make_unique<core::Consensus>();
        poeV1_ = std::make_unique<core::PoeV1Engine>();
        
        if (!config_.tui) std::cout << "Creating directories..." << std::endl;
        std::string ledgerPath = config_.dataDir + "/ledger";
        std::string knowledgePath = config_.dataDir + "/knowledge";
        std::string transferPath = config_.dataDir + "/transfer";
        std::string consensusPath = config_.dataDir + "/consensus";
        std::string poePath = config_.dataDir + "/poe";
        std::string updatesPath = config_.dataDir + "/updates";
        std::filesystem::create_directories(ledgerPath);
        std::filesystem::create_directories(knowledgePath);
        std::filesystem::create_directories(transferPath);
        std::filesystem::create_directories(consensusPath);
        std::filesystem::create_directories(poePath);
        std::filesystem::create_directories(updatesPath);

        if (config_.resetNgt) {
            std::error_code ec;
            std::filesystem::remove(transferPath + "/transfer.db", ec);
            std::filesystem::remove(transferPath + "/transfer.db-wal", ec);
            std::filesystem::remove(transferPath + "/transfer.db-shm", ec);
            utils::Logger::info("NGT balances reset (transfer DB cleared)");
        }
        
        if (!config_.tui) std::cout << "Opening ledger..." << std::endl;
        if (!ledger_->open(ledgerPath + "/ledger.db")) {
            utils::Logger::error("Failed to open ledger");
            return false;
        }
        if (!config_.tui) std::cout << "Ledger opened successfully" << std::endl;
        
        if (!config_.tui) std::cout << "Opening knowledge DB..." << std::endl;
        if (!knowledge_->open(knowledgePath + "/knowledge.db")) {
            utils::Logger::error("Failed to open knowledge DB");
            return false;
        }
        
        if (!config_.tui) std::cout << "Opening transfer DB..." << std::endl;
        if (!transfer_->open(transferPath + "/transfer.db")) {
            utils::Logger::error("Failed to open transfer DB");
            return false;
        }
        
        if (!config_.tui) std::cout << "Opening consensus DB..." << std::endl;
        if (!consensus_->open(consensusPath + "/consensus.db")) {
            utils::Logger::error("Failed to open consensus DB");
            return false;
        }

        if (!config_.tui) std::cout << "Opening PoE v1 DB..." << std::endl;
        if (!poeV1_->open(poePath + "/poe.db")) {
            utils::Logger::error("Failed to open PoE v1 DB");
            return false;
        }

        {
            std::string reason;
            if (!updateInstaller_.open(updatesPath + "/installer.state", &reason)) {
                utils::Logger::error("Failed to open update installer state: " + reason);
                return false;
            }
        }

        {
            std::string reason;
            if (!implantSafetyPipeline_.open(updatesPath + "/implant_safety.state", &reason)) {
                utils::Logger::error("Failed to open implant safety pipeline state: " + reason);
                return false;
            }
        }

        if (!config_.cli) {
            if (!initNaanCoordination()) {
                utils::Logger::error("Failed to initialize NAAN coordination runtime");
                return false;
            }
        }

	        core::PoeV1Config poeCfg;
            auto& runtimeCfg = utils::Config::instance();
	        poeCfg.validatorMode = config_.poeValidatorMode;
	        poeCfg.validatorMinStakeAtoms = poeMinStakeAtoms();
	        poeCfg.powBits = (config_.dev || config_.regtest) ? 12 : 16;
	        poeCfg.validatorsN = 1;
	        poeCfg.validatorsM = 1;
            {
                int64_t noveltyBands = runtimeCfg.getInt64("poe.novelty_bands", static_cast<int64_t>(poeCfg.noveltyBands));
                if (noveltyBands < 0) noveltyBands = 0;
                if (noveltyBands > 16) noveltyBands = 16;
                poeCfg.noveltyBands = static_cast<uint32_t>(noveltyBands);

                int64_t noveltyHamming = runtimeCfg.getInt64("poe.novelty_max_hamming", static_cast<int64_t>(poeCfg.noveltyMaxHamming));
                if (noveltyHamming < 0) noveltyHamming = 0;
                if (noveltyHamming > 64) noveltyHamming = 64;
                poeCfg.noveltyMaxHamming = static_cast<uint32_t>(noveltyHamming);

                int64_t minSubmitInterval = runtimeCfg.getInt64(
                    "poe.min_submit_interval_seconds",
                    static_cast<int64_t>(poeCfg.minSubmitIntervalSeconds));
                if (minSubmitInterval < 1) minSubmitInterval = 1;
                if (minSubmitInterval > 86400) minSubmitInterval = 86400;
                poeCfg.minSubmitIntervalSeconds = static_cast<uint32_t>(minSubmitInterval);
            }
	        poeCfg.limits.minPowBits = poeCfg.powBits;
	        poeCfg.limits.maxPowBits = 28;
	        poeCfg.limits.maxTitleBytes = 512;
	        poeCfg.limits.maxBodyBytes = 65536;
	        poeV1_->setConfig(poeCfg);
        {
            std::vector<crypto::PublicKey> validators;

            crypto::PublicKey selfPub{};
            bool hasSelfPub = false;
            if (keys_ && keys_->isValid()) {
                auto pubV = keys_->getPublicKey();
                if (pubV.size() >= crypto::PUBLIC_KEY_SIZE) {
                    std::memcpy(selfPub.data(), pubV.data(), selfPub.size());
                    hasSelfPub = true;
                }
            }

            auto addValidatorHex = [&](const std::string& token) {
                std::string t = token;
                auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
                while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
                while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
                if (t.empty()) return;

                if (t == "self") {
                    if (hasSelfPub) validators.push_back(selfPub);
                    return;
                }

                if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
                auto bytes = crypto::fromHex(t);
                if (bytes.size() != crypto::PUBLIC_KEY_SIZE) {
                    utils::Logger::warn("Invalid poe validator pubkey (expected 32 bytes hex): " + t);
                    return;
                }
                crypto::PublicKey pk{};
                std::memcpy(pk.data(), bytes.data(), pk.size());
                validators.push_back(pk);
            };

            if (!config_.poeValidators.empty()) {
                std::string raw = config_.poeValidators;
                for (char& c : raw) {
                    if (c == ';') c = ',';
                }
                std::string cur;
                for (char c : raw) {
                    if (c == ',') {
                        addValidatorHex(cur);
                        cur.clear();
                    } else {
                        cur.push_back(c);
                    }
                }
                addValidatorHex(cur);
            }

            if (validators.empty() && hasSelfPub) {
                validators.push_back(selfPub);
            }

            if (!validators.empty()) {
                std::sort(validators.begin(), validators.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
                    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
                });
                validators.erase(std::unique(validators.begin(), validators.end(), [](const crypto::PublicKey& a, const crypto::PublicKey& b) {
                    return a == b;
                }), validators.end());
                poeV1_->setStaticValidators(validators);
            }
        }

        updatePoeValidatorsFromStake();
        autoPoeEpochLastFinalizedCount_.store(poeV1_ ? poeV1_->totalFinalized() : 0);
        if (poeV1_ && !poeV1_->listEpochIds(1).empty()) {
            autoPoeEpochLastRunAt_.store(static_cast<uint64_t>(std::time(nullptr)));
        } else {
            autoPoeEpochLastRunAt_.store(0);
        }
        
        if (!config_.tui) std::cout << "Setting up callbacks..." << std::endl;
        networkHeight_ = ledger_->height();

        if (keys_ && keys_->isValid()) {
            ledger_->setSigner([this](const crypto::Hash256& hash) {
                return signHash(hash);
            });
        }
        
        if (!config_.tui) std::cout << "Setting up knowledge callbacks..." << std::endl;
        knowledge_->onNewEntry([this](const core::KnowledgeEntry& entry) {
            std::string h = crypto::toHex(entry.hash);
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knowledgeByHash_[h] = entry.id;
                knownKnowledge_.insert(h);
            }
            if (suppressCallbacks_) return;
            broadcastInv(synapse::InvType::KNOWLEDGE, entry.hash);
            
            if (keys_ && keys_->isValid() && ledger_) {
                core::Event ev{};
                ev.timestamp = entry.timestamp;
                ev.type = core::EventType::KNOWLEDGE;
                ev.data = entry.serialize();
                auto pub = keys_->getPublicKey();
                if (pub.size() >= ev.author.size()) {
                    std::memcpy(ev.author.data(), pub.data(), ev.author.size());
                }
                ledger_->append(ev);
            }
        });
        
        if (!config_.tui) std::cout << "Setting up transfer callbacks..." << std::endl;
        transfer_->onNewTransaction([this](const core::Transaction& tx) {
            std::string h = crypto::toHex(tx.txid);
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownTxs_.insert(h);
            }
            if (suppressCallbacks_) return;
            broadcastInv(synapse::InvType::TX, tx.txid);
            
            if (keys_ && keys_->isValid() && ledger_) {
                core::Event ev{};
                ev.timestamp = tx.timestamp;
                ev.type = core::EventType::TRANSFER;
                ev.data = tx.serialize();
                auto pub = keys_->getPublicKey();
                if (pub.size() >= ev.author.size()) {
                    std::memcpy(ev.author.data(), pub.data(), ev.author.size());
                }
                ledger_->append(ev);
            }
        });
        
        if (!config_.tui) std::cout << "Setting up ledger callbacks..." << std::endl;
        ledger_->onNewBlock([this](const core::Block& block) {
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownBlocks_.insert(crypto::toHex(block.hash));
            }
            broadcastInv(synapse::InvType::BLOCK, block.hash);
        });
        
        utils::Logger::info("Core subsystems initialized");
        if (!config_.tui) std::cout << "Core initialization complete!" << std::endl;
        return true;
    }
    
	    bool initModel() {
	        modelLoader_ = std::make_unique<model::ModelLoader>();
	        modelAccess_ = std::make_unique<model::ModelAccess>();
            modelMarketplace_ = std::make_unique<model::ModelMarketplace>();

            // Load model access config (local-only; remote rentals are opt-in).
            try {
                std::string modeStr = utils::Config::instance().getString("model.access.mode", "PRIVATE");
                modelAccess_->setMode(parseAccessMode(modeStr));
            } catch (...) {
                modelAccess_->setMode(model::AccessMode::PRIVATE);
            }
            {
                int slots = utils::Config::instance().getInt("model.access.max_slots", 3);
                if (slots < 1) slots = 1;
                modelAccess_->setMaxSlots(static_cast<uint32_t>(slots));
            }
            {
                int64_t p = utils::Config::instance().getInt64("model.access.price_per_hour_atoms", 0);
                if (p < 0) p = 0;
                modelAccess_->setPrice(static_cast<uint64_t>(p));
            }

            // Ensure we have a stable listing id matching the remote offer id.
            {
                std::string listingId;
                {
                    std::lock_guard<std::mutex> lock(remoteProvMtx_);
                    listingId = localOfferId_;
                }
                if (!listingId.empty() && modelMarketplace_) {
                    // Start as inactive until a model is loaded & access mode isn't PRIVATE.
                    modelMarketplace_->upsertModel(
                        listingId,
                        address_,
                        "active",
                        "",
                        0,
                        "GGUF",
                        modelAccess_->getPrice(),
                        remotePricePerRequestAtoms_,
                        modelAccess_->getMaxSlots(),
                        false
                    );
                }
            }
        
        std::string modelDir = config_.dataDir + "/models";
        std::filesystem::create_directories(modelDir);
        
        auto models = modelLoader_->listModels(modelDir);
        if (!models.empty()) {
            utils::Logger::info("Found " + std::to_string(models.size()) + " local models");
        }
        
	        return true;
	    }

	    bool ensureWebSubsystem() {
	        std::lock_guard<std::mutex> lock(webMtx_);
	        if (webSearch_ && webAi_ && webDetector_ && webExtractor_) return true;

	        webSearch_ = std::make_unique<web::WebSearch>();
	        webDetector_ = std::make_unique<web::QueryDetector>();
	        webExtractor_ = std::make_unique<web::HtmlExtractor>();
	        webAi_ = std::make_unique<web::AIWrapper>();

	        if (!webAi_->init()) {
	            webAi_.reset();
	            webSearch_.reset();
	            webDetector_.reset();
	            webExtractor_.reset();
	            return false;
	        }

	        webAi_->setWebSearch(webSearch_.get());
	        webAi_->setDetector(webDetector_.get());
	        webAi_->setExtractor(webExtractor_.get());
	        webAi_->enableAutoSearch(true);
	        webAi_->enableContextInjection(true);

	        webSearch_->onSearchError([this](const std::string& err) {
                const bool torRequired = agentTorRequired_.load();
                const bool torReadyForWeb = agentTorWebReady_.load();
                const std::string kind =
                    core::classifyWebSearchFailureKind(err, torRequired, torReadyForWeb);
                if (kind == "TOR_BOOTSTRAP_INCOMPLETE") {
                    utils::Logger::warn("Web search blocked: Tor bootstrap incomplete (reason=" +
                                       getTorBootstrapReasonCodeCached() + "): " + err);
                } else if (kind == "TIMEOUT") {
                    utils::Logger::warn("Web search timeout: " + err);
                } else {
                    utils::Logger::warn("Web search: " + err);
                }
	        });

	        web::SearchConfig cfg;
	        std::string webCfgPath = config_.dataDir + "/web_search.conf";
	        web::loadSearchConfig(webCfgPath, cfg);
            const std::string ahmiaOnion = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/";
            std::string naanWebCfgPath = config_.dataDir + "/naan_agent_web.conf";
            if (!std::filesystem::exists(naanWebCfgPath)) {
                std::ofstream naanCfg(naanWebCfgPath);
                if (naanCfg.is_open()) {
                    naanCfg << "clearnet_engines=duckduckgo\n";
                    naanCfg << "darknet_engines=ahmia,torch,darksearch,deepsearch\n";
                    naanCfg << "custom_darknet_urls=" << ahmiaOnion << "\n";
                    naanCfg << "route_clearnet_through_tor=1\n";
                    naanCfg << "naan_force_tor_mode=1\n";
                    naanCfg << "naan_auto_search_enabled=1\n";
                    naanCfg << "naan_auto_search_mode=both\n";
                    naanCfg << "naan_auto_search_queries=latest space engineering research,latest ai research papers,open source systems engineering best practices\n";
                    naanCfg << "naan_auto_search_max_results=4\n";
                    naanCfg << "clearnet_site_allowlist=\n";
                    naanCfg << "clearnet_site_denylist=\n";
                    naanCfg << "onion_site_allowlist=\n";
                    naanCfg << "onion_site_denylist=\n";
                    naanCfg << "clearnet_route_bypass_hosts=\n";
                    naanCfg << "onion_route_bypass_hosts=\n";
                    naanCfg << "bypass_onion_https_fallback=1\n";
                }
            }
            web::SearchConfigValidationStats validation{};
            web::loadSearchConfigOverlay(naanWebCfgPath, cfg, &validation);
            web::sanitizeSearchConfig(cfg);
            cfg.tor.runtimeMode = configuredTorRuntimeMode();
            cfg.tor.socksHost = configuredTorSocksHost();
            cfg.tor.socksPort = configuredTorSocksPort();
            cfg.tor.controlHost = "127.0.0.1";
            cfg.tor.controlPort = configuredTorControlPort();
            naanWebConfigTotalLines_.store(validation.totalLines);
            naanWebConfigAppliedLines_.store(validation.appliedLines);
            naanWebConfigInvalidLines_.store(validation.invalidLines);
            naanWebConfigUnknownKeys_.store(validation.unknownKeys);
            naanWebConfigUnknownKeySamples_ = validation.unknownKeySamples;
            naanWebConfigSanitizedWrites_.fetch_add(1);

            bool hasAhmiaOnion = false;
            for (const auto& url : cfg.customDarknetUrls) {
                if (web::normalizeUrl(url) == web::normalizeUrl(ahmiaOnion)) {
                    hasAhmiaOnion = true;
                    break;
                }
            }
            if (!hasAhmiaOnion) {
                cfg.customDarknetUrls.push_back(ahmiaOnion);
            }
	        if (cfg.connectorAuditDir.empty()) {
	            cfg.connectorAuditDir = config_.dataDir + "/audit/connectors";
	        }

	        webExtractor_->setRemoveAds(cfg.removeAds);
	        webExtractor_->setRemoveScripts(cfg.removeScripts);
	        webExtractor_->setRemoveStyles(cfg.removeStyles);
	        webExtractor_->setRiskPolicy(cfg.extractionRisk);

            const bool torRequired = agentTorRequired_.load();
            const auto route = refreshTorRoutePolicy(true);
            const bool torReachable = agentTorReachable_.load();
            const bool hardTorOnly = torRequired || cfg.naanForceTorMode;

            const bool onionOptIn = utils::Config::instance().getBool("web.inject.onion", false);
            const bool torClearnetOptIn = utils::Config::instance().getBool("web.inject.tor_clearnet", false);
            if (hardTorOnly) {
                cfg.routeClearnetThroughTor = true;
                cfg.enableClearnet = torReachable && route.allowWebClearnet;
                cfg.enableDarknet = torReachable && route.allowWebOnion;
            } else {
                cfg.enableClearnet = true;
                cfg.enableDarknet = onionOptIn;
                cfg.routeClearnetThroughTor = torClearnetOptIn;
            }
            webSearch_->init(cfg);
            return true;
        }
	    
	    bool initPrivacy() {
	        if (!config_.privacyMode) {
	            utils::Logger::info("Privacy mode: disabled");
	            return true;
        }
        
        privacy_ = std::make_unique<privacy::Privacy>();
        privacy::PrivacyConfig privConfig;
        privConfig.useTor = true;
        privConfig.circuitCount = 3;
        privConfig.rotateIdentity = true;
        privConfig.rotationInterval = 3600;
        privConfig.torSocksHost = configuredTorSocksHost();
        privConfig.torSocksPort = configuredTorSocksPort();
        privConfig.torControlHost = "127.0.0.1";
        privConfig.torControlPort = configuredTorControlPort();
        core::OnionServicePolicyInput onionInput;
        onionInput.networkPort = network_ ? network_->getPort() : config_.port;
        onionInput.overrideVirtualPort = utils::Config::instance().getInt64("agent.tor.onion.virtual_port", 0);
        onionInput.overrideTargetPort = utils::Config::instance().getInt64("agent.tor.onion.target_port", 0);
        onionInput.dataDir = config_.dataDir;
        const auto onionPolicy = core::evaluateOnionServicePolicy(onionInput);
        privConfig.onionServiceDir = onionPolicy.serviceDir;
        privConfig.onionVirtualPort = onionPolicy.virtualPort;
        privConfig.onionTargetPort = onionPolicy.targetPort;
        
        if (!privacy_->init(privConfig)) {
            if (agentTorRequired_.load()) {
                utils::Logger::warn("Failed to initialize privacy layer; entering deterministic degraded mode");
                agentTorDegraded_.store(true);
                return true;
            }
            utils::Logger::error("Failed to initialize privacy layer");
            return false;
        }
        
        const bool torRequired = agentTorRequired_.load();
        bool privacyEnabled = privacy_->enable(privacy::PrivacyMode::FULL);
        const auto recovery = core::runTorPrivacyEnableRecovery(
            privacyEnabled,
            torRequired,
            8,
            [this]() {
                const auto route = refreshTorRoutePolicy(true);
                core::TorPrivacyBootstrapProbe probe;
                probe.torReachable = agentTorReachable_.load();
                probe.torDegraded = route.torDegraded;
                return probe;
            },
            [this, &privConfig]() {
                privacy_->shutdown();
                return privacy_->init(privConfig);
            },
            [this]() {
                return privacy_->enable(privacy::PrivacyMode::FULL);
            },
            [](int ms) {
                std::this_thread::sleep_for(std::chrono::milliseconds(ms));
            });
        privacyEnabled = recovery.enabled;
        const int torBootstrapRecoveryRetries = recovery.retryAttemptsUsed;

        if (!privacyEnabled) {
            if (torRequired) {
                const auto route = refreshTorRoutePolicy(true);
                const bool torReachable = agentTorReachable_.load();
                agentTorDegraded_.store(route.torDegraded);
                updateAndLogTorReadinessState(torRequired, torReachable, agentTorWebReady_.load(), route.torDegraded);
                if (torReachable && !route.torDegraded) {
                    utils::Logger::warn(
                        "Tor route is reachable, but privacy FULL mode (onion service) failed; continuing without onion service");
                } else {
                    utils::Logger::warn("Failed to enable Tor during startup bootstrap; entering deterministic degraded mode");
                }
                return true;
            }
            utils::Logger::error("Failed to enable Tor");
            return false;
        }
        
        std::string onion = privacy_->getOnionAddress();
        agentTorDegraded_.store(false);
        if (torBootstrapRecoveryRetries > 0) {
            utils::Logger::info(
                "Tor bootstrap recovered after " + std::to_string(torBootstrapRecoveryRetries) +
                " privacy retry attempts");
        }
        utils::Logger::info("Privacy mode enabled: " + onion);
        return true;
    }
    
    bool initRPC() {
        if (config_.rpcPort == 0) {
            utils::Logger::info("RPC server: disabled");
            return true;
        }
        
        rpc_ = std::make_unique<web::RpcServer>();
        if (!rpc_->start(config_.rpcPort)) {
            utils::Logger::error("Failed to start RPC server");
            return false;
        }

		        rpc_->registerMethod("poe.submit", [this](const std::string& params) {
		            return handleRpcPoeSubmit(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.submit_code", [this](const std::string& params) {
		            return handleRpcPoeSubmitCode(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.list_code", [this](const std::string& params) {
		            return handleRpcPoeListCode(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.fetch_code", [this](const std::string& params) {
		            return handleRpcPoeFetchCode(params);
		        }, false, 2000);

		        rpc_->registerMethod("poe.vote", [this](const std::string& params) {
		            return handleRpcPoeVote(params);
		        }, false, 5000);

	        rpc_->registerMethod("poe.finalize", [this](const std::string& params) {
	            return handleRpcPoeFinalize(params);
	        }, false, 2000);

	        rpc_->registerMethod("poe.epoch", [this](const std::string& params) {
	            return handleRpcPoeEpoch(params);
	        }, false, 200);

	        rpc_->registerMethod("poe.export", [this](const std::string& params) {
	            return handleRpcPoeExport(params);
	        }, false, 50);

	        rpc_->registerMethod("poe.import", [this](const std::string& params) {
	            return handleRpcPoeImport(params);
	        }, false, 50);

	        rpc_->registerMethod("wallet.address", [this](const std::string& params) {
	            return handleRpcWalletAddress(params);
	        }, false, 5000);

		        rpc_->registerMethod("wallet.balance", [this](const std::string& params) {
		            return handleRpcWalletBalance(params);
		        }, false, 5000);

		        rpc_->registerMethod("model.status", [this](const std::string& params) {
		            return handleRpcModelStatus(params);
		        }, false, 5000);

		        rpc_->registerMethod("model.list", [this](const std::string& params) {
		            return handleRpcModelList(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.load", [this](const std::string& params) {
		            return handleRpcModelLoad(params);
		        }, false, 50);

		        rpc_->registerMethod("model.unload", [this](const std::string& params) {
		            return handleRpcModelUnload(params);
		        }, false, 50);

		        rpc_->registerMethod("model.access.get", [this](const std::string& params) {
		            return handleRpcModelAccessGet(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.access.set", [this](const std::string& params) {
		            return handleRpcModelAccessSet(params);
		        }, false, 2000);

		        rpc_->registerMethod("market.listings", [this](const std::string& params) {
		            return handleRpcMarketListings(params);
		        }, false, 2000);

		        rpc_->registerMethod("market.stats", [this](const std::string& params) {
		            return handleRpcMarketStats(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.remote.list", [this](const std::string& params) {
		            return handleRpcModelRemoteList(params);
		        }, false, 2000);

		        rpc_->registerMethod("model.remote.rent", [this](const std::string& params) {
		            return handleRpcModelRemoteRent(params);
		        }, false, 5000);

		        rpc_->registerMethod("model.remote.end", [this](const std::string& params) {
		            return handleRpcModelRemoteEnd(params);
		        }, false, 2000);

		        rpc_->registerMethod("ai.complete", [this](const std::string& params) {
		            return handleRpcAiComplete(params);
		        }, false, 200);

		        rpc_->registerMethod("ai.stop", [this](const std::string& params) {
		            return handleRpcAiStop(params);
		        }, false, 500);

		        rpc_->registerMethod("poe.validators", [this](const std::string& params) {
		            return handleRpcPoeValidators(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.manifest.submit", [this](const std::string& params) {
		            return handleRpcUpdateManifestSubmit(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.manifest.fetch", [this](const std::string& params) {
		            return handleRpcUpdateManifestFetch(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.manifest.list", [this](const std::string& params) {
		            return handleRpcUpdateManifestList(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.manifest.approve", [this](const std::string& params) {
		            return handleRpcUpdateManifestApprove(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.manifest.approvals", [this](const std::string& params) {
		            return handleRpcUpdateManifestApprovals(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.install.state", [this](const std::string& params) {
		            return handleRpcUpdateInstallState(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.install.prepare", [this](const std::string& params) {
		            return handleRpcUpdateInstallPrepare(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.install.advance", [this](const std::string& params) {
		            return handleRpcUpdateInstallAdvance(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.install.commit", [this](const std::string& params) {
		            return handleRpcUpdateInstallCommit(params);
		        }, false, 2000);

		        rpc_->registerMethod("update.install.rollback", [this](const std::string& params) {
		            return handleRpcUpdateInstallRollback(params);
		        }, false, 2000);

		        rpc_->registerMethod("implant.update.state", [this](const std::string& params) {
		            return handleRpcImplantUpdateState(params);
		        }, false, 2000);

		        rpc_->registerMethod("implant.update.prepare", [this](const std::string& params) {
		            return handleRpcImplantUpdatePrepare(params);
		        }, false, 2000);

		        rpc_->registerMethod("implant.update.advance", [this](const std::string& params) {
		            return handleRpcImplantUpdateAdvance(params);
		        }, false, 2000);

		        rpc_->registerMethod("implant.update.commit", [this](const std::string& params) {
		            return handleRpcImplantUpdateCommit(params);
		        }, false, 2000);

		        rpc_->registerMethod("implant.update.rollback", [this](const std::string& params) {
		            return handleRpcImplantUpdateRollback(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.status", [this](const std::string& params) {
		            return handleRpcNaanStatus(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.observatory.artifacts", [this](const std::string& params) {
		            return handleRpcNaanObservatoryArtifacts(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.observatory.artifact.get", [this](const std::string& params) {
		            return handleRpcNaanObservatoryArtifactGet(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.observatory.drafts", [this](const std::string& params) {
		            return handleRpcNaanObservatoryDrafts(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.observatory.draft.get", [this](const std::string& params) {
		            return handleRpcNaanObservatoryDraftGet(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.pipeline.dryrun", [this](const std::string& params) {
		            return handleRpcNaanPipelineDryRun(params);
		        }, false, 2000);

		        rpc_->registerMethod("naan.pipeline.drain", [this](const std::string& params) {
		            return handleRpcNaanPipelineDrain(params);
		        }, false, 2000);

	        rpc_->registerMethod("node.status", [this](const std::string& params) {
	            return handleRpcNodeStatus(params);
	        }, false, 5000);

	        rpc_->registerMethod("node.peers", [this](const std::string& params) {
	            return handleRpcNodePeers(params);
	        }, false, 5000);

	        rpc_->registerMethod("node.logs", [this](const std::string& params) {
	            return handleRpcNodeLogs(params);
	        }, false, 1000);

            rpc_->registerMethod("node.seeds", [this](const std::string& params) {
                return handleRpcNodeSeeds(params);
            }, false, 2000);

            rpc_->registerMethod("node.discovery.stats", [this](const std::string& params) {
                return handleRpcNodeDiscoveryStats(params);
            }, false, 2000);

            rpc_->registerMethod("node.tor.control", [this](const std::string& params) {
                return handleRpcNodeTorControl(params);
            }, false, 120000);
	        
	        utils::Logger::info("RPC server started on port " + std::to_string(config_.rpcPort));
	        return true;
	    }
    
    bool initMempool() {
        if (transfer_) {
            transfer_->setMaxMempoolSize(static_cast<size_t>(config_.maxMempool) * 1024);
        }
        utils::Logger::info("Mempool initialized: " + std::to_string(config_.maxMempool) + " MB");
        return true;
    }

    int runWithTUI() {
#if !SYNAPSE_BUILD_TUI
        std::cerr << "TUI support was disabled at build time; reconfigure with -DBUILD_TUI=ON.\n";
        return runDaemon();
#else
        // Check terminal capabilities first
        const char* term = std::getenv("TERM");
        bool stdin_tty = isatty(STDIN_FILENO);
        bool stdout_tty = isatty(STDOUT_FILENO);
        
        if (!term) {
            std::cerr << "TERM environment variable not set. Try: export TERM=xterm-256color\n";
            return 1;
        }
        
        if (!stdin_tty || !stdout_tty) {
            std::cerr << "Not running in a proper terminal. TUI requires an interactive terminal.\n";
            std::cerr << "Running in daemon mode instead...\n";
            return runDaemon();
        }
        
        tui::TUI ui;
        if (!ui.init()) {
            utils::Logger::error("Failed to initialize TUI");
            std::cerr << "Failed to initialize TUI (ncurses). Possible issues:\n";
            std::cerr << "1. Terminal too small (minimum 80x24)\n";
            std::cerr << "2. TERM variable incorrect: " << term << "\n";
            std::cerr << "3. Not running in interactive terminal\n";
            std::cerr << "Falling back to daemon mode...\n";
            return runDaemon();
        }

        utils::Logger::enableConsole(false);
        
        if (network_ && network_->getPort() != 0) {
            ui.setNetworkPort(network_->getPort());
            ui.setNetworkOnline(true);
        } else {
            ui.setNetworkOnline(false);
        }
        
        startThreads();

        ui.onCommand([this, &ui](const std::string& cmd) {
            std::istringstream iss(cmd);
            std::string op;
            iss >> op;
            if (op == "send") {
                std::string to;
                std::string amountStr;
                iss >> to >> amountStr;
                if (to.empty() || amountStr.empty()) {
                    ui.showError("Invalid send arguments");
                    return;
                }
                if (!transfer_ || !keys_ || !keys_->isValid() || address_.empty()) {
                    ui.showError("Wallet/transfer not ready");
                    return;
                }
                uint64_t amount = 0;
                try {
                    amount = this->parseNgtAtomic(amountStr);
                } catch (const std::exception& e) {
                    ui.showError(e.what());
                    return;
                }
                if (amount == 0) {
                    ui.showError("Amount too small");
                    return;
                }
                if (!transfer_->hasSufficientBalance(address_, amount)) {
                    ui.showError("Insufficient balance");
                    return;
                }

                uint64_t fee = transfer_->estimateFee(0);
                core::Transaction tx;
                for (int i = 0; i < 5; ++i) {
                    tx = transfer_->createTransaction(address_, to, amount, fee);
                    uint64_t requiredFee = transfer_->estimateFee(tx.serialize().size());
                    if (requiredFee == fee) break;
                    fee = requiredFee;
                }

                uint64_t bal = transfer_->getBalance(address_);
                if (UINT64_MAX - amount < fee) {
                    ui.showError("Amount too large");
                    return;
                }
                uint64_t needed = amount + fee;
                if (bal < needed) {
                    ui.showError("Insufficient balance (including fee)");
                    return;
                }

                crypto::PrivateKey pk{};
                auto pkv = keys_->getPrivateKey();
                if (pkv.size() < pk.size()) {
                    ui.showError("Invalid private key");
                    return;
                }
                std::memcpy(pk.data(), pkv.data(), pk.size());
                if (!transfer_->signTransaction(tx, pk)) {
                    ui.showError("Failed to sign transaction");
                    return;
                }
                if (!transfer_->submitTransaction(tx)) {
                    ui.showError("Failed to submit transaction");
                    return;
                }
                ui.showMessage("Transaction submitted", tui::Color::GREEN);
	            } else if (op == "poe_submit") {
	                std::string q64;
	                std::string a64;
	                std::string s64;
                iss >> q64 >> a64 >> s64;
                if (q64.empty() || a64.empty()) {
                    ui.showError("Invalid knowledge arguments");
                    return;
                }
                if (!poeV1_ || !keys_ || !keys_->isValid()) {
                    ui.showError("PoE/wallet not ready");
                    return;
                }

                auto fromB64 = [](const std::string& s) -> std::string {
                    std::vector<uint8_t> in(s.begin(), s.end());
                    auto out = crypto::base64Decode(in);
                    return std::string(out.begin(), out.end());
                };

                std::string question = fromB64(q64);
                std::string answer = fromB64(a64);
                std::string source = s64.empty() ? "" : fromB64(s64);

                if (question.empty() || answer.empty()) {
                    ui.showError("Question/answer empty");
                    return;
                }

                crypto::PrivateKey pk{};
                auto pkv = keys_->getPrivateKey();
                if (pkv.size() < pk.size()) {
                    ui.showError("Invalid private key");
                    return;
                }
                std::memcpy(pk.data(), pkv.data(), pk.size());

                std::string body = answer;
                if (!source.empty()) {
                    body += "\nsource: " + source;
                }

                updatePoeValidatorsFromStake();
                ui.updateOperationStatus("Submitting knowledge", "IN_PROGRESS", "");
                auto submitRes = poeV1_->submit(core::poe_v1::ContentType::QA, question, body, {}, pk, true);
                if (!submitRes.ok) {
                    ui.updateOperationStatus("Submitting knowledge", "ERROR", submitRes.error);
                    ui.showError("PoE submit failed: " + submitRes.error);
                    return;
                }

                broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
                for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
                    broadcastInv(synapse::InvType::POE_VOTE, v.payloadHash());
                }

                auto entry = poeV1_->getEntry(submitRes.submitId);
                uint64_t expectedAtoms = entry ? poeV1_->calculateAcceptanceReward(*entry) : 0;
                uint32_t votes = static_cast<uint32_t>(poeV1_->getVotesForSubmit(submitRes.submitId).size());
                uint32_t requiredVotes = poeV1_->getConfig().validatorsM;

                maybeCreditAcceptanceReward(submitRes.submitId);
                bool paid = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(submitRes.submitId)) : false;

                std::ostringstream oss;
                std::string sidShort = crypto::toHex(submitRes.submitId).substr(0, 8);
                if (poeV1_->isFinalized(submitRes.submitId)) {
                    ui.updateOperationStatus("Knowledge finalized", "SUCCESS", sidShort);
                    if (paid && expectedAtoms > 0) {
                        double rewardAmount = static_cast<double>(expectedAtoms) / 100000000.0;
                        std::ostringstream details;
                        details << "Accepted by " << requiredVotes << "/" << requiredVotes << " validators";
                        ui.showRewardNotification(rewardAmount, "knowledge contribution", sidShort, details.str());
                    } else {
                        oss << "Knowledge finalized (" << sidShort << "): reward pending";
                        ui.showMessage(oss.str(), tui::Color::GREEN);
                        ui.appendChatMessage("assistant", oss.str());
                    }
                } else {
                    std::ostringstream details;
                    details << votes << "/" << requiredVotes << " votes";
                    ui.updateOperationStatus("Validating entry", "IN_PROGRESS", details.str());
                    oss << "Knowledge submitted (" << sidShort << "): pending " << votes << "/" << requiredVotes;
                    if (expectedAtoms > 0) {
                        oss << " (+" << std::fixed << std::setprecision(8)
                            << (static_cast<double>(expectedAtoms) / 100000000.0) << " NGT on finalize)";
                    }
                    std::string msg = oss.str();
	                ui.showMessage(msg, tui::Color::GREEN);
	                ui.appendChatMessage("assistant", msg);
                }
		            } else if (op == "poe_submit_code") {
		                std::string t64;
		                std::string p64;
		                std::string c64;
		                iss >> t64 >> p64 >> c64;
		                if (t64.empty() || p64.empty()) {
		                    ui.showError("Invalid code arguments");
		                    return;
		                }
		                if (!poeV1_ || !keys_ || !keys_->isValid()) {
		                    ui.showError("PoE/wallet not ready");
		                    return;
		                }

		                auto fromB64 = [](const std::string& s) -> std::string {
		                    std::vector<uint8_t> in(s.begin(), s.end());
		                    auto out = crypto::base64Decode(in);
		                    return std::string(out.begin(), out.end());
		                };

		                std::string title = fromB64(t64);
		                std::string patch = fromB64(p64);
		                std::string citesRaw = c64.empty() ? "" : fromB64(c64);

		                if (title.empty() || patch.empty()) {
		                    ui.showError("Title/patch empty");
		                    return;
		                }

		                std::vector<crypto::Hash256> citations;
		                if (!citesRaw.empty()) {
		                    bool citationsOk = true;
		                    std::string raw = citesRaw;
		                    for (char& c : raw) if (c == ';') c = ',';
		                    std::string cur;
		                    auto flush = [&]() {
		                        std::string t = cur;
		                        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
		                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
		                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
		                        if (t.empty()) return;
		                        try {
		                            citations.push_back(parseHash256Hex(t));
		                        } catch (...) {
		                            citationsOk = false;
		                        }
		                    };
		                    for (size_t i = 0; i <= raw.size(); ++i) {
		                        if (i == raw.size() || raw[i] == ',') {
		                            if (!cur.empty()) flush();
		                            cur.clear();
		                        } else {
		                            cur.push_back(raw[i]);
		                        }
		                    }
		                    if (!citationsOk) {
		                        ui.showError("Invalid citations");
		                        return;
		                    }
		                }

		                crypto::PrivateKey pk{};
		                auto pkv = keys_->getPrivateKey();
		                if (pkv.size() < pk.size()) {
		                    ui.showError("Invalid private key");
		                    return;
		                }
		                std::memcpy(pk.data(), pkv.data(), pk.size());

		                updatePoeValidatorsFromStake();
		                core::PoeSubmitResult submitRes;
		                ui.updateOperationStatus("Submitting code", "IN_PROGRESS", "");
		                try {
		                    submitRes = poeV1_->submit(core::poe_v1::ContentType::CODE, title, patch, citations, pk, true);
		                } catch (const std::exception& e) {
		                    ui.updateOperationStatus("Submitting code", "ERROR", e.what());
		                    ui.showError(e.what());
		                    return;
		                }
		                if (!submitRes.ok) {
		                    ui.updateOperationStatus("Submitting code", "ERROR", submitRes.error);
		                    ui.showError("PoE submit failed: " + submitRes.error);
		                    return;
		                }

		                broadcastInv(synapse::InvType::POE_ENTRY, submitRes.submitId);
		                for (const auto& v : poeV1_->getVotesForSubmit(submitRes.submitId)) {
		                    broadcastInv(synapse::InvType::POE_VOTE, v.payloadHash());
		                }

		                auto entry = poeV1_->getEntry(submitRes.submitId);
		                uint64_t expectedAtoms = entry ? poeV1_->calculateAcceptanceReward(*entry) : 0;
		                uint32_t votes = static_cast<uint32_t>(poeV1_->getVotesForSubmit(submitRes.submitId).size());
		                uint32_t requiredVotes = poeV1_->getConfig().validatorsM;

		                maybeCreditAcceptanceReward(submitRes.submitId);
		                bool paid = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(submitRes.submitId)) : false;

		                std::ostringstream oss;
		                std::string sidShort = crypto::toHex(submitRes.submitId).substr(0, 8);
		                if (poeV1_->isFinalized(submitRes.submitId)) {
		                    ui.updateOperationStatus("Code finalized", "SUCCESS", sidShort);
		                    if (paid && expectedAtoms > 0) {
		                        double rewardAmount = static_cast<double>(expectedAtoms) / 100000000.0;
		                        std::ostringstream details;
		                        details << "Accepted by " << requiredVotes << "/" << requiredVotes << " validators";
		                        ui.showRewardNotification(rewardAmount, "code contribution", sidShort, details.str());
		                    } else {
		                        oss << "Code finalized (" << sidShort << "): reward pending";
		                        ui.showMessage(oss.str(), tui::Color::GREEN);
		                        ui.appendChatMessage("assistant", oss.str());
		                    }
		                } else {
		                    std::ostringstream details;
		                    details << votes << "/" << requiredVotes << " votes";
		                    ui.updateOperationStatus("Validating entry", "IN_PROGRESS", details.str());
		                    oss << "Code submitted (" << sidShort << "): pending " << votes << "/" << requiredVotes;
		                    if (expectedAtoms > 0) {
		                        oss << " (+" << std::fixed << std::setprecision(8)
		                            << (static_cast<double>(expectedAtoms) / 100000000.0) << " NGT on finalize)";
		                    }
		                    std::string msg = oss.str();
		                    ui.showMessage(msg, tui::Color::GREEN);
		                    ui.appendChatMessage("assistant", msg);
		                }
		            } else if (op == "poe_epoch") {
		                if (!poeV1_ || !transfer_) {
		                    ui.showError("PoE/transfer not ready");
		                    return;
	                }

                int64_t cfgBudget = utils::Config::instance().getInt64(
                    "poe.epoch_budget",
                    config_.dev ? 100000000LL : 1000000000LL);
                uint64_t budget = cfgBudget > 0 ? static_cast<uint64_t>(cfgBudget) : 0ULL;
                uint32_t iters = static_cast<uint32_t>(std::max(1, utils::Config::instance().getInt(
                    "poe.epoch_iterations",
                    config_.dev ? 10 : 20)));

                auto rewardIdForEpoch = [](uint64_t epochId, const crypto::Hash256& contentId) -> crypto::Hash256 {
                    std::vector<uint8_t> buf;
                    const std::string tag = "poe_v1_epoch";
                    buf.insert(buf.end(), tag.begin(), tag.end());
                    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((epochId >> (8 * i)) & 0xFF));
                    buf.insert(buf.end(), contentId.begin(), contentId.end());
                    return crypto::sha256(buf.data(), buf.size());
                };

                auto addressFromPubKey = [](const crypto::PublicKey& pubKey) -> std::string {
                    std::string hex = crypto::toHex(pubKey);
                    if (hex.size() < 52) return {};
                    return "ngt1" + hex.substr(0, 52);
                };

	                auto epochRes = poeV1_->runEpoch(budget, iters);
	                if (!epochRes.ok) {
	                    ui.showError("PoE epoch failed: " + epochRes.error);
	                    return;
	                }

	                {
	                    crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    knownPoeEpochs_.insert(crypto::toHex(hid));
	                }
	                broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

	                uint64_t mintedTotal = 0;
	                uint64_t mintedMine = 0;
	                uint64_t mintedCount = 0;
	                for (const auto& a : epochRes.allocations) {
                    std::string addr = addressFromPubKey(a.authorPubKey);
                    if (addr.empty()) continue;
                    crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, a.contentId);
                    if (transfer_->creditRewardDeterministic(addr, rid, a.amount)) {
                        mintedTotal += a.amount;
                        mintedCount += 1;
                        if (!address_.empty() && addr == address_) mintedMine += a.amount;
                    }
                }

                std::ostringstream oss;
                oss << "Epoch #" << epochRes.epochId << " distributed " << std::fixed << std::setprecision(8)
                    << (static_cast<double>(mintedTotal) / 100000000.0) << " NGT";
                if (mintedMine > 0) {
                    oss << " (you: " << std::fixed << std::setprecision(8)
                        << (static_cast<double>(mintedMine) / 100000000.0) << " NGT)";
                }
                oss << " to " << mintedCount << " entries";

                std::string msg = oss.str();
                ui.showMessage(msg, tui::Color::GREEN);
                ui.appendChatMessage("assistant", msg);
            }
        });
        
        std::thread updateThread([this, &ui]() {
            std::unordered_set<std::string> notifiedKnowledgePaid;
            while (running_) {
                if (keys_ && !keys_->isValid()) {
                    std::string walletPath = config_.dataDir + "/wallet.dat";
                    if (std::filesystem::exists(walletPath)) {
                        if (keys_->load(walletPath, "")) {
                            address_ = keys_->getAddress();
                            updateSignerFromKeys();
                            if (poeV1_) {
                                auto current = poeV1_->getStaticValidators();
                                if (current.empty()) {
                                    auto pubV = keys_->getPublicKey();
                                    if (pubV.size() >= crypto::PUBLIC_KEY_SIZE) {
                                        crypto::PublicKey pk{};
                                        std::memcpy(pk.data(), pubV.data(), pk.size());
                                        poeV1_->setStaticValidators({pk});
                                    }
                                }
                            }
                        }
                    }
                }
                tui::NetworkInfo netInfo;
                netInfo.totalNodes = network_ ? network_->peerCount() : 0;
                netInfo.knowledgeEntries = poeV1_ ? poeV1_->totalEntries() : (knowledge_ ? knowledge_->totalEntries() : 0);
                netInfo.knowledgeFinalized = poeV1_ ? poeV1_->totalFinalized() : 0;
                netInfo.knowledgePending =
                    (netInfo.knowledgeEntries > netInfo.knowledgeFinalized) ? (netInfo.knowledgeEntries - netInfo.knowledgeFinalized) : 0;
                
                // Get real network size estimate from Discovery
                if (discovery_) {
                    auto discStats = discovery_->getStats();
                    netInfo.networkSize = static_cast<double>(discStats.networkSize);
                    netInfo.knownPeers = discStats.knownPeersCount;
                    netInfo.connectedPeers = discStats.connectedPeers;
                    netInfo.dnsQueries = discStats.dnsQueries;
                    netInfo.peerExchanges = discStats.peerExchanges;
                    netInfo.lastPeerRefresh = discStats.lastRefreshTime;
                    netInfo.lastAnnounce = discStats.lastAnnounceTime;
                    netInfo.bootstrapNodes = discovery_->getBootstrapNodes().size();
                    netInfo.dnsSeeds = discovery_->getDnsSeeds().size();
                } else {
                    netInfo.networkSize = 0.0;
                    netInfo.knownPeers = 0;
                    netInfo.connectedPeers = 0;
                    netInfo.dnsQueries = 0;
                    netInfo.peerExchanges = 0;
                    netInfo.lastPeerRefresh = 0;
                    netInfo.lastAnnounce = 0;
                    netInfo.bootstrapNodes = 0;
                    netInfo.dnsSeeds = 0;
                }
                
                netInfo.yourStorage = 0.0;
                netInfo.syncProgress = syncProgress_;
                netInfo.synced = (syncProgress_ >= 1.0);
                ui.updateNetworkInfo(netInfo);
                
                if (network_) {
                    ui.setPeerCount(network_->peerCount());
                    
                    std::vector<tui::NodeInfo> peers;
                    auto networkPeers = network_->getPeers();
                    for (const auto& peer : networkPeers) {
                        tui::NodeInfo nodeInfo;
                        nodeInfo.nodeId = peer.id;
                        nodeInfo.id = peer.id.substr(0, 16) + "...";
                        nodeInfo.address = peer.address;
                        nodeInfo.location = "Unknown";
                        nodeInfo.port = peer.port;
                        nodeInfo.latency = 50;
                        nodeInfo.ping = 50;
                        nodeInfo.version = std::to_string(peer.version);
                        nodeInfo.isInbound = !peer.isOutbound;
                        peers.push_back(nodeInfo);
                    }
                    ui.updatePeers(peers);
                }
                
                tui::AIModelInfo modelInfo;
                if (modelLoader_) {
                    auto models = modelLoader_->listModels(config_.dataDir + "/models");
                    if (!models.empty()) {
                        modelInfo.name = models[0].name;
                        modelInfo.status = "ACTIVE";
                        modelInfo.progress = 1.0;
                    } else {
                        modelInfo.name = "";
                        modelInfo.status = "NOT LOADED";
                        modelInfo.progress = 0.0;
                    }
                } else {
                    modelInfo.name = "";
                    modelInfo.status = "NOT LOADED";
                    modelInfo.progress = 0.0;
                }
                modelInfo.mode = "PRIVATE";
                modelInfo.slotsUsed = 0;
                modelInfo.slotsMax = 1;
                modelInfo.uptime = 0.0;
                modelInfo.earningsToday = 0.0;
                modelInfo.earningsWeek = 0.0;
                modelInfo.earningsTotal = 0.0;
                ui.updateModelInfo(modelInfo);
                
                tui::WalletInfo walletInfo;
                if (keys_ && keys_->isValid()) {
                    walletInfo.address = address_;
                    uint64_t bal = 0;
                    uint64_t pend = 0;
                if (transfer_ && !address_.empty()) {
                    bal = transfer_->getBalance(address_);
                    pend = transfer_->getPendingBalance(address_);
                }
                    walletInfo.balance = static_cast<double>(bal) / 100000000.0;
                    walletInfo.pending = static_cast<double>(pend) / 100000000.0;
                    walletInfo.staked = 0.0;
                    walletInfo.totalEarned = 0.0;
                } else {
                    walletInfo.address = "";
                    walletInfo.balance = 0.0;
                    walletInfo.pending = 0.0;
                    walletInfo.staked = 0.0;
                    walletInfo.totalEarned = 0.0;
                }
                ui.updateWalletInfo(walletInfo);

                std::vector<tui::KnowledgeEntrySummary> summaries;
                if (poeV1_) {
                    struct Tmp {
                        tui::KnowledgeEntrySummary s;
                        uint64_t ts = 0;
                        bool mine = false;
                    };
                    std::vector<Tmp> tmp;
                    auto ids = poeV1_->listEntryIds(50);
                    tmp.reserve(ids.size());
                    core::PoeV1Config cfg = poeV1_->getConfig();
	                    for (const auto& sid : ids) {
	                        auto entry = poeV1_->getEntry(sid);
	                        if (!entry) continue;
	                        Tmp t;
	                        t.ts = entry->timestamp;
	                        t.s.submitId = crypto::toHex(sid);
	                        t.s.title = entry->title;
	                        t.s.contentType = static_cast<uint8_t>(entry->contentType);
	                        t.s.finalized = poeV1_->isFinalized(sid);
	                        t.s.votes = static_cast<uint32_t>(poeV1_->getVotesForSubmit(sid).size());
	                        t.s.requiredVotes = cfg.validatorsM;
	                        uint64_t atoms = poeV1_->calculateAcceptanceReward(*entry);
	                        t.s.acceptanceReward = atomsToNgt(atoms);
                        t.s.acceptanceRewardCredited = transfer_ ? transfer_->hasTransaction(rewardIdForAcceptance(sid)) : false;
                        t.mine = (!address_.empty() && addressFromPubKey(entry->authorPubKey) == address_);
                        tmp.push_back(std::move(t));
                    }
                    std::sort(tmp.begin(), tmp.end(), [](const Tmp& a, const Tmp& b) { return a.ts > b.ts; });
                    if (tmp.size() > 20) tmp.resize(20);
                    summaries.reserve(tmp.size());
                    for (auto& t : tmp) {
                        summaries.push_back(t.s);
                    }

	                    for (const auto& t : tmp) {
	                        if (!t.mine) continue;
	                        if (!t.s.finalized) continue;
	                        if (!t.s.acceptanceRewardCredited) continue;
	                        if (!notifiedKnowledgePaid.insert(t.s.submitId).second) continue;
	                        std::string sidShort = t.s.submitId.size() > 8 ? t.s.submitId.substr(0, 8) : t.s.submitId;
	                        std::ostringstream msg;
	                        std::string kind = (t.s.contentType == static_cast<uint8_t>(core::poe_v1::ContentType::CODE))
	                            ? "Code"
	                            : "Knowledge";
	                        msg << kind << " reward (" << sidShort << "): +" << std::fixed << std::setprecision(8)
	                            << t.s.acceptanceReward << " NGT";
	                        ui.appendChatMessage("assistant", msg.str());
	                    }
	                }
                ui.updateKnowledgeEntries(summaries);

                tui::StatusInfo status{};
                status.blockHeight = ledger_ ? ledger_->height() : 0;
                status.peerCount = network_ ? network_->peerCount() : 0;
                status.knowledgeCount = poeV1_ ? poeV1_->totalEntries() : (knowledge_ ? knowledge_->totalEntries() : 0);
                status.balance = static_cast<uint64_t>(walletInfo.balance);
                status.walletAddress = walletInfo.address;
                status.modelName = modelInfo.name;
                status.modelStatus = modelInfo.status;
                status.syncProgress = syncProgress_;
                ui.updateStatus(status);

                tui::AttachedAgentStatusInfo attachedInfo;
                {
                    attachedInfo.available = true;
                    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
                    const auto score = agentScore_.snapshot();
                    const auto runtimeState = naanRuntimeInitialized_.load()
                        ? currentNaanFailoverState(now)
                        : core::AgentRuntimeFailoverState::RECOVERY;
                    const auto crashState = naanRuntimeSupervisor_.crashState();
                    const auto schedulerState = naanTaskScheduler_.snapshot();
                    const auto adaptiveSchedule = agentAdaptiveScheduler_.schedule(score.throttled, score.quarantined);

                    attachedInfo.runtimeState = core::failoverStateToString(runtimeState);
                    attachedInfo.runtimeInitialized = naanRuntimeInitialized_.load();
                    attachedInfo.schedulerState = core::schedulingStateToString(adaptiveSchedule.state);
                    attachedInfo.runtimeCrashCount = crashState.totalCrashes;
                    attachedInfo.runtimeConsecutiveCrashes = crashState.consecutiveCrashes;
                    attachedInfo.schedulerTick = schedulerState.tick;
                    attachedInfo.schedulerEpochIndex = schedulerState.epochIndex;
                    attachedInfo.schedulerBudgetCpu = schedulerState.remaining.cpu;
                    attachedInfo.schedulerBudgetRam = schedulerState.remaining.ram;
                    attachedInfo.schedulerBudgetNetwork = schedulerState.remaining.network;
                    attachedInfo.agentScore = score.score;
                    attachedInfo.agentScoreBand = core::agentScoreBandToString(score.band);
                    attachedInfo.throttled = score.throttled;
                    attachedInfo.quarantined = score.quarantined;
                    attachedInfo.reviewOnly = score.reviewOnly;
                    attachedInfo.localDraftOnly = score.localDraftOnly;
                    attachedInfo.batchLimit = score.batchLimit;
                    attachedInfo.draftQueueSize = agentDraftQueue_.size();
                    attachedInfo.queuedDrafts = agentDraftQueue_.listByStatus(core::DraftStatus::QUEUED, 1000000).size();
                    attachedInfo.reviewDrafts = agentDraftQueue_.listByStatus(core::DraftStatus::REVIEW_REQUIRED, 1000000).size();
                    attachedInfo.approvedDrafts = agentDraftQueue_.listByStatus(core::DraftStatus::APPROVED, 1000000).size();
                    attachedInfo.rejectedDrafts = agentDraftQueue_.listByStatus(core::DraftStatus::REJECTED, 1000000).size();
                    attachedInfo.submittedDrafts = agentDraftQueue_.listByStatus(core::DraftStatus::SUBMITTED, 1000000).size();
                    attachedInfo.pipelineRuns = naanPipelineRuns_.load();
                    attachedInfo.pipelineApproved = naanPipelineApproved_.load();
                    attachedInfo.pipelineRejected = naanPipelineRejected_.load();
                    attachedInfo.pipelineSubmitted = naanPipelineSubmitted_.load();
                    attachedInfo.lastActionAt = naanLastActionTs_.load();
                    attachedInfo.lastReviewAt = naanLastReviewTs_.load();
                    attachedInfo.lastDraftAt = naanLastDraftTs_.load();
                    attachedInfo.lastHeartbeatAt = naanLastHeartbeatTs_.load();
                    attachedInfo.taskRunsResearch = naanTaskResearchRuns_.load();
                    attachedInfo.taskRunsVerify = naanTaskVerifyRuns_.load();
                    attachedInfo.taskRunsReview = naanTaskReviewRuns_.load();
                    attachedInfo.taskRunsDraft = naanTaskDraftRuns_.load();
                    attachedInfo.taskRunsSubmit = naanTaskSubmitRuns_.load();
                    attachedInfo.tickCount = naanTickCount_.load();

                    attachedInfo.torRequired = agentTorRequired_.load();
                    bool torReachable = probeTorSocks();
                    if (!torReachable && attachedInfo.torRequired && !agentTorManaged_.load()) {
                        bool started = maybeStartManagedTorRuntimeWithBackoff(true, "attached_status");
                        if (started) {
                            agentTorManaged_.store(true);
                            torReachable = probeTorSocks();
                        }
                    }
                    if (torReachable) {
                        resetManagedTorRestartBackoffState();
                    }
                    agentTorReachable_.store(torReachable);
                    refreshTorWebReadiness(torReachable, false);
                    core::TorRoutePolicyInput routeIn;
                    routeIn.torRequired = attachedInfo.torRequired;
                    routeIn.torReachable = torReachable;
                    routeIn.allowClearnetFallback = agentAllowClearnetFallback_.load();
                    routeIn.allowP2PFallback = agentAllowP2PFallback_.load();
                    const auto route = core::evaluateTorRoutePolicy(routeIn);
                    agentTorDegraded_.store(route.torDegraded);
                    updateAndLogTorReadinessState(attachedInfo.torRequired, torReachable, agentTorWebReady_.load(), route.torDegraded);
                    attachedInfo.torReachable = torReachable;
                    attachedInfo.torReadyForWeb = agentTorWebReady_.load();
                    attachedInfo.torReadyForOnion = agentTorOnionReady_.load();
                    attachedInfo.torControlReachable = probeTorControl();
                    attachedInfo.torControlPort = configuredTorControlPort();
                    attachedInfo.torManaged = agentTorManaged_.load();
                    attachedInfo.torDegraded = route.torDegraded;
                    attachedInfo.torBootstrapPercent = agentTorBootstrapPercent_.load();
                    attachedInfo.torSocksHost = configuredTorSocksHost();
                    attachedInfo.torSocksPort = configuredTorSocksPort();
                    attachedInfo.torConflictHint9050 = likelyTor9050vs9150ConflictHint(torReachable);
                    attachedInfo.clearnetFallbackAllowed = agentAllowClearnetFallback_.load();
                    attachedInfo.p2pFallbackAllowed = agentAllowP2PFallback_.load();
                    attachedInfo.routeMode = route.routeMode;
                    attachedInfo.torRuntimeMode = configuredTorRuntimeMode();

                    attachedInfo.dataDir = config_.dataDir;
                    attachedInfo.configPath = config_.configPath.empty()
                        ? (config_.dataDir + "/synapsenet.conf")
                        : config_.configPath;
                    attachedInfo.webConfigPath = config_.dataDir + "/web_search.conf";
                    attachedInfo.redactionCount = naanRedactionCount_.load();
                    attachedInfo.policyHash = securityPolicyHashes().first;

                    attachedInfo.p2pPort = config_.port;
                    attachedInfo.p2pSyncProgress = syncProgress_;
                    attachedInfo.p2pConnected = network_ ? network_->peerCount() : 0;
                    attachedInfo.p2pInbound = 0;
                    attachedInfo.p2pOutbound = 0;
	                    if (network_) {
                            auto netStats = network_->getStats();
                            attachedInfo.networkPeerPressurePercent = config_.maxPeers == 0
                                ? 0
                                : (netStats.totalPeers * 100ULL / config_.maxPeers);
                            attachedInfo.networkInboundPressurePercent = config_.maxInbound == 0
                                ? 0
                                : (netStats.inboundPeers * 100ULL / config_.maxInbound);
                            attachedInfo.networkOutboundPressurePercent = config_.maxOutbound == 0
                                ? 0
                                : (netStats.outboundPeers * 100ULL / config_.maxOutbound);
                            attachedInfo.networkOverloadMode = netStats.overloadMode;
                            attachedInfo.networkBufferedRxBytes = netStats.bufferedRxBytes;
                            attachedInfo.networkRejectedConnections = netStats.rejectedConnections;
                            attachedInfo.networkEvictedPeers = netStats.evictedPeers;
                            attachedInfo.networkTempBans = netStats.tempBans;
                            attachedInfo.networkMalformedMessages = netStats.malformedMessages;
                            attachedInfo.networkRateLimitedEvents = netStats.rateLimitedEvents;
                            attachedInfo.networkOverloadTransitions = netStats.overloadTransitions;
                            attachedInfo.networkInvBackpressureDrops = invBackpressureDrops_.load();
                            attachedInfo.networkGetDataBackpressureDrops = getDataBackpressureDrops_.load();
                            attachedInfo.networkGossipSuppressed = gossipSuppressed_.load();
                            attachedInfo.networkGossipSubsetRouted = gossipSubsetRouted_.load();
	                        for (const auto& peer : network_->getPeers()) {
	                            if (peer.state != network::PeerState::CONNECTED) continue;
	                            if (!peer.isOutbound) attachedInfo.p2pInbound += 1;
	                            else attachedInfo.p2pOutbound += 1;
	                        }
	                    }

                    attachedInfo.ledgerHeight = ledger_ ? ledger_->height() : 0;
                    attachedInfo.networkConsensusLag = networkHeight_.load() > attachedInfo.ledgerHeight
                        ? (networkHeight_.load() - attachedInfo.ledgerHeight)
                        : 0;
                    if (ledger_) {
                        auto tip = ledger_->tip();
                        attachedInfo.ledgerTipHash = crypto::toHex(tip.hash);
                        attachedInfo.ledgerLastBlockTime = tip.timestamp;
                    }
                    attachedInfo.miningActive = miningActive_.load();
                    attachedInfo.miningHashAttemptsTotal = miningHashAttemptsTotal_.load();
                    attachedInfo.miningHashAttemptsLast = miningHashAttemptsLast_.load();
                    attachedInfo.miningLastSolvedAt = miningLastSolvedAt_.load();
                    attachedInfo.miningWorkTarget = "leading_zero_bits>=" + std::to_string(miningWorkTargetBits_.load());
                    {
                        std::lock_guard<std::mutex> lock(miningStateMtx_);
                        attachedInfo.miningCandidateHash = crypto::toHex(miningCandidateHash_);
                    }
                    attachedInfo.onionServiceActive = isOnionServiceActive();
                    core::TorOnionServiceStateInput attachedOnionSvc{
                        attachedInfo.torRequired,
                        attachedInfo.torReachable,
                        attachedInfo.torReadyForWeb,
                        attachedInfo.torDegraded,
                        config_.privacyMode,
                        attachedInfo.torControlReachable,
                        attachedInfo.onionServiceActive};
                    attachedInfo.torReadyForOnionService = core::evaluateTorReadyForOnionService(attachedOnionSvc);
                    attachedInfo.onionServiceState = core::evaluateTorOnionServiceState(attachedOnionSvc);

                    auto storageStats = naanAuditLog_.stats();
                    attachedInfo.storageAuditSegments = storageStats.segmentCount;
                    attachedInfo.storageAuditRetainedEvents = storageStats.retainedEvents;
                    attachedInfo.storageAuditRecoveredLines = naanStorageRecoveredLines_.load();
                    attachedInfo.storageAuditDroppedSegments = naanStorageDroppedSegments_.load();
                    attachedInfo.storageIndexRecoveryRuns = naanIndexRecoveryRuns_.load();
                    attachedInfo.storageIndexRecoveryLastAt = naanIndexRecoveryLastAt_.load();
                    attachedInfo.storageConsistencyChecks = naanConsistencyChecks_.load();
                    attachedInfo.storageConsistencyRepairs = naanConsistencyRepairs_.load();
                    attachedInfo.storageConsistencyLastAt = naanConsistencyLastAt_.load();

                    attachedInfo.quarantineReason = "none";
                    attachedInfo.quarantineReasonSince = 0;
                    if (score.quarantined) {
                        attachedInfo.quarantineReasonSince = naanConnectorAbuseLastAt_.load();
                        if (attachedInfo.quarantineReasonSince > 0) {
                            attachedInfo.quarantineReason = "connector_auto_quarantine";
                        } else if (score.localDraftOnly) {
                            attachedInfo.quarantineReason = "score_policy_local_draft_only";
                        } else if (score.reviewOnly) {
                            attachedInfo.quarantineReason = "score_policy_review_only";
                        } else if (score.throttled) {
                            attachedInfo.quarantineReason = "score_policy_throttled";
                        } else {
                            attachedInfo.quarantineReason = "score_policy";
                        }
                    }

                    std::lock_guard<std::mutex> lock(webMtx_);
                    if (webSearch_) {
                        auto health = webSearch_->getConnectorHealth();
                        auto stats = webSearch_->getStats();
                        attachedInfo.connectorAvailable = true;
                        attachedInfo.connectorClearnetState = web::connectorHealthStateToString(health.clearnet.state);
                        attachedInfo.connectorTorState = web::connectorHealthStateToString(health.tor.state);
                        attachedInfo.connectorOnionState = web::connectorHealthStateToString(health.onion.state);
                        attachedInfo.connectorPolicyBlocks =
                            health.clearnet.policyBlocks + health.tor.policyBlocks + health.onion.policyBlocks;
                        attachedInfo.connectorFailures =
                            health.clearnet.failures + health.tor.failures + health.onion.failures;
                        attachedInfo.webTotalSearches = stats.totalSearches;
                        attachedInfo.webSuccessfulFetches = stats.successfulFetches;
                        attachedInfo.webFailedFetches = stats.failedFetches;
                        attachedInfo.webPagesExtracted = stats.pagesExtracted;
                        attachedInfo.webBytesDownloaded = stats.bytesDownloaded;
                    } else {
                        attachedInfo.connectorClearnetState = "unavailable";
                        attachedInfo.connectorTorState = "unavailable";
                        attachedInfo.connectorOnionState = "unavailable";
                    }
                    {
                        std::lock_guard<std::mutex> lock(naanWebResearchMtx_);
                        attachedInfo.webLastSearchAt = naanWebResearchSnapshot_.lastSearchAt;
                        attachedInfo.webLastQuery = naanWebResearchSnapshot_.query;
                        attachedInfo.webLastQueryType = naanWebResearchSnapshot_.queryType;
                        attachedInfo.webLastResultCount = naanWebResearchSnapshot_.resultCount;
                        attachedInfo.webLastClearnetResults = naanWebResearchSnapshot_.clearnetResults;
                        attachedInfo.webLastOnionResults = naanWebResearchSnapshot_.onionResults;
                        attachedInfo.webLastTopSites = naanWebResearchSnapshot_.topSites;
                        attachedInfo.webLastPostSaved = naanWebResearchSnapshot_.saved;
                        attachedInfo.webLastSkipReason = naanWebResearchSnapshot_.skipReason;
                        attachedInfo.webLastError = naanWebResearchSnapshot_.error;
                    }
                }
                ui.updateAttachedAgentStatus(attachedInfo);

                std::vector<tui::ObservatoryArtifactInfo> observatoryItems;
                {
                    auto feed = agentCoordination_.getObservatoryFeed(0, 120);
                    observatoryItems.reserve(feed.size());
                    for (const auto& entry : feed) {
                        tui::ObservatoryArtifactInfo item;
                        item.hash = crypto::toHex(entry.hash);
                        item.roomId = entry.roomId;
                        item.type = core::roomMessageTypeToString(entry.type);
                        item.author = crypto::toHex(entry.author);
                        item.payloadPreview = redactPotentialSecrets(entry.payloadPreview);
                        if (item.payloadPreview != entry.payloadPreview) {
                            naanRedactionCount_.fetch_add(1);
                        }
                        item.timestamp = entry.timestamp;
                        observatoryItems.push_back(std::move(item));
                    }
                }
                ui.updateObservatoryFeed(observatoryItems);

                {
                    auto uiEvents = snapshotNaanUiEvents();
                    std::vector<tui::AgentEventInfo> mapped;
                    mapped.reserve(uiEvents.size());
                    for (const auto& ev : uiEvents) {
                        tui::AgentEventInfo out;
                        out.timestamp = ev.timestamp;
                        out.category = ev.category;
                        out.message = ev.message;
                        mapped.push_back(std::move(out));
                    }
                    ui.updateAgentEvents(mapped);
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        
        ui.run();
        
        running_ = false;
        updateThread.join();
        stopThreads();
        ui.shutdown();
        utils::Logger::enableConsole(true);
        
        return 0;
#endif
    }
    
    int runDaemon() {
        utils::Logger::info("Running in daemon mode");
        
        std::cout << "\n=== SynapseNet Node Status ===\n";
        std::cout << "Mode: Daemon (no TUI)\n";
        std::cout << "Data Directory: " << config_.dataDir << "\n";
        std::cout << "Network Port: " << config_.port << "\n";
        std::cout << "RPC Port: " << config_.rpcPort << "\n";
        
        if (keys_ && keys_->isValid()) {
            std::cout << "Wallet Address: " << address_.substr(0, 16) << "...\n";
        } else {
            std::cout << "Wallet: Not loaded\n";
        }
        
        if (network_ && network_->getPort() != 0) {
            std::cout << "Network: Online\n";
        } else {
            std::cout << "Network: Offline\n";
        }
        
        std::cout << "\nNode is running. Press Ctrl+C to stop.\n";
        std::cout << "Logs are written to: " << config_.dataDir << "/synapsenet.log\n\n";
        
        startThreads();
        
        int statusCounter = 0;
        while (running_) {
            if (g_reloadConfig) {
                reload();
                g_reloadConfig = false;
            }
            
            // Print status every 30 seconds
            if (statusCounter % 30 == 0) {
                auto stats = getStats();
                std::cout << "[" << std::time(nullptr) << "] ";
                std::cout << "Uptime: " << formatUptime(stats.uptime) << ", ";
                std::cout << "Peers: " << stats.peersConnected << ", ";
                std::cout << "Knowledge: " << stats.knowledgeEntries << ", ";
                std::cout << "Sync: " << std::fixed << std::setprecision(1) << (stats.syncProgress * 100) << "%\n";
            }
            
            statusCounter++;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        stopThreads();
        return 0;
    }
    
    void startThreads() {
        networkThread_ = std::thread([this]() { networkLoop(); });
        consensusThread_ = std::thread([this]() { consensusLoop(); });
        maintenanceThread_ = std::thread([this]() { maintenanceLoop(); });
        syncThread_ = std::thread([this]() { syncLoop(); });
    }
    
    void stopThreads() {
        if (networkThread_.joinable()) networkThread_.join();
        if (consensusThread_.joinable()) consensusThread_.join();
        if (maintenanceThread_.joinable()) maintenanceThread_.join();
        if (syncThread_.joinable()) syncThread_.join();
    }
    
    void networkLoop() {
        uint64_t lastAnnounce = 0;
        uint64_t lastPeerRefresh = 0;
        bool p2pBlockedPrev = false;
        
        while (running_) {
            uint64_t now = std::time(nullptr);

            const bool torRequired = agentTorRequired_.load();
            bool torReachable = probeTorSocks();
            if (torRequired && !torReachable) {
                bool started = maybeStartManagedTorRuntimeWithBackoff(true, "network_loop");
                if (started) {
                    agentTorManaged_.store(true);
                    torReachable = probeTorSocks();
                }
            }
            if (torReachable) {
                resetManagedTorRestartBackoffState();
            }
            agentTorReachable_.store(torReachable);
            refreshTorWebReadiness(torReachable, false);

            core::TorRoutePolicyInput routeIn;
            routeIn.torRequired = torRequired;
            routeIn.torReachable = torReachable;
            routeIn.allowClearnetFallback = agentAllowClearnetFallback_.load();
            routeIn.allowP2PFallback = agentAllowP2PFallback_.load();
            const auto route = core::evaluateTorRoutePolicy(routeIn);
            agentTorDegraded_.store(route.torDegraded);
            updateAndLogTorReadinessState(torRequired, torReachable, agentTorWebReady_.load(), route.torDegraded);

            network::NetworkConfig netCfg = network_->getConfig();
            bool netCfgChanged = false;
            if (torRequired) {
                const bool useProxy = torReachable;
                const std::string socksHost = configuredTorSocksHost();
                const uint16_t socksPort = configuredTorSocksPort();
                const uint32_t maxOutbound = route.allowP2PDiscovery ? config_.maxOutbound : 0;

                if (netCfg.useSocksProxy != useProxy) {
                    netCfg.useSocksProxy = useProxy;
                    netCfgChanged = true;
                }
                if (netCfg.socksProxyHost != socksHost) {
                    netCfg.socksProxyHost = socksHost;
                    netCfgChanged = true;
                }
                if (netCfg.socksProxyPort != socksPort) {
                    netCfg.socksProxyPort = socksPort;
                    netCfgChanged = true;
                }
                if (netCfg.maxOutbound != maxOutbound) {
                    netCfg.maxOutbound = maxOutbound;
                    netCfgChanged = true;
                }
            } else {
                if (netCfg.useSocksProxy) {
                    netCfg.useSocksProxy = false;
                    netCfgChanged = true;
                }
                if (netCfg.maxOutbound != config_.maxOutbound) {
                    netCfg.maxOutbound = config_.maxOutbound;
                    netCfgChanged = true;
                }
            }
            if (netCfgChanged) {
                network_->setConfig(netCfg);
            }

            if (!route.allowP2PDiscovery) {
                if (!p2pBlockedPrev) {
                    utils::Logger::warn("Tor-required fail-closed mode active: outbound P2P is blocked");
                    p2pBlockedPrev = true;
                }
                for (const auto& peer : network_->getPeers()) {
                    if (peer.isOutbound) {
                        network_->disconnect(peer.id);
                    }
                }
                for (int i = 0; i < 300 && running_; ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                continue;
            }
            if (p2pBlockedPrev) {
                utils::Logger::info("Tor-required fail-closed mode cleared: outbound P2P resumed");
                p2pBlockedPrev = false;
            }
            
            // Periodic peer exchange refresh
            if (discovery_ && now - lastPeerRefresh > 30) {
                discovery_->refreshFromPeers();
                lastPeerRefresh = now;
            }
            
            // Periodic announce
            if (discovery_ && now - lastAnnounce > 300) { // Every 5 minutes
                discovery_->announce();
                lastAnnounce = now;
            }
            
            if (config_.discovery && network_->peerCount() < config_.maxOutbound) {
                // Prioritize bootstrap nodes first (best chance to find network quickly)
                if (discovery_) {
                    auto boots = discovery_->getBootstrapNodes();
                    for (const auto& bn : boots) {
                        if (network_->peerCount() >= config_.maxOutbound) break;
                        network_->connect(bn.address, bn.port);
                    }
                }
                auto peers = discovery_->getRandomPeers(10);
                for (const auto& peer : peers) {
                    if (network_->peerCount() >= config_.maxOutbound) break;
                    network_->connect(peer.address, peer.port);
                }
            }
            
            std::unordered_set<std::string> connected;
            for (const auto& peer : network_->getPeers()) {
                connected.insert(peer.address + ":" + std::to_string(peer.port));
            }
            
            auto connectToNode = [this, &connected](const std::string& node) {
                size_t colonPos = node.find(':');
                if (colonPos != std::string::npos) {
                    std::string host = node.substr(0, colonPos);
                    uint16_t port = std::stoi(node.substr(colonPos + 1));
                    std::string id = host + ":" + std::to_string(port);
                    if (connected.count(id) == 0) {
                        network_->connect(host, port);
                    }
                }
            };
            
            for (const auto& node : config_.connectNodes) connectToNode(node);
            for (const auto& node : config_.addNodes) connectToNode(node);
            
            for (int i = 0; i < 300 && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    
    void consensusLoop() {
        while (running_) {
            if (consensus_) {
                consensus_->processTimeouts();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
		    void maintenanceLoop() {
		        uint64_t lastCompact = 0;
		        uint64_t lastQuantum = 0;
		        uint64_t lastBlock = 0;
                uint64_t lastOfferBroadcast = 0;
		        while (running_) {
		            uint64_t now = std::time(nullptr);
		            tickNaanCoordinationSupervised(now);
                    maybeRunAutoPoeEpoch(now);
		            uint32_t limitEpochs = config_.dev ? 128 : 64;

		            struct PoeRetry {
		                std::string peerId;
		                PoeInvKind kind;
	                crypto::Hash256 after;
	                uint32_t limit;
	            };
		            std::vector<PoeRetry> retries;
		            {
		                std::lock_guard<std::mutex> lock(poeSyncMtx_);
		                for (auto& [peerId, st] : poeSync_) {
		                    if (st.entries.active && st.votes.active && st.entries.done && st.votes.done && !st.epochs.active) {
		                        st.epochs.active = true;
		                        st.epochs.inFlight = true;
		                        st.epochs.done = false;
		                        st.epochs.after = crypto::Hash256{};
		                        st.epochs.limit = limitEpochs;
		                        st.epochs.lastRequestAt = now;
		                        retries.push_back({peerId, PoeInvKind::EPOCH, st.epochs.after, st.epochs.limit});
		                    }
		                    if (st.entries.active && st.entries.inFlight && !st.entries.done &&
		                        now > st.entries.lastRequestAt + 3) {
		                        retries.push_back({peerId, PoeInvKind::ENTRY, st.entries.after, st.entries.limit});
		                        st.entries.lastRequestAt = now;
		                    }
		                    if (st.votes.active && st.votes.inFlight && !st.votes.done &&
		                        now > st.votes.lastRequestAt + 3) {
		                        retries.push_back({peerId, PoeInvKind::VOTE, st.votes.after, st.votes.limit});
		                        st.votes.lastRequestAt = now;
		                    }
		                    if (st.epochs.active && st.epochs.inFlight && !st.epochs.done &&
		                        now > st.epochs.lastRequestAt + 3) {
		                        retries.push_back({peerId, PoeInvKind::EPOCH, st.epochs.after, st.epochs.limit});
		                        st.epochs.lastRequestAt = now;
		                    }
		                }
		            }
		            for (const auto& r : retries) {
		                sendPoeGetInv(r.peerId, r.kind, r.after, r.limit);
	            }
	            
	            if (db_ && now - lastCompact >= 600) {
	                db_->compact();
	                lastCompact = now;
	            }
            
            if (quantumManager_ && now - lastQuantum >= 60) {
                quantumManager_->performMaintenance();
                lastQuantum = now;
            }
            
            if (ledger_ && now - lastBlock >= 15) {
                if (ledger_->getPendingEventCount() > 0) {
                    bool allowMining = true;
                    if (agentTorRequired_.load()) {
                        const auto route = refreshTorRoutePolicy(true);
                        allowMining = route.allowP2PDiscovery && agentTorWebReady_.load();
                    }
                    if (allowMining) {
                        buildBlockFromPending();
                    } else {
                        miningFailClosedSkips_.fetch_add(1);
                    }
                    lastBlock = now;
                }
            }

            // Expire remote provider sessions (slots + marketplace) deterministically by wall clock.
            if (modelAccess_) {
                modelAccess_->processExpiredSessions();
            }
            if (modelMarketplace_) {
                std::vector<std::pair<std::string, ProviderSession>> expired;
                {
                    std::lock_guard<std::mutex> lock(remoteProvMtx_);
                    for (const auto& [sid, s] : providerSessions_) {
                        if (s.expiresAt != 0 && s.expiresAt < now) {
                            expired.push_back({sid, s});
                        }
                    }
                    for (const auto& e : expired) {
                        providerSessions_.erase(e.first);
                    }
                }
                for (const auto& e : expired) {
                    (void)modelAccess_->endSession(e.second.renterId);
                    (void)modelMarketplace_->endRental(e.first);
                }
            }

            // Remote model routing: periodically broadcast offer (opt-in).
            if (network_ && modelAccess_ && modelLoader_ && now - lastOfferBroadcast >= 30) {
                if (remotePricePerRequestAtoms_ > 0 &&
                    modelLoader_->isLoaded() &&
                    modelAccess_->getMode() != model::AccessMode::PRIVATE) {
                    // Keep marketplace listing updated (stable id = offer id).
                    if (modelMarketplace_) {
                        auto info = modelLoader_->getInfo();
                        modelMarketplace_->upsertModel(
                            localOfferId_,
                            address_,
                            info.name.empty() ? "active" : info.name,
                            "",
                            info.sizeBytes,
                            "GGUF",
                            modelAccess_->getPrice(),
                            remotePricePerRequestAtoms_,
                            modelAccess_->getMaxSlots(),
                            true
                        );
                    }
                    auto offer = buildLocalOffer(now);
                    network_->broadcast(makeMessage("m_offer", offer.serialize()));
                    lastOfferBroadcast = now;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    void syncLoop() {
        while (running_) {
            uint64_t localHeight = ledger_ ? ledger_->height() : 0;
            uint64_t netHeight = networkHeight_.load();
            if (netHeight == 0) {
                syncProgress_ = 1.0;
            } else {
                double progress = static_cast<double>(localHeight) / static_cast<double>(netHeight);
                syncProgress_ = progress > 1.0 ? 1.0 : progress;
            }
            
            if (!ledger_) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            
            if (network_ && netHeight > localHeight) {
                syncing_ = true;
                auto peers = network_->getPeers();
                if (!peers.empty()) {
                    uint64_t now = std::time(nullptr);
                    size_t inFlight = 0;
                    {
                        std::lock_guard<std::mutex> lock(syncMtx_);
                        for (auto it = requestedBlocks_.begin(); it != requestedBlocks_.end();) {
                            if (now - it->second > 10) {
                                it = requestedBlocks_.erase(it);
                            } else {
                                ++inFlight;
                                ++it;
                            }
                        }
                    }
                    
                    size_t maxInFlight = 16;
                    uint64_t nextHeight = localHeight;
                    while (nextHeight < netHeight && inFlight < maxInFlight) {
                        bool already = false;
                        {
                            std::lock_guard<std::mutex> lock(syncMtx_);
                            if (requestedBlocks_.count(nextHeight)) {
                                already = true;
                            } else {
                                requestedBlocks_[nextHeight] = now;
                            }
                        }
                        if (!already) {
                            const auto& peer = peers[nextHeight % peers.size()];
                            sendGetBlock(peer.id, nextHeight);
                            ++inFlight;
                        }
                        ++nextHeight;
                    }
                }
            } else {
                syncing_ = false;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    static std::vector<uint8_t> serializeU64(uint64_t val) {
        std::vector<uint8_t> out(8);
        for (int i = 0; i < 8; i++) out[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xff);
        return out;
    }
    
    static uint64_t deserializeU64(const std::vector<uint8_t>& data) {
        if (data.size() < 8) return 0;
        uint64_t val = 0;
        for (int i = 0; i < 8; i++) val |= static_cast<uint64_t>(data[i]) << (i * 8);
        return val;
    }
    
    network::Message makeMessage(const std::string& command, const std::vector<uint8_t>& payload) {
        network::Message msg;
        msg.command = command;
        msg.payload = payload;
        msg.timestamp = std::time(nullptr);
        return msg;
    }
    
    crypto::Signature signHash(const crypto::Hash256& hash) {
        crypto::Signature sig{};
        if (!keys_ || !keys_->isValid()) return sig;
        auto privVec = keys_->getPrivateKey();
        if (privVec.size() < crypto::PRIVATE_KEY_SIZE) return sig;
        crypto::PrivateKey priv{};
        std::memcpy(priv.data(), privVec.data(), priv.size());
        sig = crypto::sign(hash, priv);
        return sig;
    }
    
    void updateSignerFromKeys() {
        if (keys_ && keys_->isValid() && ledger_) {
            ledger_->setSigner([this](const crypto::Hash256& hash) {
                return signHash(hash);
            });
        }
    }
    
    void buildBlockFromPending() {
        if (!ledger_) return;
        auto events = ledger_->getPendingEvents();
        if (events.empty()) return;
        core::Block block;
        block.height = ledger_->height();
        block.timestamp = std::time(nullptr);
        block.prevHash = ledger_->tipHash();
        block.events = std::move(events);
        block.difficulty = ledger_->currentDifficulty();
        block.merkleRoot = block.computeMerkleRoot();
        block.nonce = 0;
        block.hash = block.computeHash();

        miningActive_.store(true);
        miningWorkTargetBits_.store(block.difficulty);
        uint64_t attempts = 1;
        {
            std::lock_guard<std::mutex> lock(miningStateMtx_);
            miningCandidateHash_ = block.hash;
        }

        while (!block.meetsTarget()) {
            block.nonce++;
            block.hash = block.computeHash();
            attempts++;
            if ((attempts & 1023ULL) == 0ULL) {
                std::lock_guard<std::mutex> lock(miningStateMtx_);
                miningCandidateHash_ = block.hash;
            }
        }
        {
            std::lock_guard<std::mutex> lock(miningStateMtx_);
            miningCandidateHash_ = block.hash;
        }
        miningHashAttemptsLast_.store(attempts);
        miningHashAttemptsTotal_.fetch_add(attempts);
        miningLastSolvedAt_.store(static_cast<uint64_t>(std::time(nullptr)));
        miningActive_.store(false);

        if (!ledger_->appendBlockWithValidation(block)) {
            return;
        }

        if (transfer_) {
            std::vector<core::Transaction> blockTxs;
            for (const auto& ev : block.events) {
                if (ev.type != core::EventType::TRANSFER) continue;
                core::Transaction tx = core::Transaction::deserialize(ev.data);
                if (tx.txid == crypto::Hash256{}) continue;
                blockTxs.push_back(tx);
            }
            if (!blockTxs.empty()) {
                if (!transfer_->applyBlockTransactionsFromBlock(blockTxs, block.height, block.hash)) {
                    utils::Logger::error("Failed to apply block transfer events (local mined block)");
                }
            }
        }
    }
    
    void sendVersion(const std::string& peerId) {
        if (!network_) return;
        synapse::VersionMessage v{};
        v.version = 1;
        v.services = 0;
        v.timestamp = std::time(nullptr);
        v.nonce = static_cast<uint64_t>(std::random_device{}()) << 32 | std::random_device{}();
        v.userAgent = "SynapseNet:0.1";
        v.startHeight = ledger_ ? ledger_->height() : 0;
        v.relay = true;
        uint16_t port = network_->getPort();
        v.portRecv = port;
        v.portFrom = port;
        auto msg = makeMessage("version", v.serialize());
        network_->send(peerId, msg);
    }
    
    void sendVerack(const std::string& peerId) {
        if (!network_) return;
        auto msg = makeMessage("verack", {});
        network_->send(peerId, msg);
    }
    
    void sendGetAddr(const std::string& peerId) {
        if (!network_) return;
        auto msg = makeMessage("getaddr", {});
        network_->send(peerId, msg);
    }

    void sendMempoolRequest(const std::string& peerId) {
        if (!network_) return;
        auto msg = makeMessage("mempool", {});
        network_->send(peerId, msg);
    }
    
	    void sendGetBlock(const std::string& peerId, uint64_t height) {
	        if (!network_) return;
	        auto msg = makeMessage("getblock", serializeU64(height));
	        network_->send(peerId, msg);
	    }

		    static void writeU32LE(std::vector<uint8_t>& out, uint32_t v) {
		        out.push_back(static_cast<uint8_t>(v & 0xFF));
		        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
		        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
		        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
		    }

		    static void writeU64LE(std::vector<uint8_t>& out, uint64_t v) {
		        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
		    }

		    static uint32_t readU32LE(const std::vector<uint8_t>& data, size_t off) {
		        if (off + 4 > data.size()) return 0;
		        return static_cast<uint32_t>(data[off]) |
		               (static_cast<uint32_t>(data[off + 1]) << 8) |
	               (static_cast<uint32_t>(data[off + 2]) << 16) |
		               (static_cast<uint32_t>(data[off + 3]) << 24);
		    }

		    static uint64_t readU64LE(const std::vector<uint8_t>& data, size_t off) {
		        if (off + 8 > data.size()) return 0;
		        uint64_t v = 0;
		        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off + static_cast<size_t>(i)]) << (8 * i);
		        return v;
		    }

		    static bool hashLess(const crypto::Hash256& a, const crypto::Hash256& b) {
		        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
		    }

		    static crypto::Hash256 poeEpochInvHash(uint64_t epochId) {
		        crypto::Hash256 out{};
		        for (int i = 0; i < 8; ++i) {
		            out[24 + static_cast<size_t>(i)] = static_cast<uint8_t>((epochId >> (8 * (7 - i))) & 0xFF);
		        }
		        return out;
		    }

		    static std::optional<uint64_t> epochIdFromPoeInvHash(const crypto::Hash256& h) {
		        for (size_t i = 0; i < 24; ++i) {
		            if (h[i] != 0) return std::nullopt;
		        }
		        uint64_t v = 0;
		        for (size_t i = 0; i < 8; ++i) {
		            v = (v << 8) | static_cast<uint64_t>(h[24 + i]);
		        }
		        if (v == 0) return std::nullopt;
		        return v;
		    }

		    static std::vector<uint8_t> serializePoeEpoch(const core::PoeEpochResult& epoch) {
		        std::vector<core::PoeEpochAllocation> allocs = epoch.allocations;
		        std::sort(allocs.begin(), allocs.end(), [](const core::PoeEpochAllocation& a, const core::PoeEpochAllocation& b) {
		            return std::lexicographical_compare(a.contentId.begin(), a.contentId.end(), b.contentId.begin(), b.contentId.end());
		        });

		        std::vector<uint8_t> out;
		        out.reserve(8 + 4 + crypto::SHA256_SIZE + 8 + crypto::SHA256_SIZE + 4 +
		                    allocs.size() * (crypto::SHA256_SIZE + crypto::SHA256_SIZE + crypto::PUBLIC_KEY_SIZE + 8 + 8));
		        writeU64LE(out, epoch.epochId);
		        writeU32LE(out, epoch.iterations);
		        out.insert(out.end(), epoch.epochSeed.begin(), epoch.epochSeed.end());
		        writeU64LE(out, epoch.totalBudget);
		        out.insert(out.end(), epoch.allocationHash.begin(), epoch.allocationHash.end());
		        writeU32LE(out, static_cast<uint32_t>(allocs.size()));
		        for (const auto& a : allocs) {
		            out.insert(out.end(), a.submitId.begin(), a.submitId.end());
		            out.insert(out.end(), a.contentId.begin(), a.contentId.end());
		            out.insert(out.end(), a.authorPubKey.begin(), a.authorPubKey.end());
		            writeU64LE(out, a.score);
		            writeU64LE(out, a.amount);
		        }
		        return out;
		    }

		    static std::optional<core::PoeEpochResult> deserializePoeEpoch(const std::vector<uint8_t>& payload) {
		        const size_t headerSize = 8 + 4 + crypto::SHA256_SIZE + 8 + crypto::SHA256_SIZE + 4;
		        if (payload.size() < headerSize) return std::nullopt;
		        size_t off = 0;
		        uint64_t epochId = readU64LE(payload, off);
		        off += 8;
		        uint32_t iterations = readU32LE(payload, off);
		        off += 4;
		        crypto::Hash256 epochSeed{};
		        std::memcpy(epochSeed.data(), payload.data() + off, epochSeed.size());
		        off += epochSeed.size();
		        uint64_t totalBudget = readU64LE(payload, off);
		        off += 8;
		        crypto::Hash256 allocHash{};
		        std::memcpy(allocHash.data(), payload.data() + off, allocHash.size());
		        off += allocHash.size();
		        uint32_t count = readU32LE(payload, off);
		        off += 4;

		        const size_t itemSize = crypto::SHA256_SIZE + crypto::SHA256_SIZE + crypto::PUBLIC_KEY_SIZE + 8 + 8;
		        size_t need = off + static_cast<size_t>(count) * itemSize;
		        if (need > payload.size()) return std::nullopt;

		        std::vector<core::PoeEpochAllocation> allocations;
		        allocations.reserve(count);
		        for (uint32_t i = 0; i < count; ++i) {
		            core::PoeEpochAllocation a;
		            std::memcpy(a.submitId.data(), payload.data() + off, a.submitId.size());
		            off += a.submitId.size();
		            std::memcpy(a.contentId.data(), payload.data() + off, a.contentId.size());
		            off += a.contentId.size();
		            std::memcpy(a.authorPubKey.data(), payload.data() + off, a.authorPubKey.size());
		            off += a.authorPubKey.size();
		            a.score = readU64LE(payload, off);
		            off += 8;
		            a.amount = readU64LE(payload, off);
		            off += 8;
		            allocations.push_back(a);
		        }

		        core::PoeEpochResult out;
		        out.ok = true;
		        out.epochId = epochId;
		        out.iterations = iterations;
		        out.epochSeed = epochSeed;
		        out.totalBudget = totalBudget;
		        out.allocationHash = allocHash;
		        out.allocations = std::move(allocations);
		        return out;
		    }

	    void sendPoeInventory(const std::string& peerId) {
	        if (!network_ || !poeV1_) return;

	        const size_t maxEntries = config_.dev ? 250 : 100;
	        const size_t maxVotes = config_.dev ? 500 : 200;
	        const size_t maxEpochs = config_.dev ? 128 : 64;

	        auto entries = poeV1_->listEntryIds(maxEntries);
	        auto votes = poeV1_->listVoteIds(maxVotes);
	        auto epochs = poeV1_->listEpochIds(maxEpochs);
	        if (entries.empty() && votes.empty() && epochs.empty()) return;

	        synapse::InvMessage inv;
	        inv.items.reserve(entries.size() + votes.size() + epochs.size());

        for (const auto& sid : entries) {
            synapse::InvItem item;
            item.type = synapse::InvType::POE_ENTRY;
            std::memcpy(item.hash.data(), sid.data(), sid.size());
            inv.items.push_back(item);
        }

	        for (const auto& vid : votes) {
	            synapse::InvItem item;
	            item.type = synapse::InvType::POE_VOTE;
	            std::memcpy(item.hash.data(), vid.data(), vid.size());
	            inv.items.push_back(item);
	        }

	        for (uint64_t epochId : epochs) {
	            synapse::InvItem item;
	            item.type = synapse::InvType::POE_EPOCH;
	            crypto::Hash256 hid = poeEpochInvHash(epochId);
	            std::memcpy(item.hash.data(), hid.data(), hid.size());
	            inv.items.push_back(item);
	        }

	        auto msg = makeMessage("inv", inv.serialize());
	        network_->send(peerId, msg);
	    }

	    void sendUpdateBundleInventory(const std::string& peerId) {
	        if (!network_) return;

	        const size_t limit = config_.dev ? 256 : 128;
	        std::vector<crypto::Hash256> bundleIds;
	        {
	            std::lock_guard<std::mutex> lock(invMtx_);
	            bundleIds.reserve(updateManifestsById_.size());
	            for (const auto& [_, manifest] : updateManifestsById_) {
	                bundleIds.push_back(manifest.bundleId);
	            }
	        }
	        if (bundleIds.empty()) return;

	        std::sort(bundleIds.begin(), bundleIds.end(), [](const crypto::Hash256& a, const crypto::Hash256& b) {
	            return hashLess(a, b);
	        });
	        if (bundleIds.size() > limit) {
	            bundleIds.erase(bundleIds.begin(), bundleIds.end() - static_cast<std::ptrdiff_t>(limit));
	        }

	        synapse::InvMessage inv;
	        inv.items.reserve(bundleIds.size());
	        for (const auto& bundleId : bundleIds) {
	            synapse::InvItem item;
	            item.type = synapse::InvType::UPDATE_BUNDLE;
	            std::memcpy(item.hash.data(), bundleId.data(), bundleId.size());
	            inv.items.push_back(item);
	        }

	        if (inv.items.empty()) return;
	        auto msg = makeMessage("inv", inv.serialize());
	        network_->send(peerId, msg);
	    }

	    void sendPoeGetInv(const std::string& peerId, PoeInvKind kind, const crypto::Hash256& after, uint32_t limit) {
	        if (!network_ || !poeV1_) return;
	        if (limit == 0) limit = 1;
	        if (limit > 2048) limit = 2048;
	        std::vector<uint8_t> payload;
	        payload.reserve(1 + crypto::SHA256_SIZE + 4);
	        payload.push_back(static_cast<uint8_t>(kind));
	        payload.insert(payload.end(), after.begin(), after.end());
	        writeU32LE(payload, limit);
	        auto msg = makeMessage("poe_getinv", payload);
	        network_->send(peerId, msg);
	    }

	    void startPoeSync(const std::string& peerId) {
	        if (!network_ || !poeV1_) return;

	        uint32_t limitEntries = config_.dev ? 512 : 256;
	        uint32_t limitVotes = config_.dev ? 1024 : 512;
	        uint64_t now = std::time(nullptr);

	        bool doEntries = false;
	        bool doVotes = false;
	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            auto& st = poeSync_[peerId];
	            if (!st.entries.active) {
	                st.entries.active = true;
	                st.entries.inFlight = true;
	                st.entries.done = false;
	                st.entries.after = crypto::Hash256{};
	                st.entries.limit = limitEntries;
	                st.entries.lastRequestAt = now;
	                doEntries = true;
	            }
	            if (!st.votes.active) {
	                st.votes.active = true;
	                st.votes.inFlight = true;
	                st.votes.done = false;
	                st.votes.after = crypto::Hash256{};
	                st.votes.limit = limitVotes;
	                st.votes.lastRequestAt = now;
	                doVotes = true;
	            }
	        }

	        if (doEntries) sendPoeGetInv(peerId, PoeInvKind::ENTRY, crypto::Hash256{}, limitEntries);
	        if (doVotes) sendPoeGetInv(peerId, PoeInvKind::VOTE, crypto::Hash256{}, limitVotes);
	    }

	    std::vector<crypto::Hash256> selectPoeIdsPage(PoeInvKind kind, const crypto::Hash256& after, uint32_t limit) {
	        if (!poeV1_) return {};

	        std::vector<crypto::Hash256> all;
	        if (kind == PoeInvKind::ENTRY) {
	            all = poeV1_->listEntryIds(0);
	        } else if (kind == PoeInvKind::VOTE) {
	            all = poeV1_->listVoteIds(0);
	        } else if (kind == PoeInvKind::EPOCH) {
	            auto epochs = poeV1_->listEpochIds(0);
	            all.reserve(epochs.size());
	            for (uint64_t eid : epochs) {
	                all.push_back(poeEpochInvHash(eid));
	            }
	        } else {
	            return {};
	        }

	        auto it = std::upper_bound(all.begin(), all.end(), after, [](const crypto::Hash256& v, const crypto::Hash256& e) {
	            return hashLess(v, e);
	        });

	        std::vector<crypto::Hash256> page;
	        page.reserve(std::min<size_t>(static_cast<size_t>(limit), all.size()));
	        for (; it != all.end() && page.size() < limit; ++it) {
	            page.push_back(*it);
	        }
	        return page;
	    }

	    void handlePoeGetInvMessage(const std::string& peerId, const network::Message& msg) {
	        if (!network_ || !poeV1_) return;
	        if (msg.payload.size() < 1 + crypto::SHA256_SIZE + 4) return;

	        PoeInvKind kind = static_cast<PoeInvKind>(msg.payload[0]);
	        crypto::Hash256 after{};
	        std::memcpy(after.data(), msg.payload.data() + 1, after.size());
	        uint32_t limit = readU32LE(msg.payload, 1 + crypto::SHA256_SIZE);
	        if (limit == 0) limit = 1;
	        if (limit > 2048) limit = 2048;

	        auto page = selectPoeIdsPage(kind, after, limit);

	        std::vector<uint8_t> payload;
	        payload.reserve(1 + crypto::SHA256_SIZE + 4 + page.size() * crypto::SHA256_SIZE);
	        payload.push_back(static_cast<uint8_t>(kind));
	        payload.insert(payload.end(), after.begin(), after.end());
	        writeU32LE(payload, static_cast<uint32_t>(page.size()));
	        for (const auto& h : page) {
	            payload.insert(payload.end(), h.begin(), h.end());
	        }

	        auto reply = makeMessage("poe_inv", payload);
	        network_->send(peerId, reply);
	    }

	    void handlePoeInvMessage(const std::string& peerId, const network::Message& msg) {
	        if (!network_ || !poeV1_) return;
	        if (msg.payload.size() < 1 + crypto::SHA256_SIZE + 4) return;

	        PoeInvKind kind = static_cast<PoeInvKind>(msg.payload[0]);
	        crypto::Hash256 after{};
	        std::memcpy(after.data(), msg.payload.data() + 1, after.size());
	        uint32_t count = readU32LE(msg.payload, 1 + crypto::SHA256_SIZE);
	        size_t expected = 1 + crypto::SHA256_SIZE + 4 + static_cast<size_t>(count) * crypto::SHA256_SIZE;
	        if (expected > msg.payload.size()) return;

	        uint32_t limit = 0;
	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            auto it = poeSync_.find(peerId);
	            if (it == poeSync_.end()) return;
	            PoeSyncState* st = nullptr;
	            if (kind == PoeInvKind::ENTRY) st = &it->second.entries;
	            else if (kind == PoeInvKind::VOTE) st = &it->second.votes;
	            else if (kind == PoeInvKind::EPOCH) st = &it->second.epochs;
	            if (!st) return;
	            if (!st->active || st->done) return;
	            if (!st->inFlight) return;
	            if (st->after != after) return;
	            limit = st->limit;
	        }

	        synapse::InvMessage inv;
	        inv.items.reserve(count);
	        const uint8_t* ptr = msg.payload.data() + 1 + crypto::SHA256_SIZE + 4;
	        for (uint32_t i = 0; i < count; ++i) {
	            synapse::InvItem item;
	            if (kind == PoeInvKind::ENTRY) item.type = synapse::InvType::POE_ENTRY;
	            else if (kind == PoeInvKind::VOTE) item.type = synapse::InvType::POE_VOTE;
	            else if (kind == PoeInvKind::EPOCH) item.type = synapse::InvType::POE_EPOCH;
	            else return;
	            std::memcpy(item.hash.data(), ptr, crypto::SHA256_SIZE);
	            ptr += crypto::SHA256_SIZE;
	            inv.items.push_back(item);
	        }

	        network::Message fakeInv = makeMessage("inv", inv.serialize());
	        handleInvMessage(peerId, fakeInv);

	        crypto::Hash256 nextAfter = after;
	        if (!inv.items.empty()) {
	            std::memcpy(nextAfter.data(), inv.items.back().hash.data(), nextAfter.size());
	        }

	        bool shouldContinue = (count == limit) && (nextAfter != after);
	        bool done = !shouldContinue;
	        uint64_t now = std::time(nullptr);

	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            auto it = poeSync_.find(peerId);
	            if (it != poeSync_.end()) {
	                PoeSyncState* st = nullptr;
	                if (kind == PoeInvKind::ENTRY) st = &it->second.entries;
	                else if (kind == PoeInvKind::VOTE) st = &it->second.votes;
	                else if (kind == PoeInvKind::EPOCH) st = &it->second.epochs;
	                if (st) {
	                    st->inFlight = false;
	                    if (done) {
	                        st->done = true;
	                    } else {
	                        st->after = nextAfter;
	                        st->inFlight = true;
	                        st->lastRequestAt = now;
	                        st->pages += 1;
	                    }
	                }
	            }
	        }

	        if (shouldContinue) {
	            sendPoeGetInv(peerId, kind, nextAfter, limit);
	        }
	    }
	    
	    void broadcastInv(synapse::InvType type, const crypto::Hash256& hash) {
	        if (!network_) return;
            const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
            const std::string key = std::to_string(static_cast<int>(type)) + ":" + crypto::toHex(hash);
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                auto it = invGossipSeenAt_.find(key);
                if (it != invGossipSeenAt_.end() &&
                    now <= it->second + static_cast<uint64_t>(config_.networkGossipDedupWindowSeconds)) {
                    gossipSuppressed_.fetch_add(1);
                    return;
                }
                invGossipSeenAt_[key] = now;
                if (invGossipSeenAt_.size() > 65536) {
                    const uint64_t ttl = std::max<uint32_t>(1, config_.networkGossipDedupWindowSeconds) * 3ULL;
                    for (auto itr = invGossipSeenAt_.begin(); itr != invGossipSeenAt_.end();) {
                        if (now > itr->second + ttl) itr = invGossipSeenAt_.erase(itr);
                        else ++itr;
                    }
                }
            }

	        synapse::InvMessage inv;
            synapse::InvItem item;
            item.type = type;
            std::memcpy(item.hash.data(), hash.data(), hash.size());
            inv.items.push_back(item);
            auto msg = makeMessage("inv", inv.serialize());

            auto peers = network_->getPeers();
            if (peers.empty()) return;
            uint32_t fanout = std::max<uint32_t>(1, config_.networkGossipFanoutLimit);
            auto netStats = network_->getStats();
            if (netStats.overloadMode) {
                fanout = std::max<uint32_t>(1, fanout / 2);
            }

            if (peers.size() <= fanout) {
                network_->broadcast(msg);
                return;
            }

            std::sort(peers.begin(), peers.end(), [](const network::Peer& a, const network::Peer& b) {
                return a.id < b.id;
            });
            uint64_t startSeed = 0;
            std::memcpy(&startSeed, hash.data(), std::min<size_t>(sizeof(startSeed), hash.size()));
            size_t start = peers.empty() ? 0 : static_cast<size_t>(startSeed % peers.size());
            uint64_t sent = 0;
            for (size_t step = 0; step < peers.size() && sent < fanout; ++step) {
                size_t idx = (start + step) % peers.size();
                if (peers[idx].state != network::PeerState::CONNECTED) continue;
                if (network_->send(peers[idx].id, msg)) {
                    sent += 1;
                }
            }
            if (sent == 0) {
                network_->broadcast(msg);
            } else {
                gossipSubsetRouted_.fetch_add(sent);
            }
    }
    
	    void handleMessage(const std::string& peerId, const network::Message& msg) {
	        if (msg.command == "ping") {
            network::Message pong;
            pong.command = "pong";
            pong.payload = msg.payload;
            network_->send(peerId, pong);
        } else if (msg.command == "pong") {
            handlePongMessage(peerId, msg);
        } else if (msg.command == "version") {
            handleVersionMessage(peerId, msg);
        } else if (msg.command == "verack") {
            handleVerackMessage(peerId, msg);
        } else if (msg.command == "getaddr") {
            handleGetAddrMessage(peerId, msg);
        } else if (msg.command == "addr") {
            handleAddrMessage(peerId, msg);
        } else if (msg.command == "getpeers") {
            handleGetPeersMessage(peerId, msg);
        } else if (msg.command == "peers") {
            handlePeersMessage(peerId, msg);
        } else if (msg.command == "inv") {
            handleInvMessage(peerId, msg);
        } else if (msg.command == "getdata") {
            handleGetDataMessage(peerId, msg);
        } else if (msg.command == "getblock") {
            handleGetBlockMessage(peerId, msg);
        } else if (msg.command == "block") {
            handleBlockMessage(peerId, msg);
	        } else if (msg.command == "knowledge") {
	            handleKnowledgeMessage(peerId, msg);
	        } else if (msg.command == "tx") {
	            handleTxMessage(peerId, msg);
	        } else if (msg.command == "mempool") {
	            handleMempoolMessage(peerId, msg);
	        } else if (msg.command == "poe_getinv") {
	            handlePoeGetInvMessage(peerId, msg);
	        } else if (msg.command == "poe_inv") {
	            handlePoeInvMessage(peerId, msg);
	        } else if (msg.command == "poe_entry") {
	            handlePoeEntryMessage(peerId, msg);
	        } else if (msg.command == "poe_vote") {
	            handlePoeVoteMessage(peerId, msg);
	        } else if (msg.command == "poe_epoch") {
	            handlePoeEpochMessage(peerId, msg);
	        } else if (msg.command == "upd_manifest") {
	            handleUpdateManifestMessage(peerId, msg);
	        } else if (msg.command == "m_offer") {
	            handleRemoteOfferMessage(peerId, msg);
	        } else if (msg.command == "m_rent") {
	            handleRemoteRentMessage(peerId, msg);
	        } else if (msg.command == "m_rentok") {
	            handleRemoteRentOkMessage(peerId, msg);
	        } else if (msg.command == "m_infer") {
	            handleRemoteInferMessage(peerId, msg);
	        } else if (msg.command == "m_out") {
	            handleRemoteOutMessage(peerId, msg);
	        }
	    }

    static std::string pubKeyHex33(const std::array<uint8_t, 33>& pk) {
        return crypto::toHex(pk.data(), pk.size());
    }

    static std::string randomHex16() {
        std::array<uint8_t, 16> b{};
        std::random_device rd;
        for (auto& v : b) v = static_cast<uint8_t>(rd());
        return crypto::toHex(b.data(), b.size());
    }

    synapse::RemoteModelOfferMessage buildLocalOffer(uint64_t now) {
        synapse::RemoteModelOfferMessage offer;
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            offer.offerId = localOfferId_;
        }
        offer.providerAddress = address_;
        offer.pricePerRequestAtoms = remotePricePerRequestAtoms_;
        offer.maxSlots = modelAccess_ ? modelAccess_->getMaxSlots() : 0;
        offer.usedSlots = modelAccess_ ? modelAccess_->getActiveSlots() : 0;
        offer.expiresAt = now + 120;

        if (modelLoader_) {
            std::lock_guard<std::mutex> lock(modelMtx_);
            auto info = modelLoader_->getInfo();
            offer.modelId = info.name.empty() ? "active" : info.name;
        }
        if (offer.modelId.empty()) offer.modelId = "active";
        return offer;
    }

    bool verifyPaymentToSelf(const std::string& paymentTxidHex, uint64_t minAtoms, uint64_t& paidOut) const {
        paidOut = 0;
        if (!transfer_) return false;
        auto bytes = crypto::fromHex(paymentTxidHex);
        if (bytes.size() != 32) return false;
        crypto::Hash256 txid{};
        std::memcpy(txid.data(), bytes.data(), txid.size());
        if (!transfer_->hasTransaction(txid)) return false;
        core::Transaction tx = transfer_->getTransaction(txid);
        if (tx.outputs.empty()) return false;
        for (const auto& outp : tx.outputs) {
            if (outp.address == address_) {
                if (UINT64_MAX - paidOut < outp.amount) return false;
                paidOut += outp.amount;
            }
        }
        return paidOut >= minAtoms;
    }

    void handleRemoteOfferMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        synapse::RemoteModelOfferMessage offer;
        try {
            offer = synapse::RemoteModelOfferMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (offer.offerId.empty() || offer.modelId.empty() || offer.providerAddress.empty()) return;
        uint64_t now = std::time(nullptr);
        if (offer.expiresAt != 0 && offer.expiresAt < now) return;
        std::lock_guard<std::mutex> lock(remoteMtx_);
        RemoteOfferCache c;
        c.offer = offer;
        c.peerId = peerId;
        c.receivedAt = now;
        remoteOffers_[offer.offerId] = std::move(c);
    }

    void handleRemoteRentMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        if (!modelAccess_) return;
        synapse::RemoteModelRentMessage rent;
        try {
            rent = synapse::RemoteModelRentMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (rent.offerId.empty()) return;

        // Only honor rent requests for our currently advertised offer.
        std::string expectedOffer;
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            expectedOffer = localOfferId_;
        }
        if (expectedOffer.empty() || rent.offerId != expectedOffer) return;

        const std::string renterId = pubKeyHex33(rent.renterPubKey);
        if (!modelAccess_->canAccess(renterId)) return;
        if (!modelAccess_->hasAvailableSlot()) return;

        const uint64_t now = std::time(nullptr);
        const uint64_t sessionTtl = config_.dev ? 900 : 3600;
        const uint64_t expiresAt = now + sessionTtl;

        if (!modelAccess_->startSession(renterId)) return;

        synapse::RemoteModelRentOkMessage ok;
        ok.offerId = rent.offerId;
        // Use marketplace session id as remote session id for unified accounting.
        if (!modelMarketplace_) return;
        ok.sessionId = modelMarketplace_->rentModel(ok.offerId, renterId);
        if (ok.sessionId.empty()) {
            // Roll back access session if marketplace can't allocate.
            (void)modelAccess_->endSession(renterId);
            return;
        }
        ok.providerAddress = address_;
        ok.pricePerRequestAtoms = remotePricePerRequestAtoms_;
        ok.expiresAt = expiresAt;

        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            ProviderSession ps;
            ps.renterId = renterId;
            ps.expiresAt = expiresAt;
            ps.pricePerRequestAtoms = remotePricePerRequestAtoms_;
            providerSessions_[ok.sessionId] = std::move(ps);
        }

        if (network_) {
            auto reply = makeMessage("m_rentok", ok.serialize());
            network_->send(peerId, reply);
        }
    }

    void handleRemoteRentOkMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        synapse::RemoteModelRentOkMessage ok;
        try {
            ok = synapse::RemoteModelRentOkMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (ok.offerId.empty() || ok.sessionId.empty() || ok.providerAddress.empty()) return;
        RemoteSessionInfo s;
        s.peerId = peerId;
        s.sessionId = ok.sessionId;
        s.providerAddress = ok.providerAddress;
        s.pricePerRequestAtoms = ok.pricePerRequestAtoms;
        s.expiresAt = ok.expiresAt;
        {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            remoteSessions_[s.sessionId] = s;
            remoteRentOkByOffer_[ok.offerId] = ok;
        }
        remoteCv_.notify_all();
    }

    void handleRemoteInferMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.empty()) return;
        if (!modelLoader_ || !modelAccess_) return;
        synapse::RemoteModelInferMessage req;
        try {
            req = synapse::RemoteModelInferMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (req.sessionId.empty() || req.requestId.empty() || req.prompt.empty()) return;

        ProviderSession sess;
        {
            std::lock_guard<std::mutex> lock(remoteProvMtx_);
            auto it = providerSessions_.find(req.sessionId);
            if (it == providerSessions_.end()) return;
            sess = it->second;
        }
        const uint64_t now = std::time(nullptr);
        if (sess.expiresAt != 0 && sess.expiresAt < now) return;

        const std::string renterId = pubKeyHex33(req.renterPubKey);
        if (!renterId.empty() && renterId != sess.renterId) return;
        if (!modelAccess_->canAccess(sess.renterId)) return;
        if (modelAccess_->isRateLimited(sess.renterId)) return;

        // Enforce payment (mempool/confirmed). Provider address is our local address_.
        uint64_t paid = 0;
        bool paidOk = false;
        if (sess.pricePerRequestAtoms > 0) {
            paidOk = verifyPaymentToSelf(req.paymentTxidHex, sess.pricePerRequestAtoms, paid);
        } else {
            paidOk = true;
        }

        auto sendErr = [&](const std::string& errText) {
            synapse::RemoteModelOutMessage out;
            out.requestId = req.requestId;
            out.text = errText;
            out.tokensUsed = 0;
            out.latencyMs = 0;
            if (network_) {
                network_->send(peerId, makeMessage("m_out", out.serialize()));
            }
        };

        if (!paidOk) {
            sendErr("ERROR: payment_invalid_or_missing");
            return;
        }

        std::string resultText;
        uint64_t startMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

        {
            std::lock_guard<std::mutex> lock(modelMtx_);
            if (!modelLoader_->isLoaded()) {
                sendErr("ERROR: model_not_loaded");
                return;
            }
            if (modelLoader_->isGenerating()) {
                sendErr("ERROR: model_busy");
                return;
            }
            model::GenerationParams gp;
            gp.maxTokens = std::max<uint32_t>(1, req.maxTokens);
            gp.temperature = std::max(0.0f, req.temperature);
            gp.topP = std::max(0.0f, req.topP);
            gp.topK = req.topK;
            resultText = modelLoader_->generate(req.prompt, gp);
        }

        uint64_t endMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        uint64_t latency = (endMs >= startMs) ? (endMs - startMs) : 0;

        if (paid > 0) {
            modelAccess_->recordPayment(sess.renterId, paid);
            if (modelMarketplace_) {
                (void)modelMarketplace_->recordPayment(req.sessionId, paid);
            }
        }
        modelAccess_->recordRequest(sess.renterId, 0, static_cast<double>(latency));
        if (modelMarketplace_) {
            (void)modelMarketplace_->recordRequest(req.sessionId, 0, latency);
        }

        synapse::RemoteModelOutMessage out;
        out.requestId = req.requestId;
        out.text = resultText;
        out.tokensUsed = 0;
        out.latencyMs = latency;
        if (network_) {
            network_->send(peerId, makeMessage("m_out", out.serialize()));
        }
    }

    void handleRemoteOutMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (msg.payload.empty()) return;
        synapse::RemoteModelOutMessage out;
        try {
            out = synapse::RemoteModelOutMessage::deserialize(msg.payload);
        } catch (...) {
            return;
        }
        if (out.requestId.empty()) return;
        {
            std::lock_guard<std::mutex> lock(remoteMtx_);
            auto it = remotePending_.find(out.requestId);
            if (it != remotePending_.end()) {
                it->second.done = true;
                it->second.text = out.text;
                it->second.tokensUsed = out.tokensUsed;
                it->second.latencyMs = out.latencyMs;
            }
        }
        remoteCv_.notify_all();
    }
    
    void handleVersionMessage(const std::string& peerId, const network::Message& msg) {
        if (msg.payload.size() < 40) return;
        synapse::VersionMessage v = synapse::VersionMessage::deserialize(msg.payload);
        peerHeights_[peerId] = v.startHeight;
        if (v.startHeight > networkHeight_) {
            networkHeight_ = v.startHeight;
        }
        
        // Extract our external IP from version message if available
        // The remote peer's view of our address is in addrRecv
        if (discovery_ && v.addrRecv[10] == 0xff && v.addrRecv[11] == 0xff) {
            char ipStr[INET_ADDRSTRLEN];
            in_addr ipv4{};
            std::memcpy(&ipv4, v.addrRecv.data() + 12, 4);
            if (inet_ntop(AF_INET, &ipv4, ipStr, sizeof(ipStr))) {
                std::string ourIP = ipStr;
                // Only set if it's not localhost
                if (ourIP != "127.0.0.1" && ourIP != "0.0.0.0" && ourIP.find("127.") != 0) {
                    discovery_->setExternalAddress(ourIP);
                }
            }
        }
        
        sendVerack(peerId);
        sendGetAddr(peerId);
        sendMempoolRequest(peerId);
        sendPoeInventory(peerId);
        sendUpdateBundleInventory(peerId);
        startPoeSync(peerId);
    }
    
    void handleVerackMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        (void)msg;
    }
    
    void handlePongMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        (void)msg;
    }
    
    void handleGetAddrMessage(const std::string& peerId, const network::Message& msg) {
        (void)msg;
        if (!discovery_) return;
        auto peers = discovery_->getKnownPeers(100);
        synapse::PeersMessage peersMsg;
        for (const auto& peer : peers) {
            synapse::PeerAddress addr{};
            addr.timestamp = peer.timestamp;
            addr.services = peer.services;
            addr.port = peer.port;
            addr.addr.fill(0);
            in_addr ipv4{};
            if (inet_pton(AF_INET, peer.address.c_str(), &ipv4) == 1) {
                addr.addr[10] = 0xff;
                addr.addr[11] = 0xff;
                std::memcpy(addr.addr.data() + 12, &ipv4, 4);
                peersMsg.peers.push_back(addr);
            }
        }
        auto reply = makeMessage("addr", peersMsg.serialize());
        network_->send(peerId, reply);
    }
    
    void handleAddrMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (msg.payload.empty()) return;
        if (!discovery_) return;
        synapse::PeersMessage peersMsg = synapse::PeersMessage::deserialize(msg.payload);
        std::vector<network::PeerInfo> incoming;
        for (const auto& addr : peersMsg.peers) {
            if (addr.addr[10] == 0xff && addr.addr[11] == 0xff) {
                char ipStr[INET_ADDRSTRLEN];
                in_addr ipv4{};
                std::memcpy(&ipv4, addr.addr.data() + 12, 4);
                if (inet_ntop(AF_INET, &ipv4, ipStr, sizeof(ipStr))) {
                    network::PeerInfo info;
                    info.address = ipStr;
                    info.port = addr.port;
                    info.services = addr.services;
                    info.timestamp = addr.timestamp;
                    info.lastSeen = addr.timestamp;
                    incoming.push_back(info);
                }
            }
        }
        if (!incoming.empty()) {
            discovery_->processIncoming(incoming);
        }
    }
    
    void handleGetPeersMessage(const std::string& peerId, const network::Message& msg) {
        (void)msg;
        if (!discovery_ || !network_) return;
        
        // Rate limiting: check if we've sent to this peer recently
        static std::unordered_map<std::string, uint64_t> lastSent;
        uint64_t now = std::time(nullptr);
        auto it = lastSent.find(peerId);
        if (it != lastSent.end() && now - it->second < 60) {
            return; // Rate limit: max 1 response per minute per peer
        }
        lastSent[peerId] = now;
        
        // Get random peers (max 50, excluding the requesting peer)
        auto allPeers = discovery_->getRandomPeers(50);
        synapse::PeersMessage peersMsg;
        
        // Get requesting peer's address to exclude it
        std::string requestingPeerAddr;
        auto networkPeers = network_->getPeers();
        for (const auto& p : networkPeers) {
            if (p.id == peerId) {
                requestingPeerAddr = p.address;
                break;
            }
        }
        
        for (const auto& peer : allPeers) {
            // Don't send the requesting peer back to itself
            if (peer.address == requestingPeerAddr && peer.port == network_->getPort()) {
                continue;
            }
            
            // Skip banned peers
            if (discovery_->isBanned(peer.address)) {
                continue;
            }
            
            synapse::PeerAddress addr{};
            addr.timestamp = peer.timestamp;
            addr.services = peer.services;
            addr.port = peer.port;
            addr.addr.fill(0);
            
            in_addr ipv4{};
            if (inet_pton(AF_INET, peer.address.c_str(), &ipv4) == 1) {
                addr.addr[10] = 0xff;
                addr.addr[11] = 0xff;
                std::memcpy(addr.addr.data() + 12, &ipv4, 4);
                peersMsg.peers.push_back(addr);
            }
            
            if (peersMsg.peers.size() >= 50) break; // Max 50 peers per message
        }
        
        if (!peersMsg.peers.empty()) {
            auto reply = makeMessage("peers", peersMsg.serialize());
            network_->send(peerId, reply);
        }
    }
    
    void handlePeersMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (msg.payload.empty()) return;
        if (!discovery_) return;
        
        synapse::PeersMessage peersMsg = synapse::PeersMessage::deserialize(msg.payload);
        std::vector<network::PeerInfo> incoming;
        
        for (const auto& addr : peersMsg.peers) {
            // Only handle IPv4 addresses (mapped IPv6 format)
            if (addr.addr[10] == 0xff && addr.addr[11] == 0xff) {
                char ipStr[INET_ADDRSTRLEN];
                in_addr ipv4{};
                std::memcpy(&ipv4, addr.addr.data() + 12, 4);
                if (inet_ntop(AF_INET, &ipv4, ipStr, sizeof(ipStr))) {
                    std::string ipString = ipStr;
                    
                    // Validate: skip localhost
                    if (ipString == "127.0.0.1" || ipString == "::1" || ipString.find("127.") == 0) {
                        continue;
                    }
                    
                    // Validate: skip banned
                    if (discovery_->isBanned(ipString)) {
                        continue;
                    }
                    
                    // Validate: skip our own address
                    if (network_) {
                        // Check if this is our own address/port
                        bool isSelf = false;
                        auto localAddr = network_->getLocalAddress();
                        if (localAddr == ipString && addr.port == network_->getPort()) {
                            isSelf = true;
                        }
                        // Also check against our known address
                        if (!isSelf && !address_.empty()) {
                            // Could add more checks here if needed
                        }
                        if (isSelf) {
                            continue;
                        }
                    }
                    
                    network::PeerInfo info;
                    info.address = ipString;
                    info.port = addr.port;
                    info.services = addr.services;
                    info.timestamp = addr.timestamp;
                    info.lastSeen = addr.timestamp;
                    info.state = network::DiscoveryPeerState::UNKNOWN;
                    info.attempts = 0;
                    incoming.push_back(info);
                }
            }
        }
        
        if (!incoming.empty()) {
            discovery_->processIncoming(incoming);
        }
    }
    
	    void handleInvMessage(const std::string& peerId, const network::Message& msg) {
	        if (msg.payload.empty()) return;
	        synapse::InvMessage inv = synapse::InvMessage::deserialize(msg.payload);
	        synapse::GetDataMessage req;
            const bool overloaded = network_ ? network_->getStats().overloadMode : false;
            const uint32_t maxItems = overloaded ? config_.networkInvOverloadItems : config_.networkInvMaxItems;
            std::unordered_set<std::string> seenItems;
            seenItems.reserve(inv.items.size());
            uint64_t dropped = 0;
        
        for (const auto& item : inv.items) {
            if (req.items.size() >= maxItems) {
                dropped += 1;
                continue;
            }

            std::string itemKey = std::to_string(static_cast<int>(item.type)) + ":" +
                crypto::toHex(item.hash.data(), item.hash.size());
            if (!seenItems.insert(itemKey).second) {
                dropped += 1;
                continue;
            }

            bool known = false;
            std::string h = crypto::toHex(item.hash.data(), item.hash.size());
            
            if (item.type == synapse::InvType::TX) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    if (knownTxs_.count(h) > 0) known = true;
                }
                if (!known && transfer_) {
                    crypto::Hash256 txid{};
                    std::memcpy(txid.data(), item.hash.data(), txid.size());
                    known = transfer_->hasTransaction(txid);
                }
            } else if (item.type == synapse::InvType::KNOWLEDGE) {
                std::lock_guard<std::mutex> lock(invMtx_);
                known = (knownKnowledge_.count(h) > 0) || (knowledgeByHash_.count(h) > 0);
            } else if (item.type == synapse::InvType::BLOCK) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    if (knownBlocks_.count(h) > 0) known = true;
                }
                if (!known && ledger_) {
                    crypto::Hash256 bh{};
                    std::memcpy(bh.data(), item.hash.data(), bh.size());
                    known = ledger_->getBlockByHash(bh).hash != crypto::Hash256{};
                }
            } else if (item.type == synapse::InvType::POE_ENTRY) {
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    if (knownPoeEntries_.count(h) > 0) known = true;
                }
                if (!known && poeV1_) {
                    crypto::Hash256 sid{};
                    std::memcpy(sid.data(), item.hash.data(), sid.size());
                    known = poeV1_->getEntry(sid).has_value();
                }
	            } else if (item.type == synapse::InvType::POE_VOTE) {
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    if (knownPoeVotes_.count(h) > 0) known = true;
	                }
	                if (!known && poeV1_) {
	                    crypto::Hash256 vid{};
	                    std::memcpy(vid.data(), item.hash.data(), vid.size());
	                    known = poeV1_->getVoteById(vid).has_value();
	                }
	            } else if (item.type == synapse::InvType::POE_EPOCH) {
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    if (knownPoeEpochs_.count(h) > 0) known = true;
	                }
	                if (!known && poeV1_) {
	                    crypto::Hash256 hid{};
	                    std::memcpy(hid.data(), item.hash.data(), hid.size());
	                    auto eid = epochIdFromPoeInvHash(hid);
	                    if (!eid) {
	                        known = true;
	                    } else {
	                        known = poeV1_->getEpoch(*eid).has_value();
	                    }
	                }
	            } else if (item.type == synapse::InvType::UPDATE_BUNDLE) {
	                std::lock_guard<std::mutex> lock(invMtx_);
	                known = (knownUpdateBundles_.count(h) > 0) || (updateManifestsById_.count(h) > 0);
	            }
            
            if (!known) {
                req.items.push_back(item);
            }
        }
        if (dropped > 0) {
            invBackpressureDrops_.fetch_add(dropped);
        }
        
        if (!req.items.empty()) {
            auto request = makeMessage("getdata", req.serialize());
            network_->send(peerId, request);
        }
    }
    
	    void handleGetDataMessage(const std::string& peerId, const network::Message& msg) {
	        if (msg.payload.empty()) return;
	        synapse::GetDataMessage req = synapse::GetDataMessage::deserialize(msg.payload);
            const bool overloaded = network_ ? network_->getStats().overloadMode : false;
            const uint32_t maxItems = overloaded ? config_.networkGetDataOverloadItems : config_.networkGetDataMaxItems;
            uint64_t processed = 0;
            uint64_t dropped = 0;
        
        for (const auto& item : req.items) {
            if (processed >= maxItems) {
                dropped += 1;
                continue;
            }
            processed += 1;
            if (item.type == synapse::InvType::TX && transfer_) {
                crypto::Hash256 txid{};
                std::memcpy(txid.data(), item.hash.data(), txid.size());
                core::Transaction tx = transfer_->getTransaction(txid);
                if (tx.txid != crypto::Hash256{}) {
                    auto reply = makeMessage("tx", tx.serialize());
                    network_->send(peerId, reply);
                }
            } else if (item.type == synapse::InvType::KNOWLEDGE && knowledge_) {
                std::string h = crypto::toHex(item.hash.data(), item.hash.size());
                uint64_t id = 0;
                {
                    std::lock_guard<std::mutex> lock(invMtx_);
                    auto it = knowledgeByHash_.find(h);
                    if (it != knowledgeByHash_.end()) id = it->second;
                }
                if (id != 0) {
                    core::KnowledgeEntry entry = knowledge_->get(id);
                    if (entry.id != 0) {
                        auto reply = makeMessage("knowledge", entry.serialize());
                        network_->send(peerId, reply);
                    }
                }
            } else if (item.type == synapse::InvType::BLOCK && ledger_) {
                crypto::Hash256 bh{};
                std::memcpy(bh.data(), item.hash.data(), bh.size());
                core::Block block = ledger_->getBlockByHash(bh);
                if (block.hash != crypto::Hash256{}) {
                    auto reply = makeMessage("block", block.serialize());
                    network_->send(peerId, reply);
                }
            } else if (item.type == synapse::InvType::POE_ENTRY && poeV1_) {
                crypto::Hash256 sid{};
                std::memcpy(sid.data(), item.hash.data(), sid.size());
                auto entry = poeV1_->getEntry(sid);
                if (entry) {
                    auto reply = makeMessage("poe_entry", entry->serialize());
                    network_->send(peerId, reply);
                }
	            } else if (item.type == synapse::InvType::POE_VOTE && poeV1_) {
	                crypto::Hash256 vid{};
	                std::memcpy(vid.data(), item.hash.data(), vid.size());
	                auto vote = poeV1_->getVoteById(vid);
	                if (vote) {
	                    auto reply = makeMessage("poe_vote", vote->serialize());
	                    network_->send(peerId, reply);
	                }
	            } else if (item.type == synapse::InvType::POE_EPOCH && poeV1_) {
	                crypto::Hash256 hid{};
	                std::memcpy(hid.data(), item.hash.data(), hid.size());
	                auto eid = epochIdFromPoeInvHash(hid);
	                if (!eid) continue;
	                auto epoch = poeV1_->getEpoch(*eid);
	                if (epoch) {
	                    auto reply = makeMessage("poe_epoch", serializePoeEpoch(*epoch));
	                    network_->send(peerId, reply);
	                }
	            } else if (item.type == synapse::InvType::UPDATE_BUNDLE) {
	                core::UpdateManifest manifest;
	                bool found = false;
	                std::string idHex = crypto::toHex(item.hash.data(), item.hash.size());
	                {
	                    std::lock_guard<std::mutex> lock(invMtx_);
	                    auto it = updateManifestsById_.find(idHex);
	                    if (it != updateManifestsById_.end()) {
	                        manifest = it->second;
	                        found = true;
	                    }
	                }
	                if (found) {
	                    auto reply = makeMessage("upd_manifest", manifest.serialize());
	                    network_->send(peerId, reply);
	                }
	            }
	        }
            if (dropped > 0) {
                getDataBackpressureDrops_.fetch_add(dropped);
            }
	    }
    
    void handleGetBlockMessage(const std::string& peerId, const network::Message& msg) {
        if (!ledger_) return;
        if (msg.payload.size() < 8) return;
        uint64_t height = deserializeU64(msg.payload);
        core::Block block = ledger_->getBlock(height);
        if (block.hash != crypto::Hash256{}) {
            auto reply = makeMessage("block", block.serialize());
            network_->send(peerId, reply);
        }
    }
    
    void handleBlockMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!ledger_) return;
        core::Block block = core::Block::deserialize(msg.payload);
        if (block.hash == crypto::Hash256{}) return;

        std::vector<core::Transaction> blockTxs;
        if (transfer_) {
            for (const auto& ev : block.events) {
                if (ev.type != core::EventType::TRANSFER) continue;
                core::Transaction tx = core::Transaction::deserialize(ev.data);
                if (tx.txid == crypto::Hash256{}) return;
                blockTxs.push_back(tx);
            }
            if (!blockTxs.empty()) {
                if (!transfer_->verifyTransactionsInBlockOrder(blockTxs)) return;
            }
        }

        if (!ledger_->appendBlockWithValidation(block)) return;
        
        {
            std::lock_guard<std::mutex> lock(syncMtx_);
            requestedBlocks_.erase(block.height);
        }
        {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownBlocks_.insert(crypto::toHex(block.hash));
        }
        uint64_t impliedHeight = block.height + 1;
        if (impliedHeight > networkHeight_) {
            networkHeight_ = impliedHeight;
        }
        
        suppressCallbacks_ = true;
        for (const auto& ev : block.events) {
            if (ev.type == core::EventType::KNOWLEDGE && knowledge_) {
                core::KnowledgeEntry entry = core::KnowledgeEntry::deserialize(ev.data);
                knowledge_->importEntry(entry);
            } else if (ev.type == core::EventType::POE_ENTRY && poeV1_) {
                auto entry = core::poe_v1::KnowledgeEntryV1::deserialize(ev.data);
                if (entry) {
                    poeV1_->importEntry(*entry, nullptr);
                }
            } else if (ev.type == core::EventType::POE_VOTE && poeV1_) {
                auto vote = core::poe_v1::ValidationVoteV1::deserialize(ev.data);
                if (vote) {
                    poeV1_->addVote(*vote);
                }
            }
        }
        suppressCallbacks_ = false;

        if (transfer_ && !blockTxs.empty()) {
            if (!transfer_->applyBlockTransactionsFromBlock(blockTxs, block.height, block.hash)) {
                utils::Logger::error("Failed to apply block transfer events (received block)");
            }
        }
    }
    
    void handleKnowledgeMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!knowledge_) return;
        if (msg.payload.empty()) return;
        core::KnowledgeEntry entry = core::KnowledgeEntry::deserialize(msg.payload);
        knowledge_->importEntry(entry);
    }
    
    void handleTxMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!transfer_) return;
        if (msg.payload.empty()) return;
        core::Transaction tx = core::Transaction::deserialize(msg.payload);
        transfer_->submitTransaction(tx);
    }

    void handleMempoolMessage(const std::string& peerId, const network::Message& msg) {
        (void)msg;
        if (!network_ || !transfer_) return;

        auto pending = transfer_->getPending();
        if (pending.empty()) return;

        synapse::InvMessage inv;
        size_t limit = 5000;
        size_t count = 0;
        for (const auto& tx : pending) {
            if (count++ >= limit) break;
            synapse::InvItem item;
            item.type = synapse::InvType::TX;
            std::memcpy(item.hash.data(), tx.txid.data(), tx.txid.size());
            inv.items.push_back(item);
        }

        if (inv.items.empty()) return;
        auto reply = makeMessage("inv", inv.serialize());
        network_->send(peerId, reply);
    }

    uint64_t maybeCreditAcceptanceReward(const crypto::Hash256& submitId) {
        if (!poeV1_ || !transfer_) return 0;

        auto fin = poeV1_->finalize(submitId);
        if (!fin) return 0;

        auto entry = poeV1_->getEntry(submitId);
        if (!entry) return 0;

        std::string addr = addressFromPubKey(entry->authorPubKey);
        if (addr.empty()) return 0;

        uint64_t amount = poeV1_->calculateAcceptanceReward(*entry);
        if (amount == 0) return 0;

        crypto::Hash256 rewardId = rewardIdForAcceptance(submitId);
        if (transfer_->creditRewardDeterministic(addr, rewardId, amount)) {
            return amount;
        }
        return 0;
    }

    void maybeRunAutoPoeEpoch(uint64_t now) {
        if (!poeV1_ || !transfer_) return;

        auto& runtimeCfg = utils::Config::instance();
        if (!runtimeCfg.getBool("poe.epoch.auto_enabled", true)) return;

        int64_t intervalRaw = runtimeCfg.getInt64("poe.epoch.auto_interval_seconds", config_.dev ? 30 : 300);
        if (intervalRaw < 5) intervalRaw = 5;
        if (intervalRaw > 86400) intervalRaw = 86400;
        const uint64_t intervalSec = static_cast<uint64_t>(intervalRaw);

        const uint64_t lastRun = autoPoeEpochLastRunAt_.load();
        if (lastRun != 0 && now < (lastRun + intervalSec)) return;

        const bool requireNewFinalized = runtimeCfg.getBool("poe.epoch.auto_require_new_finalized", true);
        const uint64_t finalizedCount = poeV1_->totalFinalized();
        if (finalizedCount == 0) return;
        if (requireNewFinalized && finalizedCount <= autoPoeEpochLastFinalizedCount_.load()) return;

        int64_t cfgBudget = runtimeCfg.getInt64(
            "poe.epoch_budget",
            config_.dev ? 100000000LL : 1000000000LL);
        const uint64_t budget = cfgBudget > 0 ? static_cast<uint64_t>(cfgBudget) : 0ULL;
        if (budget == 0) {
            autoPoeEpochLastRunAt_.store(now);
            return;
        }
        const uint32_t iters = static_cast<uint32_t>(std::max(1, runtimeCfg.getInt(
            "poe.epoch_iterations",
            config_.dev ? 10 : 20)));

        auto epochRes = poeV1_->runEpoch(budget, iters);
        autoPoeEpochLastRunAt_.store(now);
        if (!epochRes.ok) {
            if (epochRes.error != "no_finalized_entries") {
                utils::Logger::warn("Auto PoE epoch skipped: " + epochRes.error);
            }
            return;
        }

        {
            crypto::Hash256 hid = poeEpochInvHash(epochRes.epochId);
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeEpochs_.insert(crypto::toHex(hid));
        }
        broadcastInv(synapse::InvType::POE_EPOCH, poeEpochInvHash(epochRes.epochId));

        uint64_t mintedTotal = 0;
        uint64_t mintedMine = 0;
        uint64_t mintedCount = 0;
        for (const auto& a : epochRes.allocations) {
            std::string addr = addressFromPubKey(a.authorPubKey);
            if (addr.empty()) continue;
            crypto::Hash256 rid = rewardIdForEpoch(epochRes.epochId, a.contentId);
            if (transfer_->creditRewardDeterministic(addr, rid, a.amount)) {
                mintedTotal += a.amount;
                mintedCount += 1;
                if (!address_.empty() && addr == address_) mintedMine += a.amount;
            }
        }

        autoPoeEpochLastFinalizedCount_.store(finalizedCount);

        std::ostringstream oss;
        oss << "Auto epoch #" << epochRes.epochId << " distributed "
            << std::fixed << std::setprecision(8)
            << (static_cast<double>(mintedTotal) / 100000000.0) << " NGT";
        if (mintedMine > 0) {
            oss << " (you: " << std::fixed << std::setprecision(8)
                << (static_cast<double>(mintedMine) / 100000000.0) << " NGT)";
        }
        oss << " to " << mintedCount << " entries";
        utils::Logger::info(oss.str());
    }

    void maybeAutoVote(const crypto::Hash256& submitId) {
        if (!poeV1_ || !keys_ || !keys_->isValid()) return;

        auto entry = poeV1_->getEntry(submitId);
        if (!entry) return;
        if (poeV1_->isFinalized(submitId)) return;

        updatePoeValidatorsFromStake();
        core::PoeV1Config cfg = poeV1_->getConfig();
        auto validators = poeV1_->getDeterministicValidators();
        if (validators.empty()) return;

        auto pubV = keys_->getPublicKey();
        if (pubV.size() < crypto::PUBLIC_KEY_SIZE) return;
        crypto::PublicKey selfPub{};
        std::memcpy(selfPub.data(), pubV.data(), selfPub.size());

        auto selected = core::poe_v1::selectValidators(poeV1_->chainSeed(), submitId, validators, cfg.validatorsN);
        if (std::find(selected.begin(), selected.end(), selfPub) == selected.end()) return;

        auto votes = poeV1_->getVotesForSubmit(submitId);
        for (const auto& v : votes) {
            if (v.validatorPubKey == selfPub) return;
        }

        auto privV = keys_->getPrivateKey();
        if (privV.size() < crypto::PRIVATE_KEY_SIZE) return;
        crypto::PrivateKey priv{};
        std::memcpy(priv.data(), privV.data(), priv.size());

        core::poe_v1::ValidationVoteV1 vote;
        vote.version = 1;
        vote.submitId = submitId;
        vote.prevBlockHash = poeV1_->chainSeed();
        vote.flags = 0;
        vote.scores = {100, 100, 100};
        core::poe_v1::signValidationVoteV1(vote, priv);

        crypto::Hash256 vid = vote.payloadHash();
        std::string vidHex = crypto::toHex(vid);

        bool added = poeV1_->addVote(vote);
        if (!added) return;

        {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeVotes_.insert(vidHex);
        }
        broadcastInv(synapse::InvType::POE_VOTE, vid);
        maybeCreditAcceptanceReward(submitId);
    }

    void handlePoeEntryMessage(const std::string& peerId, const network::Message& msg) {
        (void)peerId;
        if (!poeV1_) return;
        if (msg.payload.empty()) return;

        auto entry = core::poe_v1::KnowledgeEntryV1::deserialize(msg.payload);
        if (!entry) return;

        std::string reason;
        bool added = poeV1_->importEntry(*entry, &reason);
        crypto::Hash256 sid = entry->submitId();
        std::string sidHex = crypto::toHex(sid);

        if (added || reason == "duplicate_submit") {
            std::lock_guard<std::mutex> lock(invMtx_);
            knownPoeEntries_.insert(sidHex);
        }

        if (added) {
            broadcastInv(synapse::InvType::POE_ENTRY, sid);
        }

        maybeAutoVote(sid);
        maybeCreditAcceptanceReward(sid);
    }

	    void handlePoeVoteMessage(const std::string& peerId, const network::Message& msg) {
	        (void)peerId;
	        if (!poeV1_) return;
	        if (msg.payload.empty()) return;

        auto vote = core::poe_v1::ValidationVoteV1::deserialize(msg.payload);
        if (!vote) return;

        crypto::Hash256 vid = vote->payloadHash();
        std::string vidHex = crypto::toHex(vid);
        const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        {
            std::lock_guard<std::mutex> lock(invMtx_);
            auto it = recentPoeVotes_.find(vidHex);
            if (it != recentPoeVotes_.end() &&
                now <= it->second + static_cast<uint64_t>(config_.networkVoteDedupWindowSeconds)) {
                return;
            }
            recentPoeVotes_[vidHex] = now;
            if (recentPoeVotes_.size() > config_.networkVoteDedupMaxEntries) {
                const uint64_t ttl = std::max<uint32_t>(30, config_.networkVoteDedupWindowSeconds);
                for (auto itr = recentPoeVotes_.begin(); itr != recentPoeVotes_.end();) {
                    if (now > itr->second + ttl) itr = recentPoeVotes_.erase(itr);
                    else ++itr;
                }
                if (recentPoeVotes_.size() > config_.networkVoteDedupMaxEntries) {
                    std::vector<std::pair<std::string, uint64_t>> items;
                    items.reserve(recentPoeVotes_.size());
                    for (const auto& kv : recentPoeVotes_) items.push_back(kv);
                    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
                        if (a.second != b.second) return a.second > b.second;
                        return a.first < b.first;
                    });
                    recentPoeVotes_.clear();
                    const size_t keep = std::min<size_t>(config_.networkVoteDedupMaxEntries, items.size());
                    for (size_t idx = 0; idx < keep; ++idx) {
                        recentPoeVotes_[items[idx].first] = items[idx].second;
                    }
                }
            }
        }

        bool added = poeV1_->addVote(*vote);
        if (added) {
            {
                std::lock_guard<std::mutex> lock(invMtx_);
                knownPoeVotes_.insert(vidHex);
            }
            broadcastInv(synapse::InvType::POE_VOTE, vid);
        }

	        maybeCreditAcceptanceReward(vote->submitId);
	    }

	    void handlePoeEpochMessage(const std::string& peerId, const network::Message& msg) {
	        (void)peerId;
	        if (!poeV1_ || !transfer_) return;
	        if (msg.payload.empty()) return;

	        auto epoch = deserializePoeEpoch(msg.payload);
	        if (!epoch) return;

	        crypto::Hash256 hid = poeEpochInvHash(epoch->epochId);
	        std::string hidHex = crypto::toHex(hid);

	        if (!poeV1_->importEpoch(*epoch)) return;

	        {
	            std::lock_guard<std::mutex> lock(invMtx_);
	            knownPoeEpochs_.insert(hidHex);
	        }
	        broadcastInv(synapse::InvType::POE_EPOCH, hid);

	        auto stored = poeV1_->getEpoch(epoch->epochId);
	        if (!stored) return;

	        for (const auto& a : stored->allocations) {
	            std::string addr = addressFromPubKey(a.authorPubKey);
	            if (addr.empty()) continue;
	            crypto::Hash256 rid = rewardIdForEpoch(stored->epochId, a.contentId);
	            transfer_->creditRewardDeterministic(addr, rid, a.amount);
	        }
	    }

	    void handleUpdateManifestMessage(const std::string& peerId, const network::Message& msg) {
	        (void)peerId;
	        if (msg.payload.empty()) return;

	        auto manifest = core::UpdateManifest::deserialize(msg.payload);
	        if (!manifest) return;

	        std::string reason;
	        auto status = acceptUpdateManifest(*manifest, true, &reason);
	        if (status == UpdateManifestAccept::REJECTED) {
	            utils::Logger::warn("Rejected update manifest from peer: " + reason);
	        }
	    }
    
    void handlePeerConnected(const network::Peer& peer) {
        const bool torRequired = agentTorRequired_.load();
        if (torRequired) {
            const bool torReachable = probeTorSocks();
            agentTorReachable_.store(torReachable);
            refreshTorWebReadiness(torReachable, false);

            core::TorRoutePolicyInput routeIn;
            routeIn.torRequired = torRequired;
            routeIn.torReachable = torReachable;
            routeIn.allowClearnetFallback = agentAllowClearnetFallback_.load();
            routeIn.allowP2PFallback = agentAllowP2PFallback_.load();
            const auto route = core::evaluateTorRoutePolicy(routeIn);
            agentTorDegraded_.store(route.torDegraded);
            updateAndLogTorReadinessState(torRequired, torReachable, agentTorWebReady_.load(), route.torDegraded);

            if (!route.allowP2PDiscovery) {
                if (network_) network_->disconnect(peer.id);
                utils::Logger::warn("Rejected peer in Tor-required fail-closed mode: " + peer.id);
                return;
            }

            if (!peer.isOutbound) {
                const bool loopback = (peer.address == "127.0.0.1") || (peer.address.rfind("127.", 0) == 0);
                if (!loopback) {
                    if (network_) network_->disconnect(peer.id);
                    utils::Logger::warn("Rejected non-loopback inbound peer in Tor-required mode: " + peer.id);
                    return;
                }
            }
        }

        utils::Logger::info("Peer connected: " + peer.id);
        sendVersion(peer.id);
        
        // Update discovery with successful connection
        if (discovery_) {
            discovery_->markPeerSuccess(peer.address);
        }
    }
    
	    void handlePeerDisconnected(const network::Peer& peer) {
	        utils::Logger::info("Peer disconnected: " + peer.id);
	        peerHeights_.erase(peer.id);
	        {
	            std::lock_guard<std::mutex> lock(poeSyncMtx_);
	            poeSync_.erase(peer.id);
	        }
	        
	        // Update discovery with failed connection
	        if (discovery_) {
	            discovery_->markPeerFailed(peer.address);
	        }
	        
	        uint64_t maxHeight = 0;
	        for (const auto& [id, height] : peerHeights_) {
	            if (height > maxHeight) maxHeight = height;
	        }
	        networkHeight_ = maxHeight;
	    }

    uint64_t getMemoryUsage() const {
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            return usage.ru_maxrss * 1024;
        }
        return 0;
    }
    
    uint64_t getDiskUsage() const {
        uint64_t total = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(config_.dataDir)) {
            if (entry.is_regular_file()) {
                total += entry.file_size();
            }
        }
        return total;
    }
    
    std::atomic<bool> running_;
    bool offlineMode_ = false;
    uint64_t startTime_;
    double syncProgress_;
    NodeConfig config_;
    std::string address_;
    
    std::unique_ptr<database::Database> db_;
    std::unique_ptr<crypto::Keys> keys_;
    std::unique_ptr<network::Network> network_;
    std::unique_ptr<network::Discovery> discovery_;
    std::unique_ptr<core::Ledger> ledger_;
    std::unique_ptr<core::KnowledgeNetwork> knowledge_;
    std::unique_ptr<core::TransferManager> transfer_;
	    std::unique_ptr<core::Consensus> consensus_;
	    std::unique_ptr<core::PoeV1Engine> poeV1_;
	    std::unique_ptr<model::ModelLoader> modelLoader_;
	    std::unique_ptr<model::ModelAccess> modelAccess_;
        std::unique_ptr<model::ModelMarketplace> modelMarketplace_;
	    std::mutex modelMtx_;
	    std::atomic<uint64_t> modelRequests_{0};
		    std::unique_ptr<privacy::Privacy> privacy_;
		    std::unique_ptr<quantum::QuantumManager> quantumManager_;
		    std::unique_ptr<web::RpcServer> rpc_;
		    std::unique_ptr<web::WebSearch> webSearch_;
		    std::unique_ptr<web::QueryDetector> webDetector_;
		    std::unique_ptr<web::HtmlExtractor> webExtractor_;
		    std::unique_ptr<web::AIWrapper> webAi_;
		    std::mutex webMtx_;
            std::vector<std::string> naanWebConfigUnknownKeySamples_{};
            mutable std::mutex torBridgeProviderMetaMtx_;
            json torBridgeProviderMeta_ = json::object();
            std::atomic<uint64_t> torBridgeProviderMetaUpdatedAt_{0};
	    
	    std::unordered_map<std::string, uint64_t> peerHeights_;
    std::unordered_set<std::string> knownTxs_;
    std::unordered_set<std::string> knownKnowledge_;
	    std::unordered_set<std::string> knownBlocks_;
		    std::unordered_set<std::string> knownPoeEntries_;
		    std::unordered_set<std::string> knownPoeVotes_;
		    std::unordered_set<std::string> knownPoeEpochs_;
		    std::unordered_set<std::string> knownUpdateBundles_;
            std::unordered_map<std::string, uint64_t> recentPoeVotes_;
            std::unordered_map<std::string, uint64_t> invGossipSeenAt_;
            std::atomic<uint64_t> invBackpressureDrops_{0};
            std::atomic<uint64_t> getDataBackpressureDrops_{0};
            std::atomic<uint64_t> gossipSuppressed_{0};
            std::atomic<uint64_t> gossipSubsetRouted_{0};
		    std::unordered_map<std::string, uint64_t> knowledgeByHash_;
		    std::unordered_map<std::string, core::UpdateManifest> updateManifestsById_;
		    std::mutex updateApprovalMtx_;
		    std::unordered_map<std::string, std::vector<core::DetachedSignerApproval>> updateDetachedApprovalsByBundle_;
		    std::mutex securityPolicyMtx_;
		    std::string naanPolicyHash_{};
		    std::string implantPolicyHash_{};
		    std::atomic<uint64_t> naanSecurityEvents_{0};
		    std::atomic<uint64_t> naanSecurityHighSeverityEvents_{0};
		    std::atomic<uint64_t> naanSecurityLastEventAt_{0};
		    core::CoordinationHub agentCoordination_{};
		    std::atomic<bool> naanRuntimeInitialized_{false};
		    std::atomic<uint64_t> naanRuntimeStartedAt_{0};
		    core::AgentRuntimeSupervisor naanRuntimeSupervisor_{};
		    std::string naanRuntimeCrashStatePath_{};
		    std::atomic<uint64_t> naanRecoverySkips_{0};
		    core::AgentRuntimeSandbox agentRuntimeSandbox_{};
		    core::AgentAdaptiveScheduler agentAdaptiveScheduler_{};
		    core::AgentTaskScheduler naanTaskScheduler_{};
		    std::string naanSchedulerStatePath_{};
		    std::vector<core::ToolSchemaRule> naanToolSchemas_{};
		    core::AgentDraftQueue agentDraftQueue_{};
		    core::AgentSubmissionPipeline agentSubmissionPipeline_{};
		    core::AgentScoreTracker agentScore_{};
		    core::AgentStorageAuditLog naanAuditLog_{};
		    std::string naanStorageRootPath_{};
		    std::atomic<uint64_t> naanStorageRecoveredLines_{0};
		    std::atomic<uint64_t> naanStorageDroppedSegments_{0};
		    std::atomic<uint64_t> naanIndexRecoveryRuns_{0};
		    std::atomic<uint64_t> naanIndexRecoveryLastAt_{0};
		    std::atomic<uint64_t> naanConsistencyChecks_{0};
		    std::atomic<uint64_t> naanConsistencyRepairs_{0};
		    std::atomic<uint64_t> naanConsistencyLastAt_{0};
		    std::string naanScoreStatePath_{};
		    std::string naanScoreDecayStatePath_{};
		    std::atomic<uint64_t> naanScoreLastDecayTs_{0};
		    std::atomic<uint64_t> naanScoreLastViolationTick_{0};
		    std::atomic<uint8_t> naanLastScoreBand_{0};
		    std::atomic<uint64_t> naanScoreBandTransitions_{0};
		    std::atomic<uint64_t> naanQuarantineRecoveryTransitions_{0};
		    std::atomic<uint64_t> naanQuarantineRecoveryLastAt_{0};
		    std::atomic<uint32_t> naanScoreDecayIntervalSeconds_{60};
		    std::atomic<uint32_t> naanAbuseSpamPenalty_{1};
		    std::atomic<uint32_t> naanAbuseCitationPenalty_{1};
		    std::atomic<uint32_t> naanAbusePolicyPenalty_{2};
		    core::AgentIdentity attachedAgentIdentity_{};
		    std::atomic<uint64_t> naanTickCount_{0};
		    std::atomic<uint64_t> naanTaskResearchRuns_{0};
		    std::atomic<uint64_t> naanTaskVerifyRuns_{0};
		    std::atomic<uint64_t> naanTaskReviewRuns_{0};
		    std::atomic<uint64_t> naanTaskDraftRuns_{0};
		    std::atomic<uint64_t> naanTaskSubmitRuns_{0};
		    std::atomic<uint64_t> naanPipelineRuns_{0};
		    std::atomic<uint64_t> naanPipelineApproved_{0};
		    std::atomic<uint64_t> naanPipelineSubmitted_{0};
		    std::atomic<uint64_t> naanPipelineRejected_{0};
		    std::atomic<uint64_t> naanLastPipelineTs_{0};
		    std::mutex naanPipelineMtx_;
		    std::atomic<uint64_t> naanLastActionTs_{0};
		    std::atomic<uint64_t> naanLastResearchTs_{0};
		    std::atomic<uint64_t> naanLastVerifyTs_{0};
		    std::atomic<uint64_t> naanLastReviewTs_{0};
		    std::atomic<uint64_t> naanLastHeartbeatTs_{0};
		    std::atomic<uint64_t> naanLastDraftTs_{0};
		    web::ConnectorAbuseGuard naanConnectorAbuseGuard_{};
		    std::atomic<uint64_t> naanConnectorAbuseEvents_{0};
		    std::atomic<uint64_t> naanConnectorAbuseLastAt_{0};
            std::atomic<uint64_t> naanConnectorAbuseLastPolicyDelta_{0};
            std::atomic<uint64_t> naanConnectorAbuseLastFailureDelta_{0};
            std::atomic<uint32_t> naanConnectorAbuseLastViolations_{0};
            struct NaanWebResearchSnapshot {
                uint64_t lastSearchAt = 0;
                std::string query;
                std::string queryType;
                uint64_t resultCount = 0;
                uint64_t clearnetResults = 0;
                uint64_t onionResults = 0;
                std::string topSites;
                bool saved = false;
                std::string skipReason;
                std::string error;
            };
            std::mutex naanWebResearchMtx_;
            NaanWebResearchSnapshot naanWebResearchSnapshot_{};
            std::atomic<bool> agentTorRequired_{true};
            std::atomic<bool> agentTorReachable_{false};
            std::atomic<bool> agentTorWebReady_{false};
            std::atomic<bool> agentTorWebProbeInFlight_{false};
            std::atomic<bool> agentTorManaged_{false};
            std::atomic<bool> agentTorManagedRestartInFlight_{false};
            std::atomic<bool> agentTorDegraded_{false};
            std::atomic<uint32_t> agentTorBootstrapPercent_{0};
            std::atomic<bool> agentTorOnionReady_{false};
            std::atomic<int64_t> managedTorPid_{0};
            std::atomic<uint64_t> agentTorManagedRestartLastAttemptAt_{0};
            std::atomic<uint64_t> agentTorManagedRestartNextAllowedAt_{0};
            std::atomic<uint32_t> agentTorManagedRestartConsecutiveFailures_{0};
            std::atomic<uint64_t> agentTorManagedRestartBackoffSkips_{0};
            std::atomic<int> agentTorWebProbeExitCode_{-1};
            std::atomic<uint64_t> agentTorWebProbeLastAt_{0};
            std::atomic<uint64_t> agentTorWebProbeLastOkAt_{0};
            std::atomic<uint32_t> agentTorWebProbeConsecutiveFailures_{0};
            std::atomic<uint32_t> agentTorWebProbeConsecutiveSuccesses_{0};
            std::atomic<uint64_t> agentTorWebProbeUrlRotation_{0};
            std::atomic<uint64_t> agentTorBridgeSubsetPersistCount_{0};
            std::atomic<uint64_t> agentTorBridgeSubsetLastPersistAt_{0};
            std::atomic<uint64_t> agentTorBridgeSubsetLastEpoch_{0};
            std::atomic<uint32_t> agentTorBridgeSubsetLastCount_{0};
            std::atomic<uint64_t> agentTorBridgeRemoteLastFetchAt_{0};
            std::atomic<uint64_t> agentTorBridgeRemoteFetchAttempts_{0};
            std::atomic<uint64_t> agentTorBridgeRemoteFetchSuccesses_{0};
            std::atomic<uint64_t> agentTorBridgeRemoteRateLimitedSkips_{0};
            mutable std::mutex agentTorWebProbeMtx_;
            std::string agentTorWebProbeLastError_;
            mutable std::mutex agentTorReadinessMtx_;
            std::string agentTorReadinessState_;
            std::string agentTorBootstrapReasonCode_;
		    std::atomic<bool> agentAllowClearnetFallback_{false};
		    std::atomic<bool> agentAllowP2PFallback_{false};
            std::atomic<bool> miningActive_{false};
            std::atomic<uint64_t> miningHashAttemptsTotal_{0};
            std::atomic<uint64_t> miningHashAttemptsLast_{0};
            std::atomic<uint64_t> miningLastSolvedAt_{0};
            std::atomic<uint32_t> miningWorkTargetBits_{0};
            std::atomic<uint64_t> miningFailClosedSkips_{0};
            std::atomic<uint64_t> naanWebFailClosedSkips_{0};
            std::atomic<uint64_t> naanWebConfigSanitizedWrites_{0};
            std::atomic<uint64_t> naanWebConfigTotalLines_{0};
            std::atomic<uint64_t> naanWebConfigAppliedLines_{0};
            std::atomic<uint64_t> naanWebConfigInvalidLines_{0};
            std::atomic<uint64_t> naanWebConfigUnknownKeys_{0};
            crypto::Hash256 miningCandidateHash_{};
            mutable std::mutex miningStateMtx_;
            std::atomic<uint64_t> naanRedactionCount_{0};
            std::deque<NaanUiEvent> naanUiEvents_{};
            mutable std::mutex naanUiEventsMtx_;
		    core::UpdateInstaller updateInstaller_;
		    core::ImplantSafetyPipeline implantSafetyPipeline_;
		    core::ImplantCompatibilityPolicy implantCompatibilityPolicy_{};
		    core::ImplantUpdateGovernancePolicy implantUpdatePolicy_{};
		    std::mutex implantPolicyMtx_;
		    std::mutex implantSafetyMtx_;
		    std::mutex updateInstallMtx_;
		    std::mutex invMtx_;
		    std::mutex poeSyncMtx_;
		    std::unordered_map<std::string, PoePeerSyncState> poeSync_;
	    std::unordered_map<uint64_t, uint64_t> requestedBlocks_;
	    std::mutex syncMtx_;
    std::atomic<uint64_t> networkHeight_{0};
    std::atomic<bool> syncing_{false};
    std::atomic<bool> suppressCallbacks_{false};
    std::atomic<uint64_t> autoPoeEpochLastRunAt_{0};
    std::atomic<uint64_t> autoPoeEpochLastFinalizedCount_{0};

        // Remote model routing (opt-in)
        std::mutex remoteMtx_;
        std::condition_variable remoteCv_;
        std::unordered_map<std::string, RemoteOfferCache> remoteOffers_;            // offerId -> offer
        std::unordered_map<std::string, RemoteSessionInfo> remoteSessions_;        // sessionId -> session
        std::unordered_map<std::string, RemotePending> remotePending_;             // requestId -> result
        std::unordered_map<std::string, synapse::RemoteModelRentOkMessage> remoteRentOkByOffer_; // offerId -> ok

        std::mutex remoteProvMtx_;
        std::string localOfferId_;
        uint64_t remotePricePerRequestAtoms_ = 0;
        std::unordered_map<std::string, ProviderSession> providerSessions_;        // sessionId -> session
    
    std::thread networkThread_;
    std::thread consensusThread_;
    std::thread maintenanceThread_;
    std::thread syncThread_;
};

static SynapseNet* g_node = nullptr;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM || (!g_daemonMode && signal == SIGHUP)) {
        if (g_node) g_node->shutdown();
        g_running = false;
    } else if (signal == SIGHUP) {
        g_reloadConfig = true;
    }
}

void printBanner() {
    std::cout << R"(
  ____                              _   _      _   
 / ___| _   _ _ __   __ _ _ __  ___| \ | | ___| |_ 
 \___ \| | | | '_ \ / _` | '_ \/ __|  \| |/ _ \ __|
  ___) | |_| | | | | (_| | |_) \__ \ |\  |  __/ |_ 
 |____/ \__, |_| |_|\__,_| .__/|___/_| \_|\___|\__|
        |___/            |_|                       
)" << std::endl;
    std::cout << "  Decentralized AI Knowledge Network v0.1.0" << std::endl;
    std::cout << "  ==========================================" << std::endl;
    std::cout << std::endl;
}

void printHelp(const char* progName) {
    std::cout << "SynapseNet v0.1.0 - Decentralized Knowledge Network\n\n";
    std::cout << "Usage: " << progName << " [command] [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  (none)              Start node with TUI\n";
    std::cout << "  status              Show node status\n";
    std::cout << "  peers               List connected peers\n";
    std::cout << "  submit <file>       Contribute knowledge\n";
    std::cout << "  send <addr> <amt>   Transfer NGT\n";
    std::cout << "  query <text>        Search knowledge network\n";
    std::cout << "  balance             Show wallet balance\n";
    std::cout << "  address             Show wallet address\n";
    std::cout << "  naan                Show NAAN runtime/observatory data\n";
    std::cout << "  logs                Show recent activity\n";
    std::cout << "  seeds               Show bootstrap/DNS seeds\n";
    std::cout << "  discovery           Show discovery diagnostics\n";
    std::cout << "\nNGT policy:\n";
    std::cout << "  NGT cannot be purchased in-protocol.\n";
    std::cout << "  NGT is earned by protocol outcomes or transferred between addresses.\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -h, --help          Show this help\n";
    std::cout << "  -v, --version       Show version\n";
    std::cout << "  -d, --daemon        Run as daemon (no TUI)\n";
    std::cout << "  -c, --config FILE   Use custom config file\n";
    std::cout << "  -D, --datadir DIR   Data directory\n";
    std::cout << "  -p, --port PORT     P2P port (default: 8333)\n";
    std::cout << "  -r, --rpcport PORT  RPC port (default: 8332)\n";
    std::cout << "  --testnet           Connect to testnet\n";
    std::cout << "  --regtest           Run in regression test mode\n";
    std::cout << "  --privacy           Enable privacy mode (Tor)\n";
    std::cout << "  --amnesia           RAM-only mode, zero traces\n";
    std::cout << "  --dev               Developer mode (fast PoE params)\n";
    std::cout << "  --reset-ngt         Clear all NGT balances (transfer DB)\n";
    std::cout << "  --poe-validators X  Comma-separated validator pubkeys (hex)\n";
    std::cout << "  --poe-validator-mode MODE  Validator mode: static|stake (default: static)\n";
    std::cout << "  --poe-min-stake NGT         Minimum stake for stake-mode validators (default: 0)\n";
    std::cout << "  --quantum           Enable quantum security\n";
    std::cout << "  --security LEVEL    Security level (standard/high/paranoid/quantum-ready)\n";
    std::cout << "  --connect HOST:PORT Connect to specific node\n";
    std::cout << "  --addnode HOST:PORT Add node to connection list\n";
    std::cout << "  --seednode HOST:PORT Add seed node\n";
    std::cout << "  --maxpeers N        Maximum peer connections\n";
    std::cout << "  --dbcache N         Database cache size in MB\n";
    std::cout << "  --loglevel LEVEL    Log level (debug/info/warn/error)\n";
}

void printVersion() {
    std::cout << "SynapseNet v0.1.0-beta\n";
    std::cout << "Protocol version: 1\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Crypto: Built-in implementation\n";
}

static bool rpcHttpPost(uint16_t port, const std::string& body, std::string& responseBodyOut, std::string& errorOut, int timeoutSeconds) {
    responseBodyOut.clear();
    errorOut.clear();

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        errorOut = "socket() failed";
        return false;
    }

    struct timeval tv;
    tv.tv_sec = timeoutSeconds;
    tv.tv_usec = 0;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(sock);
        errorOut = "connect() failed";
        return false;
    }

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n";
    req << "Host: 127.0.0.1\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";
    req << body;
    std::string reqStr = req.str();

    size_t sent = 0;
    while (sent < reqStr.size()) {
        ssize_t n = ::send(sock, reqStr.data() + sent, reqStr.size() - sent, 0);
        if (n <= 0) {
            ::close(sock);
            errorOut = "send() failed";
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    resp.reserve(8192);
    char buf[4096];
    while (true) {
        ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, buf + n);
        if (resp.size() > 8 * 1024 * 1024) {
            ::close(sock);
            errorOut = "response too large";
            return false;
        }
        size_t headerEnd = resp.find("\r\n\r\n");
        if (headerEnd == std::string::npos) continue;

        size_t clPos = resp.find("Content-Length:");
        if (clPos == std::string::npos) continue;
        size_t clEnd = resp.find("\r\n", clPos);
        if (clEnd == std::string::npos) continue;
        std::string clStr = resp.substr(clPos + 15, clEnd - (clPos + 15));
        size_t contentLength = 0;
        try {
            contentLength = static_cast<size_t>(std::stoul(clStr));
        } catch (...) {
            ::close(sock);
            errorOut = "invalid Content-Length";
            return false;
        }

        size_t bodyStart = headerEnd + 4;
        if (resp.size() >= bodyStart + contentLength) {
            responseBodyOut = resp.substr(bodyStart, contentLength);
            ::close(sock);
            return true;
        }
    }

    ::close(sock);
    errorOut = "no response";
    return false;
}

static bool rpcCall(uint16_t port, const std::string& method, const json& params, json& resultOut, std::string& errorOut, int timeoutSeconds) {
    json req;
    req["jsonrpc"] = "2.0";
    req["id"] = 1;
    req["method"] = method;
    req["params"] = params;

    std::string respBody;
    if (!rpcHttpPost(port, req.dump(), respBody, errorOut, timeoutSeconds)) {
        return false;
    }

    json resp;
    try {
        resp = json::parse(respBody);
    } catch (const std::exception& e) {
        errorOut = std::string("invalid JSON response: ") + e.what();
        return false;
    }

    if (resp.contains("error") && !resp["error"].is_null()) {
        try {
            int code = resp["error"].value("code", -1);
            std::string msg = resp["error"].value("message", "RPC error");
            errorOut = "rpc_error(" + std::to_string(code) + "): " + msg;
        } catch (...) {
            errorOut = "rpc_error";
        }
        return false;
    }
    if (!resp.contains("result")) {
        errorOut = "missing result field";
        return false;
    }
    resultOut = resp["result"];
    return true;
}

static bool isRpcTransportError(const std::string& err) {
    if (err == "socket() failed" || err == "connect() failed" || err == "send() failed" || err == "no response") {
        return true;
    }
    if (err.rfind("invalid JSON response:", 0) == 0) {
        return true;
    }
    return err == "missing result field";
}

static std::optional<int> runCliViaRpc(const NodeConfig& config) {
    if (config.commandArgs.empty()) return 0;

    const std::string cmd = config.commandArgs[0];
    const uint16_t rpcPort = config.rpcPort;

    auto call = [&](const std::string& method, const json& params, json& out, std::string& errOut) -> bool {
        errOut.clear();
        bool longOp = false;
        if (method.rfind("ai.", 0) == 0) longOp = true;
        if (method.rfind("poe.", 0) == 0) longOp = true;
        if (method == "model.load") longOp = true;
        if (method == "naan.pipeline.drain") longOp = true;
        if (method == "node.tor.control") longOp = true;
        int timeoutSeconds = longOp ? 300 : 3;
        return rpcCall(rpcPort, method, params, out, errOut, timeoutSeconds);
    };

    if (cmd == "address") {
        json out;
        std::string err;
        if (!call("wallet.address", json::object(), out, err)) {
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << out.value("address", "") << "\n";
        return 0;
    }

    if (cmd == "balance") {
        json out;
        std::string err;
        if (!call("wallet.balance", json::object(), out, err)) {
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << "address=" << out.value("address", "") << "\n";
        std::cout << "balance=" << std::fixed << std::setprecision(8) << out.value("balance", 0.0) << " NGT\n";
        return 0;
    }

    if (cmd == "naan") {
        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
            std::cout << "Usage:\n";
            std::cout << "  synapsed naan status\n";
            std::cout << "  synapsed naan artifacts [--since TIMESTAMP] [--limit N]\n";
            std::cout << "  synapsed naan artifact <hashHex>\n";
            std::cout << "  synapsed naan drafts [--status S] [--limit N] [--include-rejected 0|1]\n";
            std::cout << "  synapsed naan draft <draftIdHex>\n";
            std::cout << "  synapsed naan dryrun [--limit N]\n";
            std::cout << "  synapsed naan drain [--limit N]\n";
            return 0;
        }

        const std::string sub = config.commandArgs[1];
        if (sub == "status") {
            json out;
            std::string err;
            if (!call("naan.status", json::object(), out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (sub == "artifacts") {
            json params = json::object();
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--since" && i + 1 < config.commandArgs.size()) {
                    params["since"] = std::stoll(config.commandArgs[i + 1]);
                    i++;
                } else if (config.commandArgs[i] == "--limit" && i + 1 < config.commandArgs.size()) {
                    params["limit"] = std::stoi(config.commandArgs[i + 1]);
                    i++;
                }
            }

            json out;
            std::string err;
            if (!call("naan.observatory.artifacts", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (sub == "artifact") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed naan artifact <hashHex>\n";
                return 1;
            }
            json params;
            params["hash"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("naan.observatory.artifact.get", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (sub == "drafts") {
            json params = json::object();
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--status" && i + 1 < config.commandArgs.size()) {
                    params["status"] = config.commandArgs[i + 1];
                    i++;
                } else if (config.commandArgs[i] == "--limit" && i + 1 < config.commandArgs.size()) {
                    params["limit"] = std::stoi(config.commandArgs[i + 1]);
                    i++;
                } else if (config.commandArgs[i] == "--include-rejected" && i + 1 < config.commandArgs.size()) {
                    params["includeRejected"] = (std::stoi(config.commandArgs[i + 1]) != 0);
                    i++;
                }
            }

            json out;
            std::string err;
            if (!call("naan.observatory.drafts", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (sub == "draft") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed naan draft <draftIdHex>\n";
                return 1;
            }
            json params;
            params["draftId"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("naan.observatory.draft.get", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (sub == "dryrun") {
            json params = json::object();
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--limit" && i + 1 < config.commandArgs.size()) {
                    params["limit"] = std::stoi(config.commandArgs[i + 1]);
                    i++;
                }
            }

            json out;
            std::string err;
            if (!call("naan.pipeline.dryrun", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (sub == "drain") {
            json params = json::object();
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--limit" && i + 1 < config.commandArgs.size()) {
                    params["limit"] = std::stoi(config.commandArgs[i + 1]);
                    i++;
                }
            }

            json out;
            std::string err;
            if (!call("naan.pipeline.drain", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        std::cerr << "Unknown naan subcommand: " << sub << "\n";
        return 1;
    }

    if (cmd == "tor") {
        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
            std::cout << "Usage:\n";
            std::cout << "  synapsed tor status\n";
            std::cout << "  synapsed tor refresh-bridges [--persist-sanitized 0|1]\n";
            std::cout << "  synapsed tor restart-managed [--reload-web 0|1]\n";
            std::cout << "  synapsed tor mode <auto|external|managed> [--socks-host H] [--socks-port N] [--control-port N] [--persist 0|1] [--reload-web 0|1]\n";
            return 0;
        }

        const std::string sub = config.commandArgs[1];
        if (sub == "status") {
            json out;
            std::string err;
            if (!call("node.status", json::object(), out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            json tor;
            tor["torRuntimeMode"] = out.value("torRuntimeMode", "");
            tor["torSocksHost"] = out.value("torSocksHost", "127.0.0.1");
            tor["torSocksPort"] = out.value("torSocksPort", 0);
            tor["torControlPort"] = out.value("torControlPort", 0);
            tor["torControlReachable"] = out.value("torControlReachable", false);
            tor["torSocksReachable"] = out.value("torSocksReachable", false);
            tor["torReadyForWeb"] = out.value("torReadyForWeb", false);
            tor["torReadyForOnion"] = out.value("torReadyForOnion", false);
            tor["torReadyForOnionService"] = out.value("torReadyForOnionService", false);
            tor["torOnionServiceActive"] = out.value("torOnionServiceActive", false);
            tor["torOnionServiceState"] = out.value("torOnionServiceState", "");
            tor["torDegraded"] = out.value("torDegraded", false);
            tor["torManagedPid"] = out.value("torManagedPid", 0);
            tor["torBootstrapState"] = out.value("torBootstrapState", "");
            tor["torBootstrapPercent"] = out.value("torBootstrapPercent", 0);
            tor["torBootstrapReasonCode"] = out.value("torBootstrapReasonCode", "");
            tor["torConflictHint9050"] = out.value("torConflictHint9050", false);
            tor["torBridgeProviderUpdatedAt"] = out.value("torBridgeProviderUpdatedAt", static_cast<uint64_t>(0));
            tor["torBridgeCacheAgeSeconds"] = out.value("torBridgeCacheAgeSeconds", static_cast<uint64_t>(0));
            tor["torBridgeProvider"] = out.value("torBridgeProvider", json::object());
            tor["routeMode"] = out.value("routeMode", "");
            std::cout << tor.dump(2) << "\n";
            return 0;
        }

        json params = json::object();
        if (sub == "refresh" || sub == "refresh-bridges") {
            params["action"] = "refresh_bridges";
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--persist-sanitized" && i + 1 < config.commandArgs.size()) {
                    params["persistSanitized"] = (std::stoi(config.commandArgs[i + 1]) != 0);
                    i++;
                }
            }
        } else if (sub == "restart" || sub == "restart-managed") {
            params["action"] = "restart_managed_tor";
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if ((config.commandArgs[i] == "--reload-web" || config.commandArgs[i] == "--reload-web-config") &&
                    i + 1 < config.commandArgs.size()) {
                    params["reloadWebConfig"] = (std::stoi(config.commandArgs[i + 1]) != 0);
                    i++;
                }
            }
        } else if (sub == "mode") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed tor mode <auto|external|managed> [--socks-host H] [--socks-port N] [--control-port N] [--persist 0|1] [--reload-web 0|1]\n";
                return 1;
            }
            params["action"] = "switch_mode";
            params["mode"] = config.commandArgs[2];
            for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--socks-host" && i + 1 < config.commandArgs.size()) {
                    params["socksHost"] = config.commandArgs[i + 1];
                    i++;
                } else if (config.commandArgs[i] == "--socks-port" && i + 1 < config.commandArgs.size()) {
                    params["socksPort"] = std::stoi(config.commandArgs[i + 1]);
                    i++;
                } else if (config.commandArgs[i] == "--control-port" && i + 1 < config.commandArgs.size()) {
                    params["controlPort"] = std::stoi(config.commandArgs[i + 1]);
                    i++;
                } else if (config.commandArgs[i] == "--persist" && i + 1 < config.commandArgs.size()) {
                    params["persist"] = (std::stoi(config.commandArgs[i + 1]) != 0);
                    i++;
                } else if ((config.commandArgs[i] == "--reload-web" || config.commandArgs[i] == "--reload-web-config") &&
                           i + 1 < config.commandArgs.size()) {
                    params["reloadWebConfig"] = (std::stoi(config.commandArgs[i + 1]) != 0);
                    i++;
                }
            }
        } else {
            std::cerr << "Unknown tor subcommand: " << sub << "\n";
            return 1;
        }

        json out;
        std::string err;
        if (!call("node.tor.control", params, out, err)) {
            if (isRpcTransportError(err)) return std::nullopt;
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << out.dump(2) << "\n";
        return 0;
    }

    if (cmd == "poe") {
	        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed poe submit --question Q --answer A [--source S]\n";
	            std::cout << "  synapsed poe submit-code --title T (--patch P | --patch-file PATH)\n";
	            std::cout << "  synapsed poe list-code [--limit N]\n";
	            std::cout << "  synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	            std::cout << "  synapsed poe vote <submitIdHex>\n";
	            std::cout << "  synapsed poe finalize <submitIdHex>\n";
	            std::cout << "  synapsed poe epoch [--budget NGT] [--iters N]\n";
	            std::cout << "  synapsed poe export <path>\n";
            std::cout << "  synapsed poe import <path>\n";
            std::cout << "  synapsed poe pubkey\n";
            std::cout << "  synapsed poe validators\n";
            return 0;
        }

        const std::string sub = config.commandArgs[1];

        if (sub == "pubkey") {
            json out;
            std::string err;
            if (!call("wallet.address", json::object(), out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.value("pubkey", "") << "\n";
            return 0;
        }

        if (sub == "validators") {
            json out;
            std::string err;
            if (!call("poe.validators", json::object(), out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            if (out.is_array()) {
                for (const auto& v : out) {
                    if (v.is_string()) std::cout << v.get<std::string>() << "\n";
                }
                if (out.empty()) std::cout << "(none)\n";
            } else {
                std::cout << "(none)\n";
            }
            return 0;
        }

	        if (sub == "submit") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i].rfind("--", 0) != 0) continue;
                std::string k = config.commandArgs[i].substr(2);
                std::string v;
                if (i + 1 < config.commandArgs.size() && config.commandArgs[i + 1].rfind("--", 0) != 0) {
                    v = config.commandArgs[i + 1];
                    i++;
                }
                opts[k] = v;
            }

            std::string q = opts["question"];
            std::string a = opts["answer"];
            std::string s = opts["source"];
            if (q.empty() || a.empty()) {
                std::cerr << "Missing --question/--answer\n";
                return 1;
            }

            json params;
            params["question"] = q;
            params["answer"] = a;
            if (!s.empty()) params["source"] = s;
            params["auto_finalize"] = true;

            json out;
            std::string err;
            if (!call("poe.submit", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << "submitId=" << out.value("submitId", "") << "\n";
            std::cout << "contentId=" << out.value("contentId", "") << "\n";
            double credited = out.value("credited", 0.0);
            if (credited > 0.0) {
                std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
            } else {
                std::cout << "acceptanceReward=0.00000000 NGT\n";
            }
	            return 0;
	        }

	        if (sub == "submit-code") {
	            std::unordered_map<std::string, std::string> opts;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i].rfind("--", 0) != 0) continue;
	                std::string k = config.commandArgs[i].substr(2);
	                std::string v;
	                if (i + 1 < config.commandArgs.size() && config.commandArgs[i + 1].rfind("--", 0) != 0) {
	                    v = config.commandArgs[i + 1];
	                    i++;
	                }
	                opts[k] = v;
	            }

	            std::string title = opts["title"];
	            std::string patch = opts["patch"];
	            std::string patchFile = opts["patch-file"];
	            if (patch.empty() && !patchFile.empty()) {
	                std::ifstream in(patchFile, std::ios::binary);
	                if (!in) {
	                    std::cerr << "Failed to read --patch-file\n";
	                    return 1;
	                }
	                std::ostringstream ss;
	                ss << in.rdbuf();
	                patch = ss.str();
	            }

	            if (title.empty() || patch.empty()) {
	                std::cerr << "Missing --title and --patch/--patch-file\n";
	                return 1;
	            }

	            json params;
	            params["title"] = title;
	            params["patch"] = patch;
	            std::string cites = opts["citations"];
	            if (!cites.empty()) {
	                for (char& c : cites) if (c == ';') c = ',';
	                json arr = json::array();
	                std::string cur;
	                for (size_t i = 0; i <= cites.size(); ++i) {
	                    if (i == cites.size() || cites[i] == ',') {
	                        std::string t = cur;
	                        auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.front()))) t.erase(t.begin());
	                        while (!t.empty() && isSpace(static_cast<unsigned char>(t.back()))) t.pop_back();
	                        if (!t.empty()) arr.push_back(t);
	                        cur.clear();
	                    } else {
	                        cur.push_back(cites[i]);
	                    }
	                }
	                if (!arr.empty()) params["citations"] = arr;
	            }
	            params["auto_finalize"] = true;

	            json out;
	            std::string err;
	            if (!call("poe.submit_code", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << "submitId=" << out.value("submitId", "") << "\n";
	            std::cout << "contentId=" << out.value("contentId", "") << "\n";
	            double credited = out.value("credited", 0.0);
	            if (credited > 0.0) {
	                std::cout << "acceptanceReward=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
	            } else {
	                std::cout << "acceptanceReward=0.00000000 NGT\n";
	            }
	            return 0;
	        }

	        if (sub == "list-code") {
	            size_t limit = 25;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i] == "--limit" && i + 1 < config.commandArgs.size()) {
	                    limit = static_cast<size_t>(std::max(1, std::stoi(config.commandArgs[i + 1])));
	                    i++;
	                }
	            }
	            json params;
	            params["limit"] = limit;
	            json out;
	            std::string err;
	            if (!call("poe.list_code", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            if (!out.is_array() || out.empty()) {
	                std::cout << "(none)\n";
	                return 0;
	            }
	            for (const auto& item : out) {
	                std::string sid = item.value("submitId", "");
	                std::string title = item.value("title", "");
	                if (!sid.empty()) std::cout << sid << "  " << title << "\n";
	            }
	            return 0;
	        }

	        if (sub == "fetch-code") {
	            if (config.commandArgs.size() < 3) {
	                std::cerr << "Usage: synapsed poe fetch-code <submitIdHex|contentIdHex>\n";
	                return 1;
	            }
	            json params;
	            params["id"] = config.commandArgs[2];
	            json out;
	            std::string err;
	            if (!call("poe.fetch_code", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << "submitId=" << out.value("submitId", "") << "\n";
	            std::cout << "contentId=" << out.value("contentId", "") << "\n";
	            std::cout << "timestamp=" << out.value("timestamp", 0) << "\n";
	            std::cout << "title=" << out.value("title", "") << "\n";
	            std::cout << "finalized=" << (out.value("finalized", false) ? "true" : "false") << "\n";
	            std::cout << "patch:\n";
	            std::cout << out.value("patch", "") << "\n";
	            return 0;
	        }

	        if (sub == "vote") {
	            if (config.commandArgs.size() < 3) {
	                std::cerr << "Usage: synapsed poe vote <submitIdHex>\n";
	                return 1;
            }
            json params;
            params["submitId"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.vote", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::string status = out.value("status", "");
            bool added = out.value("added", false);
            if (!status.empty()) std::cout << status << "\n";
            double credited = out.value("credited", 0.0);
            if (credited > 0.0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
            }
            return added ? 0 : 1;
        }

        if (sub == "finalize") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed poe finalize <submitIdHex>\n";
                return 1;
            }
            json params;
            params["submitId"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.finalize", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            bool finalized = out.value("finalized", false);
            if (!finalized) {
                std::cerr << "not_finalized\n";
                return 1;
            }
            std::cout << "finalized\n";
            double credited = out.value("credited", 0.0);
            if (credited > 0.0) {
                std::cout << "credited=" << std::fixed << std::setprecision(8) << credited << " NGT\n";
            }
            return 0;
        }

        if (sub == "epoch") {
            auto parseNgtAtomic = [](const std::string& s, uint64_t& out) -> bool {
                if (s.empty()) return false;
                std::string t = s;
                for (auto& c : t) if (c == ',') c = '.';
                size_t dot = t.find('.');
                std::string intPart = dot == std::string::npos ? t : t.substr(0, dot);
                std::string fracPart = dot == std::string::npos ? "" : t.substr(dot + 1);
                if (intPart.empty()) intPart = "0";
                if (fracPart.size() > 8) return false;
                for (char c : intPart) if (c < '0' || c > '9') return false;
                for (char c : fracPart) if (c < '0' || c > '9') return false;
                unsigned __int128 iv = 0;
                for (char c : intPart) iv = iv * 10 + static_cast<unsigned>(c - '0');
                unsigned __int128 fv = 0;
                for (char c : fracPart) fv = fv * 10 + static_cast<unsigned>(c - '0');
                for (size_t i = fracPart.size(); i < 8; ++i) fv *= 10;
                unsigned __int128 total = iv * 100000000ULL + fv;
                if (total > std::numeric_limits<uint64_t>::max()) return false;
                out = static_cast<uint64_t>(total);
                return true;
            };

            uint64_t budgetAtoms = 0;
            uint32_t iters = 20;
            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
                if (config.commandArgs[i] == "--budget" && i + 1 < config.commandArgs.size()) {
                    uint64_t v = 0;
                    if (!parseNgtAtomic(config.commandArgs[i + 1], v)) {
                        std::cerr << "Invalid --budget\n";
                        return 1;
                    }
                    budgetAtoms = v;
                    i++;
                } else if (config.commandArgs[i] == "--iters" && i + 1 < config.commandArgs.size()) {
                    iters = static_cast<uint32_t>(std::max(1, std::stoi(config.commandArgs[i + 1])));
                    i++;
                }
            }

            json params;
            if (budgetAtoms > 0) params["budget_atoms"] = budgetAtoms;
            params["iters"] = iters;
            json out;
            std::string err;
            if (!call("poe.epoch", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << "epochId=" << out.value("epochId", 0) << "\n";
            std::cout << "allocationHash=" << out.value("allocationHash", "") << "\n";
            std::cout << "minted=" << std::fixed << std::setprecision(8) << out.value("minted", 0.0) << " NGT\n";
            std::cout << "mintedEntries=" << out.value("mintedEntries", 0) << "\n";
            double you = out.value("youEarned", 0.0);
            if (you > 0.0) {
                std::cout << "youEarned=" << std::fixed << std::setprecision(8) << you << " NGT\n";
            }
            return 0;
        }

        if (sub == "export") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed poe export <path>\n";
                return 1;
            }
            json params;
            params["path"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.export", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump() << "\n";
            return 0;
        }

        if (sub == "import") {
            if (config.commandArgs.size() < 3) {
                std::cerr << "Usage: synapsed poe import <path>\n";
                return 1;
            }
            json params;
            params["path"] = config.commandArgs[2];
            json out;
            std::string err;
            if (!call("poe.import", params, out, err)) {
                if (isRpcTransportError(err)) return std::nullopt;
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump() << "\n";
            return 0;
        }

	        std::cerr << "Unknown poe subcommand: " << sub << "\n";
	        return 1;
	    }

	    if (cmd == "model") {
	        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed model status\n";
	            std::cout << "  synapsed model list [--dir PATH]\n";
	            std::cout << "  synapsed model load (--path PATH | --name FILENAME)\n";
	            std::cout << "    [--context N] [--threads N] [--gpu-layers N] [--use-gpu 0|1] [--mmap 0|1]\n";
	            std::cout << "  synapsed model unload\n";
                std::cout << "  synapsed model access get\n";
                std::cout << "  synapsed model access set --mode (PRIVATE|SHARED|PAID|COMMUNITY) [--max-slots N]\n";
                std::cout << "    [--price-per-hour-atoms N] [--price-per-request-atoms N]\n";
                std::cout << "  synapsed model remote list\n";
                std::cout << "  synapsed model remote rent --offer OFFER_ID\n";
                std::cout << "  synapsed model remote end --session SESSION_ID\n";
	            return 0;
	        }

	        const std::string sub = config.commandArgs[1];

	        if (sub == "status") {
	            json out;
	            std::string err;
	            if (!call("model.status", json::object(), out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

		        if (sub == "list") {
		            json params = json::object();
		            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
		                if (config.commandArgs[i] == "--dir" && i + 1 < config.commandArgs.size()) {
		                    params["dir"] = config.commandArgs[i + 1];
		                    i++;
		                }
	            }
	            json out;
	            std::string err;
	            if (!call("model.list", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

		        if (sub == "load") {
		            json params = json::object();
		            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
		                if (config.commandArgs[i] == "--path" && i + 1 < config.commandArgs.size()) {
		                    params["path"] = config.commandArgs[i + 1];
		                    i++;
	                } else if (config.commandArgs[i] == "--name" && i + 1 < config.commandArgs.size()) {
	                    params["name"] = config.commandArgs[i + 1];
	                    i++;
	                } else if (config.commandArgs[i] == "--context" && i + 1 < config.commandArgs.size()) {
	                    params["contextSize"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--threads" && i + 1 < config.commandArgs.size()) {
	                    params["threads"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--gpu-layers" && i + 1 < config.commandArgs.size()) {
	                    params["gpuLayers"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--use-gpu" && i + 1 < config.commandArgs.size()) {
	                    params["useGpu"] = (std::stoi(config.commandArgs[i + 1]) != 0);
	                    i++;
	                } else if (config.commandArgs[i] == "--mmap" && i + 1 < config.commandArgs.size()) {
	                    params["useMmap"] = (std::stoi(config.commandArgs[i + 1]) != 0);
	                    i++;
	                }
	            }
	            json out;
	            std::string err;
	            if (!call("model.load", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return out.value("ok", false) ? 0 : 1;
	        }

	        if (sub == "unload") {
	            json out;
	            std::string err;
	            if (!call("model.unload", json::object(), out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return out.value("ok", false) ? 0 : 1;
	        }

            // Convenience shortcuts (align with interface spec).
            if (sub == "private" || sub == "shared" || sub == "paid" || sub == "community") {
                json params = json::object();
                params["mode"] = sub;
                json out;
                std::string err;
                if (!call("model.access.set", params, out, err)) {
                    if (isRpcTransportError(err)) return std::nullopt;
                    std::cerr << "RPC failed: " << err << "\n";
                    return 1;
                }
                std::cout << out.dump(2) << "\n";
                return 0;
            }

            if (sub == "price") {
                if (config.commandArgs.size() < 3) {
                    std::cerr << "Usage: synapsed model price <pricePerHourAtoms>\n";
                    return 1;
                }
                json params = json::object();
                params["pricePerHourAtoms"] = std::stoll(config.commandArgs[2]);
                json out;
                std::string err;
                if (!call("model.access.set", params, out, err)) {
                    if (isRpcTransportError(err)) return std::nullopt;
                    std::cerr << "RPC failed: " << err << "\n";
                    return 1;
                }
                std::cout << out.dump(2) << "\n";
                return 0;
            }

            if (sub == "slots") {
                if (config.commandArgs.size() < 3) {
                    std::cerr << "Usage: synapsed model slots <maxSlots>\n";
                    return 1;
                }
                json params = json::object();
                params["maxSlots"] = std::stoll(config.commandArgs[2]);
                json out;
                std::string err;
                if (!call("model.access.set", params, out, err)) {
                    if (isRpcTransportError(err)) return std::nullopt;
                    std::cerr << "RPC failed: " << err << "\n";
                    return 1;
                }
                std::cout << out.dump(2) << "\n";
                return 0;
            }

            if (sub == "access") {
                const std::string sub2 = (config.commandArgs.size() >= 3) ? config.commandArgs[2] : "help";
                if (sub2 == "get") {
                    json out;
                    std::string err;
                    if (!call("model.access.get", json::object(), out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "set") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--mode" && i + 1 < config.commandArgs.size()) {
                            params["mode"] = config.commandArgs[i + 1];
                            i++;
                        } else if (config.commandArgs[i] == "--max-slots" && i + 1 < config.commandArgs.size()) {
                            params["maxSlots"] = std::stoll(config.commandArgs[i + 1]);
                            i++;
                        } else if (config.commandArgs[i] == "--price-per-hour-atoms" && i + 1 < config.commandArgs.size()) {
                            params["pricePerHourAtoms"] = std::stoll(config.commandArgs[i + 1]);
                            i++;
                        } else if (config.commandArgs[i] == "--price-per-request-atoms" && i + 1 < config.commandArgs.size()) {
                            params["remotePricePerRequestAtoms"] = std::stoll(config.commandArgs[i + 1]);
                            i++;
                        }
                    }
                    json out;
                    std::string err;
                    if (!call("model.access.set", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                std::cerr << "Usage: synapsed model access get|set ...\n";
                return 1;
            }

            if (sub == "remote") {
                const std::string sub2 = (config.commandArgs.size() >= 3) ? config.commandArgs[2] : "help";
                if (sub2 == "list") {
                    json out;
                    std::string err;
                    if (!call("model.remote.list", json::object(), out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "rent") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--offer" && i + 1 < config.commandArgs.size()) {
                            params["offerId"] = config.commandArgs[i + 1];
                            i++;
                        }
                    }
                    if (!params.contains("offerId")) {
                        std::cerr << "Usage: synapsed model remote rent --offer OFFER_ID\n";
                        return 1;
                    }
                    json out;
                    std::string err;
                    if (!call("model.remote.rent", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "end") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--session" && i + 1 < config.commandArgs.size()) {
                            params["sessionId"] = config.commandArgs[i + 1];
                            i++;
                        }
                    }
                    if (!params.contains("sessionId")) {
                        std::cerr << "Usage: synapsed model remote end --session SESSION_ID\n";
                        return 1;
                    }
                    json out;
                    std::string err;
                    if (!call("model.remote.end", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                std::cerr << "Usage: synapsed model remote list|rent|end ...\n";
                return 1;
            }

            if (sub == "market") {
                const std::string sub2 = (config.commandArgs.size() >= 3) ? config.commandArgs[2] : "help";
                if (sub2 == "listings") {
                    json params = json::object();
                    for (size_t i = 3; i < config.commandArgs.size(); ++i) {
                        if (config.commandArgs[i] == "--all") {
                            params["includeInactive"] = true;
                        }
                    }
                    json out;
                    std::string err;
                    if (!call("market.listings", params, out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                if (sub2 == "stats") {
                    json out;
                    std::string err;
                    if (!call("market.stats", json::object(), out, err)) {
                        if (isRpcTransportError(err)) return std::nullopt;
                        std::cerr << "RPC failed: " << err << "\n";
                        return 1;
                    }
                    std::cout << out.dump(2) << "\n";
                    return 0;
                }
                std::cerr << "Usage: synapsed model market listings [--all] | stats\n";
                return 1;
            }

	        std::cerr << "Unknown model subcommand: " << sub << "\n";
	        return 1;
	    }

	    if (cmd == "ai") {
	        if (config.commandArgs.size() == 1 || config.commandArgs[1] == "help") {
	            std::cout << "Usage:\n";
	            std::cout << "  synapsed ai complete --prompt TEXT [--max-tokens N] [--temperature X] [--remote-session SESSION_ID]\n";
	            std::cout << "  synapsed ai stop\n";
	            return 0;
	        }

	        const std::string sub = config.commandArgs[1];

	        if (sub == "stop") {
	            json out;
	            std::string err;
	            if (!call("ai.stop", json::object(), out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

	        if (sub == "complete") {
	            json params;
	            for (size_t i = 2; i < config.commandArgs.size(); ++i) {
	                if (config.commandArgs[i] == "--prompt" && i + 1 < config.commandArgs.size()) {
	                    params["prompt"] = config.commandArgs[i + 1];
	                    i++;
	                } else if (config.commandArgs[i] == "--max-tokens" && i + 1 < config.commandArgs.size()) {
	                    params["maxTokens"] = std::stoi(config.commandArgs[i + 1]);
	                    i++;
	                } else if (config.commandArgs[i] == "--temperature" && i + 1 < config.commandArgs.size()) {
	                    params["temperature"] = std::stod(config.commandArgs[i + 1]);
	                    i++;
                    } else if (config.commandArgs[i] == "--remote-session" && i + 1 < config.commandArgs.size()) {
                        params["remote"] = true;
                        params["remoteSessionId"] = config.commandArgs[i + 1];
                        i++;
	                }
	            }
	            json out;
	            std::string err;
	            if (!call("ai.complete", params, out, err)) {
	                if (isRpcTransportError(err)) return std::nullopt;
	                std::cerr << "RPC failed: " << err << "\n";
	                return 1;
	            }
	            std::cout << out.dump(2) << "\n";
	            return 0;
	        }

	        std::cerr << "Unknown ai subcommand: " << sub << "\n";
	        return 1;
	    }

	    if (cmd == "status" || cmd == "peers" || cmd == "logs") {
	        json out;
	        std::string err;
	        if (!call("node." + cmd, json::object(), out, err)) {
            std::cerr << "RPC failed: " << err << "\n";
            return 1;
        }
        std::cout << out.dump(2) << "\n";
        return 0;
    }

        if (cmd == "seeds") {
            json out;
            std::string err;
            if (!call("node.seeds", json::object(), out, err)) {
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

        if (cmd == "discovery") {
            json out;
            std::string err;
            if (!call("node.discovery.stats", json::object(), out, err)) {
                std::cerr << "RPC failed: " << err << "\n";
                return 1;
            }
            std::cout << out.dump(2) << "\n";
            return 0;
        }

    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}

bool parseArgs(int argc, char* argv[], NodeConfig& config) {
    static struct option longOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {"daemon", no_argument, nullptr, 'd'},
        {"config", required_argument, nullptr, 'c'},
        {"datadir", required_argument, nullptr, 'D'},
        {"port", required_argument, nullptr, 'p'},
        {"rpcport", required_argument, nullptr, 'r'},
        {"testnet", no_argument, nullptr, 't'},
        {"regtest", no_argument, nullptr, 'R'},
        {"privacy", no_argument, nullptr, 'P'},
        {"amnesia", no_argument, nullptr, 'A'},
        {"dev", no_argument, nullptr, 'E'},
        {"reset-ngt", no_argument, nullptr, 'Z'},
        {"poe-validators", required_argument, nullptr, 'V'},
        {"poe-validator-mode", required_argument, nullptr, 'M'},
        {"poe-min-stake", required_argument, nullptr, 'T'},
        {"quantum", no_argument, nullptr, 'Q'},
        {"security", required_argument, nullptr, 'S'},
        {"connect", required_argument, nullptr, 'C'},
        {"addnode", required_argument, nullptr, 'N'},
        {"seednode", required_argument, nullptr, 's'},
        {"maxpeers", required_argument, nullptr, 'm'},
        {"dbcache", required_argument, nullptr, 'b'},
        {"loglevel", required_argument, nullptr, 'l'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    int optionIndex = 0;
    
	    while ((opt = getopt_long(argc, argv, "+hvdc:D:p:r:tRPAEZV:M:T:QS:C:N:s:m:b:l:", 
	                              longOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 'h':
                config.showHelp = true;
                return true;
            case 'v':
                config.showVersion = true;
                return true;
            case 'd':
                config.daemon = true;
                config.tui = false;
                break;
            case 'c':
                config.configPath = optarg;
                break;
            case 'D':
                config.dataDir = optarg;
                break;
            case 'p':
                config.port = std::stoi(optarg);
                break;
            case 'r':
                config.rpcPort = std::stoi(optarg);
                break;
            case 't':
                config.testnet = true;
                config.networkType = "testnet";
                break;
            case 'R':
                config.regtest = true;
                config.networkType = "regtest";
                config.discovery = false;
                break;
            case 'P':
                config.privacyMode = true;
                break;
            case 'A':
                config.amnesia = true;
                break;
            case 'E':
                config.dev = true;
                config.networkType = "dev";
                break;
            case 'Z':
                config.resetNgt = true;
                break;
            case 'V':
                config.poeValidators = optarg;
                break;
            case 'M':
                config.poeValidatorMode = optarg;
                break;
            case 'T':
                config.poeMinStake = optarg;
                break;
            case 'Q':
                config.quantumSecurity = true;
                config.quantumSecuritySetByCli = true;
                break;
            case 'S':
                config.securityLevel = optarg;
                config.securityLevelSetByCli = true;
                break;
            case 'C':
                config.connectNodes.push_back(optarg);
                break;
            case 'N':
                config.addNodes.push_back(optarg);
                break;
            case 's':
                config.seedNodes.push_back(optarg);
                break;
            case 'm':
                config.maxPeers = std::stoi(optarg);
                break;
            case 'b':
                config.dbCacheSize = std::stoi(optarg);
                break;
            case 'l':
                config.logLevel = optarg;
                break;
            default:
                return false;
        }
    }
    
	    if (optind < argc) {
	        std::string command = argv[optind];
	        if (command == "poe" || command == "status" || command == "peers" ||
	            command == "balance" || command == "address" || command == "logs" ||
	            command == "model" || command == "ai" || command == "tor") {
	            config.cli = true;
	            config.tui = false;
	            config.daemon = false;
	            config.commandArgs.clear();
            for (int i = optind; i < argc; ++i) {
                config.commandArgs.emplace_back(argv[i]);
            }
            return true;
        }
    }
	    
	    return true;
}

void ensureDirectories(const NodeConfig& config) {
    std::filesystem::create_directories(config.dataDir);
    std::filesystem::create_directories(config.dataDir + "/blocks");
    std::filesystem::create_directories(config.dataDir + "/chaindata");
    std::filesystem::create_directories(config.dataDir + "/wallet");
    std::filesystem::create_directories(config.dataDir + "/models");
    std::filesystem::create_directories(config.dataDir + "/logs");
    std::filesystem::create_directories(config.dataDir + "/ledger");
    std::filesystem::create_directories(config.dataDir + "/knowledge");
    std::filesystem::create_directories(config.dataDir + "/transfer");
    std::filesystem::create_directories(config.dataDir + "/consensus");
}

std::string formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string formatUptime(uint64_t seconds) {
    uint64_t days = seconds / 86400;
    uint64_t hours = (seconds % 86400) / 3600;
    uint64_t mins = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;
    
    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0 || days > 0) oss << hours << "h ";
    if (mins > 0 || hours > 0 || days > 0) oss << mins << "m ";
    oss << secs << "s";
    return oss.str();
}

bool checkDiskSpace(const std::string& path, uint64_t requiredBytes) {
    struct statvfs stat;
    if (statvfs(path.c_str(), &stat) != 0) {
        return false;
    }
    uint64_t available = stat.f_bavail * stat.f_frsize;
    return available >= requiredBytes;
}

bool checkSystemRequirements() {
    uint32_t cores = std::thread::hardware_concurrency();
    if (cores < 2) {
        std::cerr << "Warning: System has only " << cores << " CPU core(s)\n";
    }
    return true;
}

void registerSignalHandlers() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
#ifndef _WIN32
    std::signal(SIGHUP, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);
#endif
}

void daemonize() {
#ifndef _WIN32
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Failed to fork daemon process\n";
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }
    
    if (setsid() < 0) {
        exit(1);
    }
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int nullfd = ::open("/dev/null", O_RDWR);
    if (nullfd >= 0) {
        ::dup2(nullfd, STDIN_FILENO);
        ::dup2(nullfd, STDOUT_FILENO);
        ::dup2(nullfd, STDERR_FILENO);
        if (nullfd > STDERR_FILENO) ::close(nullfd);
    }
#endif
}

}

int main(int argc, char* argv[]) {
    synapse::registerSignalHandlers();
    
    synapse::NodeConfig config;
    
    const char* home = std::getenv("HOME");
    config.dataDir = home ? std::string(home) + "/.synapsenet" : ".synapsenet";
    
    if (!synapse::parseArgs(argc, argv, config)) {
        return 1;
    }

    synapse::g_daemonMode = config.daemon;
    
    if (config.showHelp) {
        synapse::printHelp(argv[0]);
        return 0;
    }
    
    if (config.showVersion) {
        synapse::printVersion();
        return 0;
    }
    
    if (!config.daemon && !config.tui && !config.cli) {
        synapse::printBanner();
    }
    
    if (!synapse::checkSystemRequirements()) {
        return 1;
    }
    
    synapse::ensureDirectories(config);
    
    if (!synapse::checkDiskSpace(config.dataDir, 1024 * 1024 * 100)) {
        std::cerr << "Warning: Low disk space in " << config.dataDir << "\n";
    }
    
    if (config.daemon) {
        synapse::daemonize();
    }

    if (config.cli) {
        auto rc = synapse::runCliViaRpc(config);
        if (rc.has_value()) {
            return *rc;
        }
    }

    std::string instanceErr;
    auto instanceLock = synapse::utils::SingleInstanceLock::acquire(config.dataDir, &instanceErr);
    if (!instanceLock) {
        std::cerr << "SynapseNet: " << instanceErr << "\n";
        return 1;
    }
    
    synapse::SynapseNet node;
    synapse::g_node = &node;
    
    if (!node.initialize(config)) {
        std::cerr << "Failed to initialize node\n";
        return 1;
    }

    int result = 0;
    if (config.cli) {
        result = node.runCommand(config.commandArgs);
    } else {
        result = node.run();
    }
    
    node.shutdown();
    synapse::g_node = nullptr;
    
    return result;
}
