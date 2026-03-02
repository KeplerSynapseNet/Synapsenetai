# SynapseNet 0.1.0-beta

**A Decentralized Intelligence Network**

> "Satoshi gave us money without banks. I will give you brains without corporations."  
> — Kepler

SynapseNet is a decentralized peer-to-peer network for collective intelligence. It is to **KNOWLEDGE** what Bitcoin is to **MONEY**. Mine with intelligence using Proof of Emergence (PoE).

## What is SynapseNet?

SynapseNet is a local-first AI network where nodes contribute and validate knowledge using deterministic consensus (PoE). The network is designed to be censorship-resistant, decentralized, and community-driven, with optional local AI chat and Web 4.0 context injection (clearnet/onion).

## Screenshots

![KeplerSynapseNet](pictures/synapsenet_ai_agent.png)


## Links

- **GitHub:** https://github.com/KeplerSynapseNet
- **Official:** https://synapsenetai.org
- **Onion:** http://dc4p33qjalqqpk6ggy2p7axv57rdj53lrlgeq3bfto3laoiifzh5odad.onion

### Bitcoin
kepler
`bc1q5pkemq7q84ld4rf5kwtafp7jfl9dlf3pc4z9d4`

## Quick Start

```bash
# If you configured with: cmake -S KeplerSynapseNet -B build
TERM=xterm-256color ./build/synapsed -D /tmp/synapsenet_dev --dev

# If you configured inside KeplerSynapseNet (cmake -S . -B build)
# TERM=xterm-256color ./KeplerSynapseNet/build/synapsed -D /tmp/synapsenet_dev --dev
```

For external Tor (`9150`) bridge mode and startup troubleshooting, see `KeplerSynapseNet/README.md` and:
- `KeplerSynapseNet/docs/tor_shared_external_9150_runbook.md`
- `KeplerSynapseNet/docs/tor_9050_9150_conflict_runbook.md`

## Shared Tor 9150 (No-Conflict Launch Sequence)

Use one Tor runtime on `127.0.0.1:9150` and share it across SynapseNet + Tor Browser.

```bash
# 1) Stop extra Tor owners (optional but recommended before restart)
pkill -f "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor" || true
pkill -f "/opt/homebrew/bin/tor" || true
sleep 1
```

```bash
# 2) Start external bridge Tor on 9150
cd <repo-root>/KeplerSynapseNet
tools/macos_tor_obfs4_helper.sh \
  --bridges-file /tmp/bridges.txt \
  --socks-port 9150 \
  --control-port 9151 \
  --bootstrap-check \
  --bootstrap-attempts 6 \
  --bridge-subset-size 4 \
  --takeover-port-owner \
  --keep-running \
  --out /tmp/tor-obfs4-synapsenet.conf
```

```bash
# 3) Verify Tor path
lsof -nP -iTCP:9150 -sTCP:LISTEN
curl --socks5-hostname 127.0.0.1:9150 https://check.torproject.org/api/ip --max-time 30
```

```bash
# 4) Run SynapseNet using external Tor snippet
cd <repo-root>/KeplerSynapseNet
TERM=xterm-256color ./build/synapsed \
  -D /tmp/synapsenet_fresh \
  --dev \
  -c /tmp/synapsenet_external_9150.conf
```

```bash
# 5) Run Tor Browser as SOCKS client of the same Tor
TOR_PROVIDER=none TOR_SOCKS_HOST=127.0.0.1 TOR_SOCKS_PORT=9150 \
"/Applications/Tor Browser.app/Contents/MacOS/firefox" --new-instance
```

Important:
- Do not run plain `tor` manually after this (it starts another instance, usually on `9050`).
- If helper reports `9150 already in use` and the curl probe returns `"IsTor":true`, keep the current Tor process and continue.

## NAAN Site Allowlist (TUI)

You can configure what sites NAAN is allowed to use directly from the SynapseNet interface:

1. Open `Settings`.
2. Press `W` (`NAAN Site Allowlist (clearnet/onion)`).
3. Choose list target:
   - `C` for `clearnet_site_allowlist`
   - `O` for `onion_site_allowlist`
4. Enter one rule per line, press `Enter` to add.
5. Press `Enter` on an empty line to save and exit.

Config file path shown in the UI:
- `<DATA_DIR>/naan_agent_web.conf`

Security note:
- You are responsible for any site you add.
- Malicious sites can deliver phishing, exploit payloads, and malware.
- Use endpoint protection (AV/EDR), sandboxing/VMs, and least privilege.
- IDE/AI tools can help triage logs and suspicious behavior, but they do **not** replace antivirus/EDR.
- If you use cloud/LLM analysis, share sanitized logs only (no keys/secrets/private data).

## Build

### CI

GitHub Actions runs:
- Linux + macOS build + tests (llama.cpp OFF for speed)
- Linux build with llama.cpp
- Windows build + tests (MSYS2)
- Docker build (tests run during image build)

Common requirements:
- CMake 3.16+
- C++17 compiler
- ncurses (required)
- SQLite3 (optional but recommended)
- Go (optional, only if you want the terminal Synapse IDE)

### Linux

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git libncurses-dev libsqlite3-dev

cmake -S KeplerSynapseNet -B build -DCMAKE_BUILD_TYPE=Release -DUSE_LLAMA_CPP=OFF -DBUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### macOS

```bash
brew install cmake ncurses sqlite3

cmake -S KeplerSynapseNet -B build -DCMAKE_BUILD_TYPE=Release -DUSE_LLAMA_CPP=OFF -DBUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Windows (WSL2 recommended)

1. Install WSL2 + Ubuntu.
2. Open Ubuntu and follow the Linux build steps above.

### Windows (MSYS2)

1. Install MSYS2: https://www.msys2.org
2. Open the **MSYS2 MSYS** shell and install deps:

```bash
pacman -Syu
pacman -S --needed base-devel cmake ninja pkgconf git ncurses sqlite
```

3. Configure + build + test:

```bash
cmake -S KeplerSynapseNet -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DUSE_LLAMA_CPP=OFF \
  -DUSE_SECP256K1=ON \
  -DBUILD_PRIVACY=OFF \
  -DBUILD_IDE=OFF \
  -DBUILD_TESTS=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure --parallel 2
```

### Docker (Windows/macOS/Linux fallback)

This builds **Linux** binaries inside a container (useful on Windows when WSL2 is not available or fails).

```bash
docker build -f KeplerSynapseNet/Dockerfile -t keplersynapsenet:local KeplerSynapseNet
# or multi-arch
# docker buildx build --platform linux/amd64,linux/arm64 -t keplersynapsenet:local --load .

docker run --rm -it -p 8332:8332 keplersynapsenet:local
```

## Project Structure

| Directory | Description |
|-----------|-------------|
| `KeplerSynapseNet/` | Core daemon, TUI, AI model integration, P2P network |
| `ide/synapsenet-vscode/` | VS Code extension for Synapse IDE |
| `interfaces txt/` | Architecture specs, design documents |
| `pictures/` | Project assets |

Documentation source of truth: edit only `Synapsenet-main/interfaces txt`; `Synapsenet-main/KeplerSynapseNet/interfaces txt` is a CI mirror.

## Features

- **Local AI Chat** — Run GGUF models locally, stream tokens in real time
- **Proof of Emergence (PoE)** — Contribute knowledge, validate, earn NGT
- **Web 4.0** — Optional clearnet/onion search injection (F5/F6/F7)
- **Quantum-resistant crypto** — CRYSTALS-Dilithium, Kyber, SPHINCS+
- **Synapse IDE** — Terminal IDE + VS Code extension for AI-assisted coding

## License

MIT License. See [LICENSE](LICENSE).

## Contributing

Everyone is welcome to contribute and improve SynapseNet. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and consensus rules.
