FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG GO_VERSION=1.25.5
ARG CMAKE_BUILD_TYPE=Release
ARG TARGETARCH
ARG BUILDPLATFORM
ARG TARGETPLATFORM

# Base build deps (C++ + ncurses + sqlite + git for FetchContent fallback).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    cmake \
    ninja-build \
    pkg-config \
    build-essential \
    python3 \
    libssl-dev \
    libncurses-dev \
    libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

# Install Go (needed for synapseide_build target).
RUN case "${TARGETARCH}" in amd64|arm64) ;; *) echo "Unsupported TARGETARCH=${TARGETARCH}" && exit 1 ;; esac \
  && echo "BUILDPLATFORM=${BUILDPLATFORM} TARGETPLATFORM=${TARGETPLATFORM} TARGETARCH=${TARGETARCH}" \
  && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tgz \
  && rm -rf /usr/local/go \
  && tar -C /usr/local -xzf /tmp/go.tgz \
  && rm -f /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /src
COPY . .

# Configure + build + run tests (keeps Docker builds honest).
RUN cmake -S . -B build -G Ninja \
      -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
      -DUSE_LLAMA_CPP=ON \
      -DUSE_SECP256K1=ON \
      -DBUILD_TESTS=ON \
      -DBUILD_IDE=ON \
      -DBUILD_PRIVACY=OFF \
  && cmake --build build --parallel \
  && ctest --test-dir build --output-on-failure

# Minimal runtime image (Linux). Users on macOS/Windows can run this via Docker Desktop.
FROM --platform=$TARGETPLATFORM ubuntu:24.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    libncurses6 \
    libsqlite3-0 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/build/synapsed /app/synapsed
COPY --from=build /src/build/synapseide /app/synapseide

EXPOSE 8332
ENTRYPOINT ["/app/synapsed"]
