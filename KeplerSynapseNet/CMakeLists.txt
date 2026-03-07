cmake_minimum_required(VERSION 3.16)
project(KeplerSynapseNet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(USE_LLAMA_CPP "Enable llama.cpp GGML backend" ON)
option(USE_SECP256K1 "Use libsecp256k1 for signatures" ON)
option(BUILD_PRIVACY "Build with privacy layer" OFF)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_IDE "Build SynapseNet terminal IDE (crush fork)" ON)
set(BUILD_TUI_DEFAULT ON)
if(WIN32)
    set(BUILD_TUI_DEFAULT OFF)
endif()
option(BUILD_TUI "Build terminal UI (ncurses)" ${BUILD_TUI_DEFAULT})

if(USE_LLAMA_CPP)
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/llama.cpp/CMakeLists.txt)
        add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/llama.cpp ${CMAKE_BINARY_DIR}/llama.cpp)
        if(TARGET llama)
            set(HAS_LLAMA ON)
        endif()
    else()
        include(FetchContent)
        FetchContent_Declare(
            llama_cpp
            GIT_REPOSITORY https://github.com/ggerganov/llama.cpp.git
            GIT_TAG master
        )
        FetchContent_MakeAvailable(llama_cpp)
        if(TARGET llama)
            set(HAS_LLAMA ON)
        endif()
    endif()
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Find liboqs (optional PQC library)
set(HAS_LIBOQS OFF)
find_path(OQS_INCLUDE_DIR
    NAMES oqs/oqs.h
)
find_library(OQS_LIBRARY
    NAMES oqs
)
if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
    set(HAS_LIBOQS ON)
    message(STATUS "Found liboqs: ${OQS_LIBRARY}")
    include_directories(${OQS_INCLUDE_DIR})
else()
    message(WARNING "liboqs not found - building with simulated PQC implementations")
endif()

set(HAS_SECP256K1 OFF)
if(USE_SECP256K1)
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/secp256k1/CMakeLists.txt)
        add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/secp256k1 ${CMAKE_BINARY_DIR}/secp256k1)
        if(TARGET secp256k1)
            set(HAS_SECP256K1 ON)
        endif()
    else()
        include(FetchContent)
        FetchContent_Declare(
            secp256k1
            GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
            GIT_TAG master
        )
        FetchContent_MakeAvailable(secp256k1)
        if(TARGET secp256k1)
            set(HAS_SECP256K1 ON)
        endif()
    endif()
else()
    message(FATAL_ERROR "USE_SECP256K1=OFF is not supported: placeholder crypto fallback has been removed")
endif()

if(NOT HAS_SECP256K1)
    message(FATAL_ERROR "libsecp256k1 is required for real key derivation/signature verification")
endif()

# Find and require curses/ncurses (TUI dependency).
# NOTE: On some Windows environments (e.g. MSYS2) CMake's FindCurses can be flaky,
# so we fall back to pkg-config and a manual search when needed.
if(BUILD_TUI)
    if(WIN32)
        set(CURSES_NEED_NCURSES TRUE)
        set(CURSES_NEED_WIDE TRUE)
    endif()
    find_package(Curses QUIET)
    if(NOT CURSES_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(NCURSES QUIET ncursesw ncurses)
            if(NCURSES_FOUND)
                set(CURSES_FOUND TRUE)
                set(CURSES_LIBRARIES ${NCURSES_LIBRARIES})
                set(CURSES_INCLUDE_DIR ${NCURSES_INCLUDE_DIRS})
            endif()
        endif()
    endif()
    if(NOT CURSES_FOUND)
        find_path(CURSES_INCLUDE_DIR
            NAMES
                ncurses.h
                curses.h
            PATH_SUFFIXES
                ncurses
        )
        find_library(CURSES_LIBRARIES
            NAMES
                ncursesw
                ncurses
                curses
                pdcurses
        )
        if(CURSES_INCLUDE_DIR AND CURSES_LIBRARIES)
            set(CURSES_FOUND TRUE)
        endif()
    endif()
    if(NOT CURSES_FOUND)
        message(FATAL_ERROR "curses/ncurses library not found. Install with: 'brew install ncurses' (macOS), 'apt-get install libncurses-dev' (Linux), or 'pacman -S ncurses' (MSYS2)")
    endif()
endif()

# Find SQLite3 (optional, but enables persistent storage).
set(HAS_SQLITE3 OFF)
set(SQLITE3_LIBRARY "")
set(SQLITE3_INCLUDE_DIR "")

find_package(SQLite3 QUIET)
if(SQLite3_FOUND)
    set(SQLITE3_LIBRARY ${SQLite3_LIBRARIES})
    set(SQLITE3_INCLUDE_DIR ${SQLite3_INCLUDE_DIRS})
else()
    find_library(SQLITE3_LIBRARY sqlite3)
    find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
    if(NOT SQLITE3_LIBRARY AND APPLE)
        find_library(SQLITE3_LIBRARY sqlite3
            PATHS /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib)
    endif()
endif()

if(SQLITE3_LIBRARY AND SQLITE3_INCLUDE_DIR)
    set(HAS_SQLITE3 ON)
else()
    message(WARNING "SQLite3 headers/library not found. Building with an in-memory DB fallback (no persistence).")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)
if(HAS_SQLITE3)
    include_directories(${SQLITE3_INCLUDE_DIR})
endif()
if(BUILD_TUI AND CURSES_FOUND)
    include_directories(${CURSES_INCLUDE_DIR})
endif()
if(USE_LLAMA_CPP)
    include_directories(${CMAKE_SOURCE_DIR}/third_party/llama.cpp/include)
endif()

# Source files
set(CORE_SOURCES
    src/core/agent_coordination.cpp
    src/core/agent_draft_queue.cpp
    src/core/agent_runtime.cpp
    src/core/agent_scheduler.cpp
    src/core/agent_score.cpp
    src/core/agent_storage.cpp
    src/core/agent_submission_pipeline.cpp
    src/core/consensus.cpp
    src/core/event_system.cpp
    src/core/implant_compatibility.cpp
    src/core/implant_safety_pipeline.cpp
    src/core/knowledge.cpp
    src/core/ledger.cpp
    src/core/poe_v1.cpp
    src/core/poe_v1_engine.cpp
    src/core/poe_v1_objects.cpp
    src/core/state_manager.cpp
    src/core/tor_bridge_provider.cpp
    src/core/tor_bridge_utils.cpp
    src/core/tor_peer_identity.cpp
    src/core/tor_process_guard.cpp
    src/core/tor_route_policy.cpp
    src/core/transfer.cpp
    src/core/update_bundle.cpp
    src/core/update_installer.cpp
    src/core/wallet.cpp
)

set(TUI_SOURCES_FULL
    src/tui/primary_ui_spec.cpp
    src/tui/screens.cpp
    src/tui/tui.cpp
    src/tui/tui_dashboard.cpp
    src/tui/tui_help.cpp
    src/tui/tui_knowledge.cpp
    src/tui/tui_mining.cpp
    src/tui/tui_model.cpp
    src/tui/tui_network.cpp
    src/tui/tui_settings.cpp
    src/tui/tui_startup.cpp
    src/tui/tui_wallet.cpp
)
set(TUI_SOURCES)
if(BUILD_TUI)
    list(APPEND TUI_SOURCES ${TUI_SOURCES_FULL})
else()
    list(APPEND TUI_SOURCES src/tui/primary_ui_spec.cpp)
endif()

set(MODEL_SOURCES
    src/model/model_access.cpp
    src/model/model_download.cpp
    src/model/model_inference.cpp
    src/model/model_loader.cpp
    src/model/model_marketplace.cpp
    src/model/model_training.cpp
)

set(NETWORK_SOURCES
    src/network/discovery.cpp
    src/network/handshake.cpp
    src/network/network.cpp
    src/network/peer_manager.cpp
    src/network/protocol.cpp
    src/network/scale_policy.cpp
    src/network/sync.cpp
)

set(CRYPTO_SOURCES
    src/crypto/address.cpp
    src/crypto/crypto.cpp
    src/crypto/keys.cpp
)

set(DATABASE_SOURCES
    src/database/database.cpp
    src/database/wallet_db.cpp
)

set(PYTHON_SOURCES
    src/python/python_bridge.cpp
    src/python/sandbox.cpp
)

set(UTILS_SOURCES
    src/utils/config.cpp
    src/utils/format.cpp
    src/utils/logger.cpp
    src/utils/memory.cpp
    src/utils/serialize.cpp
    src/utils/single_instance.cpp
    src/utils/sleep_inhibitor.cpp
    src/utils/threading.cpp
)

set(INFRA_SOURCES
    src/infrastructure/error_handling.cpp
    src/infrastructure/messages.cpp
)

set(WEB_SOURCES
    src/web/ai_wrapper.cpp
    src/web/connector_audit.cpp
    src/web/curl_fetch.cpp
    src/web/darknet_engines.cpp
    src/web/deep_search_wrapper.cpp
    src/web/forum_crawler.cpp
    src/web/html_extractor.cpp
    src/web/onion_search_router.cpp
    src/web/query_detector.cpp
    src/web/rpc_server.cpp
    src/web/search_config.cpp
    src/web/tor_engine.cpp
    src/web/tor_fetch.cpp
    src/web/web_search.cpp
)

set(QUANTUM_SOURCES
    src/quantum/crypto_selector.cpp
    src/quantum/deterministic_otp.cpp
    src/quantum/dilithium.cpp
    src/quantum/hwrng.cpp
    src/quantum/hybrid_kem.cpp
    src/quantum/hybrid_sig.cpp
    src/quantum/key_derivation.cpp
    src/quantum/knowledge_crypto.cpp
    src/quantum/kyber.cpp
    src/quantum/model_inference_crypto.cpp
    src/quantum/network_security.cpp
    src/quantum/otp.cpp
    src/quantum/otp_manager.cpp
    src/quantum/pqc_manager.cpp
    src/quantum/qkd_bb84.cpp
    src/quantum/qkd_integration.cpp
    src/quantum/qkd_relay.cpp
    src/quantum/quantum_manager.cpp
    src/quantum/sphincs.cpp
    src/quantum/timing_defense.cpp
    src/quantum/wallet_security.cpp
)

set(PRIVACY_SOURCES
    src/privacy/amnesia.cpp
    src/privacy/dandelion.cpp
    src/privacy/decoy_traffic.cpp
    src/privacy/hidden_volume.cpp
    src/privacy/mix_inference.cpp
    src/privacy/onion_service.cpp
    src/privacy/privacy.cpp
    src/privacy/privacy_manager.cpp
    src/privacy/session_crypto.cpp
    src/privacy/socks5_proxy.cpp
    src/privacy/stealth_address.cpp
    src/privacy/traffic_analysis.cpp
)

set(BASE_SOURCES
    ${CORE_SOURCES}
    ${TUI_SOURCES}
    ${MODEL_SOURCES}
    ${NETWORK_SOURCES}
    ${CRYPTO_SOURCES}
    ${DATABASE_SOURCES}
    ${PYTHON_SOURCES}
    ${UTILS_SOURCES}
    ${INFRA_SOURCES}
    ${WEB_SOURCES}
    ${QUANTUM_SOURCES}
    ${PRIVACY_SOURCES}
)

if(BUILD_PRIVACY)
    add_definitions(-DPRIVACY_ENABLED)
endif()

add_library(synapsed_core STATIC ${BASE_SOURCES})

target_link_libraries(synapsed_core PUBLIC Threads::Threads)
target_link_libraries(synapsed_core PUBLIC OpenSSL::Crypto)
if(BUILD_TUI)
    target_link_libraries(synapsed_core PUBLIC ${CURSES_LIBRARIES})
endif()
target_compile_definitions(synapsed_core PUBLIC SYNAPSE_BUILD_TUI=$<BOOL:${BUILD_TUI}>)
target_compile_definitions(synapsed_core PUBLIC SYNAPSE_HAVE_SQLITE3=$<BOOL:${HAS_SQLITE3}>)

if(HAS_SECP256K1)
    target_compile_definitions(synapsed_core PUBLIC SYNAPSE_USE_SECP256K1=1)
    target_link_libraries(synapsed_core PUBLIC secp256k1)
endif()

if(HAS_LIBOQS)
    target_compile_definitions(synapsed_core PUBLIC USE_LIBOQS=1)
    target_link_libraries(synapsed_core PUBLIC ${OQS_LIBRARY})
endif()

if(HAS_SQLITE3)
    target_link_libraries(synapsed_core PUBLIC ${SQLITE3_LIBRARY})
else()
    message(STATUS "SQLite3 support disabled (in-memory DB fallback)")
endif()

if(USE_LLAMA_CPP AND HAS_LLAMA)
    target_compile_definitions(synapsed_core PUBLIC USE_LLAMA_CPP=1)
    target_link_libraries(synapsed_core PUBLIC llama)
endif()

add_executable(synapsed src/main.cpp)
target_link_libraries(synapsed PRIVATE synapsed_core)

# SynapseNet IDE (Go / crush fork)
if(BUILD_IDE)
    find_program(GO_EXECUTABLE go)
    if(NOT GO_EXECUTABLE)
        message(WARNING "Go not found; SynapseNet IDE will not be built (install Go and reconfigure)")
    else()
        set(SYNAPSE_IDE_BIN "${CMAKE_BINARY_DIR}/synapseide")
        add_custom_target(synapseide_build ALL
            BYPRODUCTS ${SYNAPSE_IDE_BIN}
            COMMAND ${GO_EXECUTABLE} build -o ${SYNAPSE_IDE_BIN}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/crush-main
        )
        install(PROGRAMS ${SYNAPSE_IDE_BIN} DESTINATION bin)
    endif()
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install
install(TARGETS synapsed DESTINATION bin)
