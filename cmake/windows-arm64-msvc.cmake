# BoringSSL does not support ARM64 assembly with MSVC. Keep its portable crypto.
set(OPENSSL_NO_ASM ON CACHE BOOL "Use portable BoringSSL implementations" FORCE)

# A toolchain file bypasses boring-sys's normal Rust CRT selection.
if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    if("$ENV{CARGO_CFG_TARGET_FEATURE}" MATCHES "(^|,)crt-static(,|$)")
        set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded CACHE STRING "Rust CRT linkage")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL CACHE STRING "Rust CRT linkage")
    endif()
endif()
