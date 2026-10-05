# Windows ARM64 native builds

Run Cargo from the meow-rs workspace root. Its `.cargo/config.toml` supplies a
target-scoped CMake toolchain for `aarch64-pc-windows-msvc`, including when that
target is the native Rust host. Other targets retain their existing build paths.
If a caller invokes Cargo from outside this workspace with `--manifest-path`,
it must supply `CMAKE_TOOLCHAIN_FILE_aarch64_pc_windows_msvc` as the absolute path
to `cmake/windows-arm64-msvc.cmake`; Cargo does not discover a nested workspace's
configuration from an unrelated working directory.

`boring-sys` 5.2.0 disables assembly when cross-compiling for Windows but returns
early for native hosts. The native Visual Studio ARM64 build consequently tries
to link `.S` objects that the generated projects never produce. The toolchain
uses BoringSSL's portable C implementations, matching the
[upstream MSVC ARM64 build configuration](https://boringssl.googlesource.com/boringssl/+/5903cfafaf9cd4f1ef436b6e5717ba511f096e83/infra/config/main.star#1102).
TLS, ECH, QUIC and proxy feature selections remain unchanged. This may reduce
crypto throughput compared with a platform that supports the assembly paths.

A custom toolchain also bypasses `boring-sys`'s normal CRT selection. This file
preserves Rust's `crt-static` choice, using the dynamic CRT otherwise, for both
debug and release builds.

The regression evidence is the native Windows ARM64 CI failure in run
`37341993846`, job `111871223426`: `fipsmodule` fails with `LNK1181` for
`aes-gcm-avx2-x86_64-apple.obj`. Acceptance requires native ARM64 host tests and
the release build in the desktop CI matrix; x64 configuration or builds alone
do not establish ARM64 acceptance.
