# FlClash-Meow desktop host

Fork-specific embedded host for FlClash-Meow. The standalone `meow` CLI keeps its own startup path. This crate embeds the existing configuration, tunnel, listeners, DNS, provider and API modules in one process; the IPC adapter calls the in-process API router and does not open an internal REST socket or spawn a second core.

The executable accepts one product IPC address. Windows addresses begin with `\\.\pipe\FlClashMeowCore_`; Unix socket basenames begin with `FlClashMeowSocket_`. Frames use four-byte little-endian lengths with a 64 MiB limit. Request and response payloads retain the Dart envelope and encode structured values once. Control responses and state events have separate queues from bounded bulk events. `shutdown` waits for runtime teardown, flushes the response and then closes IPC.

`getCoreInfo` declares protocol version 1 and host/core source identity. `initClash` initializes an absolute product home without opening proxy listeners. `setupConfig` reads the derived `config.yaml`; profile reads return the original YAML mapping. `checkConfig` returns structured diagnostics; `validateConfig` keeps the legacy string result. Unknown fields and ignored capture settings prevent application. A process-local optional validator in `meow-config::proxy_parser` applies the same host policy to provider nodes before materialization, including later refreshes. The CLI does not install it.

`cargo test -p flclash-meow-host --tests` exercises framing and the public request boundary. Windows native builds require MSVC, CMake, NASM and libclang, and a signed architecture-matching Wintun DLL. `MEOW_WINTUN_DLL` may point at the verified official DLL; it is embedded by `meow-listener`. `MEOW_HOST_COMMIT` identifies an archived build input when Git metadata is absent.

## Integration acceptance still open

The current Windows tests prove idle initialization, unknown nested option detection, unknown provider-node rejection, real HTTP proxy transmission, eager listener readiness, stop and restoration after an occupied-port replacement. They do not certify native TUN, system DNS/routes, elevation or the other desktop architectures.

The upstream TUN cleanup needs an ownership repair and an error-reporting seam before native acceptance can close:

- `meow-listener::tun::dns::DnsGuard::drop` on Windows resets every adapter to DHCP, then restores a saved backup without checking for another writer's later changes. macOS/Linux restoration likewise needs owner-aware comparison. This must only restore values still owned by this runtime.
- `meow-tunnel::tunnel::teardown_tun` and `await_core_done` return no cleanup error; a lwIP teardown timeout logs and continues. A failed cleanup must become a visible RPC error and prevent a successor stack from overlapping a generation whose exit is unconfirmed.
- `TunListener` startup currently reports readiness, but failure paths and native guard drops must report route/DNS restoration failures rather than relying only on warnings. A successful shutdown acknowledgement currently establishes task teardown completion, not verified OS restoration.
- Unix elevated-host cache ownership must be preserved for the connected user's product home. Ordinary proxy fallback must exclude TUN before application.

No capability-parity extensions are planned. These are required host ownership and cleanup fixes, with real platform records required by the client specification.
