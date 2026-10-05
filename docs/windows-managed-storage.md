# Windows caller-owned product storage

The desktop host installs an optional storage policy after authenticating its IPC
peer. `WindowsCaller::duplicate` retains an impersonation token; clones retain the
same token identity. `authorize_home_windows` accepts an existing local drive
directory and permanently binds the process to that caller and directory object.
Standalone CLI processes leave this policy unset.

Every synchronous managed open, directory creation, and atomic replacement runs
under the exact caller token. The thread's previous impersonation token is restored
on scope exit, including errors. No credentials span an await. A restoration failure
terminates the process rather than contaminating a Tokio worker. Async hooks perform
the complete synchronous operation in `spawn_blocking`.

Directory and file traversal uses `NtCreateFile` relative to retained directory
handles, one validated component at a time, with `OBJ_DONT_REPARSE` and
`FILE_OPEN_REPARSE_POINT`. Directory handles deny delete sharing and prevent parent
replacement. Reads reject reparse points, non-disk objects, outside paths, alternate
streams, device names, and files with multiple hard links. Atomic writes create a
new scratch file and rename that file handle relative to the retained parent handle.
Failed scratch writes delete only the retained scratch object.

Homes and existing managed children must be TokenUser-owned. An elevated caller may
also use its actual TokenOwner only when that SID is an enabled owner group in the
same token. This does not give ordinary callers an Administrators exception.
New directories and files explicitly use TokenUser as owner. Existing owners and
ACLs are never repaired recursively, and no privileges are enabled.

Provider, geodata, fake-IP JSON, and selector-cache writes already use the shared
managed hooks, including later background updates. Fake-IP persistence is an atomic
JSON snapshot; there is no SQLite/WAL file-open context in this core storage path.
The protected native recovery journals use their separate product policy.

## Validation

On Windows, run:

```powershell
cargo test --locked -p meow-common --all-targets
cargo clippy --locked -p meow-common --all-targets -- -D warnings
cargo fmt --all --check
```

The public managed storage suite covers replacement and subsequent ordinary editing,
short names, hard links, outside paths, junctions, concurrent parent replacement,
mutation of an already authorized home into a junction, retained directory locks,
TokenUser ownership of new directories/files, restricted-token access denial,
restoration of a preexisting thread token, and immutable async background policy.
The separate CLI fixture confirms that the optional policy does not change CLI reads.

The elevated exact-owner fixture is intentionally opt-in. On a disposable elevated
Windows runner, run it explicitly; default tests do not supply this evidence:

```powershell
cargo test --locked -p meow-common --test managed_files_windows elevated_exact_owner_is_accepted_but_ordinary_caller_rejects_admin_owned_home -- --ignored --exact --nocapture
```

That fixture uses only temporary owned directories and already available tokens.
It verifies the elevated token's actual Admin owner, TokenUser ownership of newly
created cache files/directories, and rejection by a LUA token with the Admin group
disabled. It does not install a service, modify routing, or enable privileges.

Primary API references: [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile),
[FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information),
and [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).
