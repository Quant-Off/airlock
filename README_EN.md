# Airlock

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

An agent is an untrusted code executor. LLMs are probabilistic and vulnerable to prompt injection, so what has to be enforced at the boundary is what an agent actually does, not what it intends to do.

Airlock is a local zero trust gateway for AI coding agents. It mediates the file access, process execution, and network connections an agent performs on a developer machine, blocks dangerous actions or routes them to a human for approval, and records every action in a tamper-evident audit log.

Airlock is the Trusted Computing Base (TCB), and we call it the `broker`. Agents, tools, MCP servers, and LLMs are all outside the trust boundary.

## Quick start

```bash
$ cargo build --release

# First, check what the policy allows
$ ./target/release/airlock policy check
$ ./target/release/airlock policy explain --file ~/.ssh/id_rsa
$ ./target/release/airlock policy explain --exec rm -rf /

# Run under the broker
$ ./target/release/airlock run -- claude

# Verify and inspect what happened
$ ./target/release/airlock audit verify
$ ./target/release/airlock audit show --decisions-only
```

If there is no policy file, only the built-in baseline applies. Airlock looks for `airlock.toml` or `.airlock.toml` in the current directory, and falls back to `~/.config/airlock/policy.toml`, in that order. It does not walk up to parent directories. Examples live in `examples/policy/`. Editing an example to fit your setup is the recommended way to start.

```bash
$ cp examples/policy/strict.toml airlock.toml
```

On Linux, `execve` and `connect` calls made by child processes are relayed to the broker and recorded in the audit log. Without this, only the single process that `airlock run` launches directly is recorded, and everything happening underneath it is invisible. **This layer is Linux only, and the options below are ignored on macOS.**

```bash
# Default. Records exec and outbound connections
$ airlock run -- claude

# Also records file opens. Slow, because every entry is fsynced
$ airlock run --mediate full -- claude

# Turns mediation off and keeps only session level records
$ airlock run --mediate off -- claude
```

## What it guarantees

The table below sums it up. It doubles as a rough TODO list, so the unimplemented rows are work that is planned.

| Item                                              |     Status      | Notes                                                                        |
|---------------------------------------------------|:---------------:|------------------------------------------------------------------------------|
| Hash-chained audit log and tamper detection       | **Implemented** | Verifier included                                                            |
| Capability policy model and TOML DSL              | **Implemented** |                                                                              |
| Path canonicalization (traversal, symlinks, case) | **Implemented** |                                                                              |
| macOS kernel enforcement (Seatbelt)               | **Implemented** | Files, exec paths, all outbound traffic                                      |
| `/dev/tty` inline ask approval                    | **Implemented** | Bounded response window, denies once exceeded                                |
| Linux kernel enforcement (Landlock)               | **Implemented** | Files, TCP ports                                                             |
| Runtime mediation (seccomp user notification)     | **Implemented** | **Linux only.** Records child process exec, connect, and file opens in audit |
| Host level egress enforcement                     | Not implemented | The policy can express it, but a proxy layer is required                      |
| MCP proxy layer                                   | Not implemented |                                                                              |

The scope of enforcement differs per platform, and the same policy file does not reach the same conclusion on both operating systems. The exact differences are below.

| Policy kind                        | Linux (Landlock + seccomp)                                       | macOS (Seatbelt)                            |
|------------------------------------|------------------------------------------------------------------|---------------------------------------------|
| File paths                         | Kernel enforced (per inode)                                      | Kernel enforced (per canonical path)        |
| Exec path and file name            | Not kernel enforced. The mediation layer records and asks        | **Kernel enforced** (`deny` only, not `ask`) |
| Exec argv conditions (`rm -rf`, etc.) | The mediation layer records and asks                          | Neither enforced nor recorded               |
| Blocking all outbound traffic      | Kernel enforced                                                  | Kernel enforced                             |
| Port level egress                  | Kernel enforced (ABI v4 or later)                                | Not enforced                                |
| Host level egress                  | Not enforced (proxy layer required)                              | Not enforced (proxy layer required)         |
| Recording child process actions    | Enabled with `--mediate` (exec and connect by default)           | **Not recorded.** There is no mediation mechanism |

In other words, on macOS only the single process that `airlock run` launches directly ends up in the audit log, and what its children execute or where they connect does not. The `--mediate` value has no effect on macOS, and that fact is recorded both in the startup banner and in the genesis entry of the audit log.

Unimplemented items are not left to the documentation alone. When `airlock run` starts, it prints exactly what is not enforced in that session.

```
airlock 0.1.0
  Policy      baseline (22 rules, digest ae70ec11fe7a)
  Enforcement seatbelt (sandbox_init_with_parameters)
  Mediation   off (requested exec-net)
  Workspace   /Users/me/work/proj
  Approval    /dev/tty inline prompt (300s response limit, denies once exceeded)
  Audit       ~/.local/share/airlock/sessions/1785073894508695000-38871
  Limitation  Host level egress policy is not enforced by Seatbelt. A proxy layer is required
  Limitation  Seatbelt cannot express human approval, so ask file rules are lowered to deny in the profile
  Limitation  ask exec rules are not kernel enforced ...: danger-rm, sudo-exec, ...
  Limitation  This platform has no runtime mediation mechanism, so --mediate exec-net does not apply ...
  Limitation  Mediation is off, so child process exec, connect, and file opens are not recorded in audit ...
```

`airlock audit` likewise distinguishes entries recorded in `observe` mode from entries the kernel actually enforced, so an unenforced record never looks like an enforced one.

### What the audit log detects

The audit log detects modified entry contents, reordering, deletions in the middle, insertions resealed with recomputed hashes, tail truncation, and entries transplanted from another session. It does **not** detect an attacker who can recompute the entire chain from the beginning.

The audit log is not complete on its own. The real defense comes from combining it with the enforcement layer denying the agent write access to the audit directory (tier 0 below). Section 2 of `docs/audit-format.md` is the normative statement of the exact guarantees.

## Policy

A declarative TOML based DSL. `docs/policy-dsl.md` is the normative reference for the full grammar and evaluation semantics.

```toml
version = 1
name = "my-policy"

[defaults]
file = "deny"
exec = "ask"
egress = "deny" # allow is forbidden at the grammar level

[[rules]]
id = "workspace"
kind = "file"
path = "~/work/**"
action = "allow"
```

Decisions are made in the order below. Each level is called a tier, and evaluation stops at the first match.

```
0. Self-protection rules      Writes to the audit log and the policy file are forbidden. Cannot be relaxed
1. Built-in forbid rules      Secret paths. Relaxed only when named explicitly in overrides
2. User rules                 Declaration order, first match wins
3. Built-in ask/deny rules    Persistence paths, dangerous exec
4. [defaults]
```

The key point is that built-in forbid sits **above** user rules. Allowing all of `~/work/**` still leaves `.env` inside it blocked, and asking about the two paths with the policy above unchanged shows the difference directly.

```bash
$ airlock policy explain --file ~/work/src/main.rs --mode read
# Decision  allow
# Rule      workspace (user tier)

$ airlock policy explain --file ~/work/.env --mode read
# Decision  forbid
# Rule      env-files (baseline tier)
# Reason    Application secrets
```

To lift secret protection you must state which rule you are relaxing and leave a reason. Without a reason, loading fails.

```toml
[[rules]]
id = "read-ssh-config"
kind = "file"
path = "~/.ssh/config"
mode = ["read"]
action = "allow"
overrides = "ssh-private-keys"
reason = "Needs to read deployment target host aliases"
```

That relaxation is reflected in the policy digest, and the digest is bound into the genesis entry of the audit log. In other words, who lifted a protection, when, and on what grounds is provable after the fact.

## Crate structure

`airlock-policy` decides what is allowed, `airlock-audit` records what happened, and `airlock-broker` enforces those decisions at the OS boundary.

- `crates/airlock` The flagship binary. `run`, `audit`, `policy`
- `crates/airlock-broker` The OS enforcement layer. The `Enforcer` trait and per-platform backends
- `crates/airlock-policy` The capability policy model and the evaluation engine
- `crates/airlock-audit` The hash-chained append-only audit log and its verification
- `crates/airlock-canonical` Length-prefixed canonical encoding. A leaf that depends on nothing

Dependencies flow in one direction only. `airlock-canonical` is at the bottom, `airlock-audit` and `airlock-policy` sit above it, `airlock-broker` above those, and the `airlock` CLI at the top. There are no cycles.

## Verification

```bash
$ ./scripts/check.sh
```

This checks fmt, clippy (`-D warnings`), the full test suite, the ban on unwrap and expect in library code, policy preset loading, and distribution metadata in one pass. CI (`.github/workflows/ci.yml`) runs the same script on Linux and macOS, and additionally verifies cross compilation for `x86_64` and `aarch64`. The mediation layer uses different seccomp arch values and syscall numbers per architecture, so code that only compiles on one architecture never makes it into a release. The reason unwrap is banned is that the broker is the TCB, and a single swallowed failure path is a hole in the enforcement layer.

The tests follow the mandatory requirements in the specification documents directly, and they do the work rather than merely asserting it. The audit log tests build an actually tampered chain and check that it is detected, the policy tests create real symlinks and path traversal attempts and check that they are blocked, and the macOS enforcement tests put a real process in the sandbox and check that reading a secret is denied.

## Documentation

- `docs/README.md` Documentation index
- `docs/design.md` The full design (threat model, architecture, settled decisions, technical constraints, MVP)
- `docs/policy-dsl.md` The policy DSL specification
- `docs/audit-format.md` The audit log format specification
- `SECURITY.md` The reporting channel, and what counts as a vulnerability versus a known limitation
- `CHANGELOG.md` Change history

When a design decision changes, `docs/` is updated before the code.

## For convenience

You can ask an agent to generate or edit a policy. Paradoxically, though, doing so conflicts with the purpose of the Airlock project, which is to improve the security of what AI does.

You can go ahead if you really want to, but it is not recommended by default.

## License

This project is licensed under AGPL-3.0. See the [LICENSE](LICENSE) file.

For a security tool, source verifiability is the precondition for trust, so we believe users should be able to read and build the TCB on their own machine and check it for themselves.
