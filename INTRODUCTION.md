# Introduction

[![Language](https://img.shields.io/badge/INTRODUCTION-Korean_Ver-blue?style=for-the-badge)](INTRODUCTION_KR.md)

Where [README.md](README.md) covers the project overview and the quick start, this document explains what Airlock actually does and does not guarantee, how the policy and the audit log fit together, and how the code is organized.

## What is guaranteed

The table below is both the current implementation status and the list of what remains.

| Item                                              |     Status      | Notes                                                                        |
|---------------------------------------------------|:---------------:|------------------------------------------------------------------------------|
| Hash-chained audit log with tamper detection      | **Implemented** | Verifier included                                                            |
| Capability policy model and TOML DSL              | **Implemented** |                                                                              |
| Path canonicalization (traversal, symlinks, case) | **Implemented** |                                                                              |
| macOS kernel enforcement (Seatbelt)               | **Implemented** | Files, exec paths, outbound as a whole                                       |
| `/dev/tty` inline ask approval                    | **Implemented** | Has a response deadline, and denies once it passes                           |
| Linux kernel enforcement (Landlock)               | **Implemented** | Files, TCP ports                                                             |
| Runtime mediation (seccomp user notification)     | **Implemented** | **Linux only.** Records the exec, connect, and file opens of child processes |
| Host level egress enforcement (macOS)             | **Implemented** | `--egress-proxy`. Narrows outbound down to a single local proxy              |
| Host level egress enforcement (Linux)             |     Partial     | Port narrowing only. Bypassable until network namespace isolation lands      |
| Egress DLP (blocking secret patterns)             | Not implemented | The proxy does not terminate TLS                                             |
| MCP proxy layer                                   | Not implemented |                                                                              |

## Enforcement scope per platform

Enforcement scope differs from platform to platform, and the same policy file does not reach the same conclusion on both operating systems. The exact differences are below.

| Policy kind                          | Linux (Landlock + seccomp)                                   | macOS (Seatbelt)                                  |
|--------------------------------------|--------------------------------------------------------------|---------------------------------------------------|
| File paths                           | Kernel enforced (per inode)                                  | Kernel enforced (per canonical path)              |
| exec path and file name              | Not kernel enforced. The mediation layer records it and asks | **Kernel enforced** (`deny` only, not `ask`)      |
| exec argv conditions (`rm -rf`, ...) | The mediation layer records it and asks                      | Neither enforced nor recorded                     |
| Blocking outbound as a whole         | Kernel enforced                                              | Kernel enforced                                   |
| Port level egress                    | Kernel enforced (ABI v4 or later)                            | Not enforced                                      |
| Host level egress                    | Observed with `--egress-proxy`. Bypassable                   | **Kernel enforced** with `--egress-proxy`         |
| Recording child process behavior     | Turned on with `--mediate` (exec and connect by default)     | **Not recorded.** There is no mediation mechanism |

In other words, on macOS only the single process that `airlock run` launches directly ends up in the audit log, and what the children underneath it execute and where they connect does not. The `--mediate` value is not applied on macOS, and that fact is recorded both in the banner and in the genesis entry of the audit log.

Airlock does not leave what it has not implemented to the documentation alone. When `airlock run` starts, it prints for itself what is not enforced in that session.

```
airlock 0.1.0
  Policy      baseline (22 rules, digest ae70ec11fe7a)
  Enforcement seatbelt (sandbox_init_with_parameters)
  Mediation   off (exec-net requested)
  Workspace   /Users/me/work/proj
  Approval    /dev/tty inline prompt (300 second response deadline, denied once it passes)
  Audit       ~/.local/share/airlock/sessions/1785073894508695000-38871
  Gap         Host level egress policy is not enforced by Seatbelt. A proxy layer is required
  Gap         Seatbelt cannot express human approval, so ask file rules are lowered to deny in the profile
  Gap         ask exec rules are not enforced by the kernel ...: danger-rm, sudo-exec, ...
  Gap         This platform has no runtime mediation mechanism, so --mediate exec-net is not applied ...
  Gap         Mediation is off, so the exec, connect, and file opens of child processes are not recorded ...
```

The CLI itself prints in Korean. The banner above, and the command output shown later in this document, are translated here so that they can be read.

`airlock audit` likewise marks entries recorded in `observe` mode apart from entries the kernel actually enforced, so an unenforced record never looks like an enforced one.

### What the audit log detects

The audit log detects modified entry contents, reordering, deletion from the middle, insertion with the hash resealed, truncation of the tail, and entries transplanted from another session. It does **not** detect an attacker who can recompute the entire chain from the beginning.

The audit log is not complete on its own. The real defense comes from combining it with the enforcement layer denying the agent write access to the audit directory (tier 0 below). Section 2 of `docs/audit-format.md` is the normative statement of the exact scope.

## Policy

A declarative DSL based on TOML.

```toml
version = 1
name = "my-policy"

[defaults]
file = "deny"
exec = "ask"
egress = "deny" # allow is banned at the syntax level

[[rules]]
id = "workspace"
kind = "file"
path = "~/work/**"
action = "allow"
```

Decisions descend in the order below. These are called tiers, and evaluation stops at the first match.

```
0. Self-protection rules    Writes to the audit log and the policy file are denied. No exceptions
1. Built-in forbid rules    Secret paths. Opened only by naming the rule in overrides
2. User rules               Declaration order, first match wins
3. Built-in ask/deny rules  Persistence footholds, dangerous exec
4. [defaults]
```

The key point is that built-in forbid sits **above** user rules. Allowing `~/work/**` as a whole still leaves the `.env` inside it blocked, and asking about the two paths with the policy above left as is shows that difference directly.

```bash
$ airlock policy explain --file ~/work/src/main.rs --mode read
# Decision  allow
# Rule      workspace (user tier)

$ airlock policy explain --file ~/work/.env --mode read
# Decision  forbid
# Rule      env-files (baseline tier)
# Reason    Application secrets
```

To make an exception to secret protection you have to state which rule you are opening and leave a rationale. Loading fails without one.

```toml
[[rules]]
id = "read-ssh-config"
kind = "file"
path = "~/.ssh/config"
mode = ["read"]
action = "allow"
overrides = "ssh-private-keys"
reason = "Needs to read the host aliases of the deployment targets"
```

This exception is reflected in the policy digest, and the digest is bound into the genesis entry of the audit log. In other words, who opened a protection, when, and on what grounds is provable after the fact.

## Crate structure

`airlock-policy` decides what is allowed, `airlock-audit` records what happened, and `airlock-broker` enforces those decisions at the OS boundary.

- `crates/airlock` The flagship binary. `run`, `audit`, `policy`
- `crates/airlock-broker` The OS enforcement layer. The `Enforcer` trait and the per-platform backends
- `crates/airlock-policy` The capability policy model and the evaluation engine
- `crates/airlock-audit` The hash-chained append-only audit log and its verification
- `crates/airlock-proxy` The local egress proxy. Host level outbound decisions
- `crates/airlock-canonical` Length-prefixed canonical encoding. A leaf that depends on nothing

Dependencies flow in one direction only. `airlock-canonical` is at the bottom, `airlock-audit` and `airlock-policy` sit above it, `airlock-proxy` and `airlock-broker` above those, and the CLI `airlock` at the top. There are no cycles.

## Verification

```bash
$ ./scripts/check.sh
```

This checks fmt, clippy (`-D warnings`), the full test suite, the ban on unwrap and expect in library code, policy preset loading, and distribution metadata in one go. CI (`.github/workflows/ci.yml`) runs the same script on Linux and macOS, and on top of that checks `x86_64` and `aarch64` cross compilation. The mediation layer uses different seccomp arch values and syscall numbers per architecture, so code that compiles on only one architecture does not go into a release. unwrap is banned because the broker is the TCB, and a single swallowed failure path is a hole in the enforcement layer.

The tests follow the obligations in the specification documents directly, and they do the work rather than merely asserting it. The audit tests build an actually tampered chain and check that it is detected, the policy tests create real symlinks and path traversal attempts and check that they are blocked, and the macOS enforcement layer tests put a real process in the sandbox and check that reading a secret is denied.

## Documentation

- `docs/README.md` Documentation index
- `docs/design.md` The full design (threat model, architecture, settled decisions, technical constraints, MVP)
- `docs/policy-dsl.md` The policy DSL specification
- `docs/audit-format.md` The audit log format specification
- `docs/egress-proxy.md` The egress proxy layer specification
- `docs/policy-guide.md` The policy authoring guide
- `docs/limitations.md` The full list of current limitations
- `SECURITY.md` The reporting channel, and what counts as a vulnerability versus a known limitation
- `CHANGELOG.md` The change history

When a design decision changes, `docs/` is updated before the code.
