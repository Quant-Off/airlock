# Contributing

[![Language](https://img.shields.io/badge/CONTRIBUTING-Korean_Ver-blue?style=for-the-badge)](CONTRIBUTING_KR.md)

Airlock is the Trusted Computing Base (TCB) on a user's machine. If the code here is wrong, users run agents believing something is blocked when it is not. That is why the bar for contributions is higher than for a typical application. Almost every rule below follows from that one reason.

## Before you start

- **Do not open an issue for a vulnerability.** Follow the reporting channel in [SECURITY.md](SECURITY.md). That document also states what counts as a vulnerability versus a known limitation.
- Read [README.md](README.md) and [docs/design.md](docs/design.md) for the design background. What is not enforced today is listed in [docs/limitations.md](docs/limitations.md), with rationale and code locations.
- Changes to the enforcement layer, the policy evaluation order, or the audit format should be discussed in an issue before you write code. Typo fixes and added tests can go straight to a PR.
- Questions are welcome in issues or on [Discord](https://discord.gg/9utg4hp3m8).

Note that the design documents under `docs/` and most in-tree comments are written in Korean. Code, identifiers, and PR discussion in English are fine.

## Development environment

`rust-toolchain.toml` pins the toolchain to `1.95.0`. It exists so that CI and local builds use the same compiler, so please do not work around it. The workspace `rust-version` (1.88) is the lower bound, and the edition is 2024. `python3` is required by `scripts/metadata-check.py`.

Enforcement layer tests are platform specific and skip silently when the environment cannot run them.

- Linux needs a kernel with Landlock support (5.13 or later), and inside a container it must be possible to install seccomp filters.
- macOS runs the Seatbelt backend as is.
- If you only verified on one OS, say so in the PR. A skipped test is not a passing test.

## Verification

One command before you push.

```bash
$ ./scripts/check.sh
```

It checks the following.

| Step                  | What it runs                                                           |
|-----------------------|------------------------------------------------------------------------|
| fmt                   | `cargo fmt --all -- --check`                                           |
| clippy                | `cargo clippy --workspace --all-targets -- -D warnings`                |
| test                  | `cargo test --workspace --no-fail-fast`                                |
| no unwrap             | That library code (tests excluded) contains no `unwrap()` or `expect(` |
| policy presets        | That every `examples/policy/*.toml` loads                              |
| distribution metadata | Missing crate `description` or dependency `version`                    |

CI (`.github/workflows/ci.yml`) runs the same script on Linux and macOS, and adds `cargo-deny` (advisories, licenses, sources) plus `x86_64` and `aarch64` cross compilation. The mediation layer uses different seccomp arch values and syscall numbers per architecture, so code that compiles on only one of them cannot land.

While iterating, narrow it down with `cargo check --workspace` or `cargo test -p <crate>`, then run the full script once before pushing.

## Workspace rules

Dependencies flow in one direction only, and there are no cycles.

```
airlock-canonical -> airlock-audit, airlock-policy -> airlock-broker -> airlock
```

- `crates/airlock` The CLI entry point (`run`, `audit`, `policy`, `setup`)
- `crates/airlock-broker` The OS enforcement layer. Linux Landlock + seccomp, macOS Seatbelt
- `crates/airlock-policy` The capability policy model and evaluation engine
- `crates/airlock-audit` The hash-chained append-only audit log
- `crates/airlock-canonical` Length-prefixed canonical encoding. A leaf that depends on nothing
- `crates/airlock-proxy` The egress proxy
- `crates/airlock-setup` The interactive policy wizard. UI dependencies (cliclack, console) do not leave this crate

A new crate placed under `crates/` is picked up by the member glob. Version, edition, and license are inherited from the workspace, and internal crates are declared in `workspace.dependencies` with **both** `path` and `version`. Without `version`, a crates.io upload is rejected.

The presets in `airlock-setup` are copies of `examples/policy`, and a test enforces that they stay in sync. If you edit an example policy, edit the preset too.

## Code conventions

- Comments and doc comments are not written by default. When one is needed it is written in Korean, and it states **why**, not what the code does. The existing comments in the tree are the reference.
- Library code does not use `unwrap()` or `expect(`. The broker is the TCB, so a single swallowed failure path is a hole in the enforcement layer. Return failures as types.
- Keep `unsafe` to a minimum, and justify it under a `# Safety` heading. State panic conditions under `# Errors` or `# Panics`.
- **Fail closed.** If it cannot be decided, it is denied, not allowed. A `connect` whose address could not be read, a path that cannot be canonicalized, and an unsupported ABI all land on the deny side.
- Untrusted values (agent argv, strings from a policy file, host names, network payloads) pass through the sanitization in `airlock-canonical` before they reach a screen or a log. This keeps control characters and bidirectional reordering characters from rewriting a line a human reads.
- The release profile sets `overflow-checks = true` and `panic = "abort"`. Proposals to turn overflow checks off for performance are not accepted.
- Be conservative about adding dependencies. A new dependency must fall inside the license allowlist in `deny.toml`, and wildcard versions are banned. If a change adds a dependency to a TCB crate (`broker`, `policy`, `audit`, `canonical`), state the justification in the PR.

## Test conventions

Tests must do the work rather than merely assert it. The existing tests are the baseline.

- Audit tests build an actually tampered chain and check that it is detected (`crates/airlock-audit/tests/tamper.rs`).
- Policy tests create real symlinks, path traversal attempts, and Unicode case aliases, and check that they are blocked (`crates/airlock-policy/tests/bypass.rs`).
- Enforcement tests put a real process in the sandbox and check that reading a secret is denied (`crates/airlock-broker/tests/`).

If you add a rule or an enforcement feature, add **a test that tries to bypass it**. When fixing a regression, write the reproducing test first and confirm it fails before the fix.

## Changes that touch the security boundary

If you are modifying `airlock-broker`, `airlock-policy`, `airlock-audit`, or `airlock-canonical`, check the following.

- Do not change the policy tier order (self-protection -> built-in forbid -> user rules -> built-in ask/deny -> defaults). A change that lets a user rule relax a built-in forbid without `overrides` is itself a vulnerability.
- **Anything that is not enforced must be declared as a gap.** Writing it down in the documentation is not enough. It has to surface in the `airlock run` banner and in the audit log, and reporting an unenforced rule as if it were enforced is a vulnerability.
- If you change the audit log encoding, update `docs/audit-format.md` first, and state in the CHANGELOG whether existing chains can still be verified.
- Rule id character constraints, path canonicalization (NFC, case folding, symlinks, NUL, firmlinks), and glob matching are all bypass surfaces. Touching them requires the matching bypass tests.
- An approval prompt must never present a string produced by the agent as a fact observed by the broker. The approval channel (`/dev/tty`) is not handed to children.
- Treat all external input as untrusted: agent tool calls, MCP messages, policy files, and payloads arriving through the proxy.

## Documentation

- When a design decision changes, `docs/` is updated before the code.
- `docs/audit-format.md`, `docs/policy-dsl.md`, and `docs/egress-proxy.md` are specifications and are normative. If the code disagrees with them, the specification is right.
- Korean and English documents are maintained as pairs. Do not update only one side of `README.md` / `README_KR.md`, `SECURITY.md` / `SECURITY_KR.md`, or `CONTRIBUTING.md` / `CONTRIBUTING_KR.md`.
- If user visible behavior changes, add an entry to the unreleased section of `CHANGELOG.md`. The format is Keep a Changelog.

## Commits and pull requests

Commit messages are written in Korean: a one line summary, followed by a `-` list when needed. No `feat` or `chore` prefixes, and no trailing periods.

```
정책 평가에서 케이스 별칭 우회 차단

- NFC 정규화 뒤 대문자 접기로 U+017F 표기를 잡음
- 대소문자 무구분 마운트 회귀 테스트 추가
```

Do not commit:

- personal policy files such as `airlock.toml` (covered by `.gitignore`)
- audit log session directories, since the paths may contain secrets
- `target/`, editor settings, or local scratch directories

Send pull requests against `master`, and state in the description:

- what changed and why, and whether it changes the trust boundary
- which OS you verified on, and whether any tests were skipped
- which documents you updated, if the enforcement scope or the policy semantics changed

All three CI jobs (check, dependency audit, cross compile) must pass before a merge.

## Where help is wanted

`docs/limitations.md` is effectively the TODO list. These are open in particular.

- Network namespace isolation on Linux. Today a child can bypass the proxy and connect out directly on the same port
- Observing child processes on macOS. With no mediation mechanism, only the single process that `airlock run` launches directly appears in the audit log
- The MCP proxy layer
- Example policies and presets. Policies that came out of a real agent setup are especially useful

## License

Contributions are distributed under the same AGPL-3.0-only license as the project. Sending a pull request is taken as agreement to that. For a security tool, source verifiability is the precondition for trust, so users must be able to read and build the TCB on their own machine and check it for themselves.
