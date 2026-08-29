# Airlock

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README_KR.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

An agent is an untrusted code executor. LLMs are probabilistic and vulnerable to prompt injection, so what has to be enforced at the boundary is what an agent actually does, not what it intends to do.

Airlock acts as a local zero trust gateway for AI coding agents. It mediates the file access, process execution, and network connections an agent performs on a developer machine, blocks only the dangerous actions or routes them to a human for approval, and records every action in a tamper-evident audit log.

Airlock is the Trusted Computing Base (TCB), and we call it the `broker`. Agents, tools, MCP servers, and LLMs are all outside the trust boundary.

What Airlock does and does not guarantee, and how the policy and the audit log fit together, are covered in [INTRODUCTION.md](INTRODUCTION.md). Compliance against sector-specific regulatory requirements is documented in [COMPLIANCE.md](COMPLIANCE.md).

## Quick start

```bash
$ cargo build --release

# Write a policy file interactively
$ airlock setup

# Check what the generated policy allows
$ airlock policy check
$ airlock policy explain --file ~/.ssh/id_rsa
$ airlock policy explain --exec rm -rf /

# Run under the broker
$ airlock run -- claude

# Verify and inspect what happened
$ airlock audit verify
$ airlock audit show --decisions-only

# Run the day's check, then stamp it as reviewed
$ airlock audit report --json
$ airlock audit ack --note "daily check"
```

If there is no policy file, only the built-in baseline applies. Airlock looks for `airlock.toml` or `.airlock.toml` in the current directory, and falls back to `~/.config/airlock/policy.toml`, in that order. It does not walk up to parent directories. Examples live in `examples/policy/`. Editing an example to fit your setup is the recommended way to start.

```bash
$ cp examples/policy/strict.toml airlock.toml
```

The semantics of the policy system are written up in [policy-dsl.md](docs/policy-dsl.md).

All human-facing output is available in Korean (default) and English. `airlock setup` asks for the language first and saves the choice to `~/.config/airlock/config.toml`; `AIRLOCK_LANG=en` overrides it per run. English preset variants live in `examples/policy/en/`. Details in [i18n.md](docs/i18n.md).

Enforcing host level egress policy for real requires `--egress-proxy`. Without this flag, the host list in a policy is only a declaration of intent.

```bash
$ airlock run --egress-proxy -- claude
```

On Linux, the `execve` and `connect` calls made by child processes are relayed to the broker and recorded in the audit log. Without this, only the single process that `airlock run` launches directly is recorded, and everything happening underneath it is invisible. **This layer is Linux only, and the options below are ignored on macOS.**

```bash
# Default. Records exec and outbound connections
$ airlock run -- claude

# Also records file opens. Slow, because every entry is fsynced
$ airlock run --mediate full -- claude

# Turns mediation off and keeps only session level records
$ airlock run --mediate off -- claude
```

## Current limitations

Airlock does not leave what it fails to enforce to the documentation alone. When `airlock run` starts, it prints in its banner exactly what is not enforced in that session, and `airlock audit` distinguishes entries the kernel actually enforced from entries that were only observed.

The big ones to know about right now are these.

- **macOS records only the outbound connections of child processes.**
  - With no mediation mechanism, what children execute and which files they open never reaches the audit log. Outbound is the exception: under `--egress-proxy` the proxy is itself the gate, so a child's connection is decided and recorded no matter what the mediation level says. The `--mediate` value is accepted but not applied, and that fact is recorded in the banner and in the audit log.
- **Host level egress on Linux is still bypassable.**
  - `--egress-proxy` narrows the Landlock ports down to the proxy alone, but a child that connects out directly on the same port skips the proxy. Network namespace isolation has to land before this becomes the same boundary as on macOS.
- **Tunnel contents are not inspected.**
  - The proxy does not terminate TLS, so what you send to an allowed host is not examined. DLP is not implemented. What is recorded is metadata: bytes out, bytes in, and duration per destination. `max_bytes_out` can cap the cumulative total for a destination, but since the byte count is only known once a connection closes, it takes effect from the next connection onward.
- **Plaintext outbound is blocked only under `--egress-proxy`.**
  - `[defaults].egress_plaintext` defaults to `deny`, and a rule that names only a host no longer opens plaintext. To allow it you have to write `protocol = "http"` yourself. But the mediation layer only sees `connect(2)` and reports every connection as `tcp`, so without the proxy the plaintext floor never fires at all.
- **exec argv conditions are not a security boundary.**
  - The program path now is one. When `[defaults].exec` is not `allow`, both platforms grant execute permission only to the whitelist, so a binary the agent writes into the workspace cannot be run. What stays outside the kernel is argv matching (`rm -rf`, ...), which exists as a tripwire that shows dangerous intent to a human early. On Linux the dynamic linker itself needs execute permission, so `/lib` and `/usr/lib` are opened as whole trees, and `mmap(PROT_EXEC)` is not mediated by Landlock at all.
- **The audit log detects chain recomputation only when the anchor is kept elsewhere.**
  - Each session's final head is appended to a separate anchor chain. Point `--anchor-dir` at another volume and deleting a whole session or recomputing a chain is detected. Leave it inside the audit root and whoever can recompute the chain recomputes the anchor at the same cost.

The full list, with rationale and code locations, is in [limitations.md](docs/limitations.md). For the per-platform comparison of enforcement scope, see INTRODUCTION.md.

## Contributing

The build and verification steps, the code and test conventions, and the bar for changes that touch the security boundary are in [CONTRIBUTING.md](CONTRIBUTING.md). Please send vulnerabilities through the reporting channel in [SECURITY.md](SECURITY.md) rather than a public issue.

## License

This project is licensed under AGPL-3.0. See the [LICENSE](LICENSE) file.

For a security tool, source verifiability is the precondition for trust, so we believe users should be able to read and build the TCB on their own machine and check it for themselves.
