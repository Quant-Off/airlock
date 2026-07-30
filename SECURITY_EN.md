# Security Policy

Airlock is a security tool, so this document states both the reporting channel and the actual scope of the guarantees. A security document that does not write down what it fails to block leads users into false confidence.

## Reporting a vulnerability

Please do not open a public issue. Send it to <qtfelix@qu4nt.space> instead. The following makes reproduction faster.

- The Airlock version (`airlock --version`) and the OS version
- The policy file you used and the output of `airlock policy check`
- Reproduction steps, ideally in the form of a failing test
- The audit log directory (`chain.jsonl`, `head.json`). Paths may contain secrets, so send only the parts that are needed

We reply with an acknowledgement within 3 days and an initial assessment within 14 days. Disclosure before a fix puts users at risk, so as a rule we disclose after the patch and the release.

## Supported versions

For 0.x, only the latest minor version is supported. This table will be updated after 1.0.

## Trust boundary

The TCB is `airlock-broker` and, beneath it, `airlock-policy`, `airlock-audit`, and `airlock-canonical`. Nothing else. Agents, the tools an agent launches, MCP servers, and LLMs are all outside the trust boundary.

In other words, the following **are vulnerabilities.**

- An access that the policy decides as deny or forbid actually happens in the kernel
- A user rule relaxes a built-in forbid without `overrides`
- An audit log entry is modified, deleted, or inserted, and `airlock audit verify` still passes
- An approval prompt presents a string produced by the agent as if it were a fact observed by the broker
- An unenforced rule is reported as if it were enforced. This includes non-enforcement that does not appear in the banner and the gap list

## What is not a vulnerability

The following are known limitations, and they are the scope the product itself declares in its banner and its documentation. You are welcome to report them, but they behave that way by design.

- An attacker with write access to the audit directory recomputes the entire chain from the beginning. Section 2 of `docs/audit-format.md` defines this boundary
- Host level egress policy is not enforced. With no proxy layer, enforcement reaches only the port (Linux), or only allowing or blocking outbound traffic as a whole (macOS)
- On macOS, `ask` rules are lowered to deny in the kernel profile. Seatbelt cannot express human approval
- On macOS, individual exec, connect, and file access by child processes are not recorded in the audit log. There is no runtime mediation mechanism
- The path read by the mediation layer (seccomp user notification) may differ from the target the kernel actually opens (TOCTOU). The real boundary for file access is Landlock
- An access that Landlock denies in the kernel is not itself recorded in the audit log
- An attacker who already holds root, kernel vulnerabilities, and physical access

## Verification

```bash
$ ./scripts/check.sh
```

This checks fmt, clippy (`-D warnings`), the full test suite, the ban on unwrap in library code, and policy preset loading. The enforcement layer does the work rather than merely asserting it: it puts a real process in the sandbox and checks that reading a secret is denied. The Linux only tests require a kernel with Landlock support (5.13 or later), and in a container it must be possible to install seccomp filters.
