# Airlock

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

에이전트는 신뢰할 수 없는 코드 실행자입니다. LLM은 확률적이고 프롬프트 인젝션에 취약하므로, 에이전트가 무엇을 하려는지가 아니라 실제로 무엇을 하는지를 경계에서 강제해야 합니다.

Airlock은 AI 코딩 에이전트를 위한 로컬 제로 트러스트 게이트웨이 역할을 수행합니다. 에이전트가 개발자 머신에서 수행하는 파일 접근, 프로세스 실행, 네트워크 연결을 경계에서 중재하고, 위험한 행위만을 차단하거나 사람의 승인을 받게 하며, 모든 행위를 변조 탐지 가능한 감사 로그(audit log)로 남깁니다.

Airlock은 신뢰 가능한 컴퓨팅 기반(Trusted Computing Base, TCB)이며 이를 `broker`(브로커)라고 표현합니다. 에이전트나 툴, MCP 서버, LLM은 전부 신뢰 경계 밖에 있습니다.

무엇을 보장하고 무엇을 보장하지 않는지, 정책과 감사 로그가 어떻게 맞물리는지는 [INTRODUCTION.md](INTRODUCTION.md)에 정리해 두었으며, 특정 부문의 규정 준수 사항에 관해 [COMPLIANCE.md](COMPLIANCE.md)에서 확인하실 수 있습니다.

## 빠른 시작

```bash
$ cargo build --release

# 대화형으로 정책 파일 작성
$ airlock setup

# 생성된 정책이 무엇을 허용하는지 확인
$ airlock policy check
$ airlock policy explain --file ~/.ssh/id_rsa
$ airlock policy explain --exec rm -rf /

# 브로커 아래에서 실행
$ airlock run -- claude

# 무슨 일이 있었는지 검증, 조회
$ airlock audit verify
$ airlock audit show --decisions-only
```

정책(policy) 파일이 없으면 내장 베이스라인만이 적용됩니다. 현재 디렉토리의 `airlock.toml` 또는 `.airlock.toml`, 없으면 `~/.config/airlock/policy.toml`을 순서대로 찾습니다. 상위 디렉토리로 거슬러 올라가지는 않습니다. 예제는 `examples/policy/`에 있습니다. 예제를 직접 수정해 사용하는 걸 권장합니다.

```bash
$ cp examples/policy/strict.toml airlock.toml
```

정책 시스템에 관한 의미론적 문서를 [policy-dsl.md](docs/policy-dsl.md)에 정리해 두었습니다.

호스트 단위 egress 정책을 실제로 강제하려면 `--egress-proxy`가 필요합니다. 이 플래그가 없으면 정책의 호스트 목록은 의도 선언에 그칩니다.

```bash
$ airlock run --egress-proxy -- claude
```

Linux에서는 자식 프로세스가 부르는 `execve`와 `connect`를 브로커로 중계해 감사에 남깁니다. 이것이 없으면 `airlock run`이 직접 띄운 프로세스 하나만 기록되고 그 아래에서 벌어지는 일은 보이지 않습니다. **이 층은 Linux 전용이며 macOS에서는 아래 옵션이 무시됩니다.**

```bash
# 기본값. exec 과 아웃바운드 연결을 기록한다
$ airlock run -- claude

# 파일 열기까지 기록한다. 엔트리마다 fsync 하므로 느리다
$ airlock run --mediate full -- claude

# 중계를 끄고 세션 단위 기록만 남긴다
$ airlock run --mediate off -- claude
```

## 현재 한계

Airlock은 강제되지 않는 것을 문서에만 적어 두지 않습니다. `airlock run`이 시작할 때 그 세션에서 무엇이 강제되지 않는지 배너로 직접 출력하고, `airlock audit`은 커널이 실제로 강제한 엔트리와 관찰만 한 엔트리를 구분해 표시합니다.

지금 알아 두어야 할 큰 것들은 다음과 같습니다.

- **macOS는 자식 프로세스의 행위를 기록하지 못합니다.**
  - 중계 기구가 없어 `airlock run`이 직접 띄운 프로세스 하나만 감사에 남습니다. `--mediate` 값은 받아들여지되 적용되지 않으며, 그 사실이 배너와 감사 로그에 남습니다.
- **Linux의 호스트 단위 egress는 아직 우회 가능합니다.**
  - `--egress-proxy`가 Landlock 포트를 프록시 하나로 줄이지만, 자식이 같은 포트로 외부에 직접 연결하면 프록시를 건너뜁니다. network namespace 격리가 들어와야 macOS와 같은 경계가 됩니다.
- **터널 내용은 보지 않습니다.**
  - 프록시가 TLS를 종단하지 않으므로, 허용된 호스트로 무엇을 보내는지는 검사하지 않습니다. DLP는 미구현입니다.
- **exec 규칙은 보안 경계가 아닙니다.**
  - argv 매칭은 원리적으로 우회 가능하며, 위험한 의도를 사람에게 조기에 보여 주는 tripwire 용도입니다. 실제 방어는 파일 규칙과 egress 규칙에서 나옵니다.
- **감사 로그는 체인 전체를 재계산할 수 있는 공격자를 탐지하지 못합니다.**
  - 실제 방어는 강제 층이 감사 디렉토리를 에이전트에게 쓰기 금지하는 것과 조합해서 나옵니다.

근거와 코드 위치까지 붙은 전체 목록은 [limitations.md](docs/limitations.md)에 있습니다. 플랫폼별 강제 범위 비교는 INTRODUCTION.md를 확인하세요.

## 기여

빌드와 검증 절차, 코드와 테스트 규약, 보안 경계를 건드리는 변경의 기준은 [CONTRIBUTING.md](CONTRIBUTING.md)에 있습니다. 취약점은 공개 이슈가 아니라 [SECURITY.md](SECURITY.md)의 신고 경로로 보내 주시길 바랍니다.

## 라이선스

이 프로젝트는 AGPL-3.0 라이선스를 받습니다. [LICENSE](LICENSE) 파일에서 확인할 수 있습니다.

보안 도구는 소스 검증 가능성이 신뢰의 전제이므로 사용자가 자기 머신의 TCB를 직접 읽고 빌드해 확인할 수 있어야 한다 생각됩니다.
