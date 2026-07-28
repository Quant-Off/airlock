# Airlock

[//]: # ([![Language]&#40;https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge&#41;]&#40;README_EN.md&#41;)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

에이전트는 신뢰할 수 없는 코드 실행자입니다. LLM은 확률적이고 프롬프트 인젝션에 취약하므로, 에이전트가 무엇을 하려는지가 아니라 실제로 무엇을 하는지를 경계에서 강제해야 합니다.

Airlock은 AI 코딩 에이전트를 위한 로컬 제로 트러스트 게이트웨이 역할을 수행합니다. 에이전트가 개발자 머신에서 수행하는 파일 접근, 프로세스 실행, 네트워크 연결을 경계에서 중재하고, 위험한 행위만을 차단하거나 사람의 승인을 받게 하며, 모든 행위를 변조 탐지 가능한 감사 로그(audit log)로 남깁니다.

Airlock은 신뢰 가능한 컴퓨팅 기반(Trusted Computing Base, TCB)이며 이를 `broker`(브로커)라고 표현합니다. 에이전트나 툴, MCP 서버, LLM은 전부 신뢰 경계 밖에 있습니다.

## 빠른 시작

```bash
$ cargo build --release

# 정책이 무엇을 허용하는지 먼저 확인
$ ./target/release/airlock policy check
$ ./target/release/airlock policy explain --file ~/.ssh/id_rsa
$ ./target/release/airlock policy explain --exec rm -rf /

# 브로커 아래에서 실행
$ ./target/release/airlock run -- claude

# 무슨 일이 있었는지 검증, 조회
$ ./target/release/airlock audit verify
$ ./target/release/airlock audit show --decisions-only
```

정책(policy) 파일이 없으면 내장 베이스라인만이 적용됩니다. 현재 디렉토리의 `airlock.toml` 또는 `.airlock.toml`, 없으면 `~/.config/airlock/policy.toml`을 순서대로 찾습니다. 상위 디렉토리로 거슬러 올라가지는 않습니다. 예제는 `examples/policy/`에 있습니다. 예제를 직접 수정해 사용하는 걸 권장합니다.

```bash
$ cp examples/policy/strict.toml airlock.toml
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

## 무엇을 보장하는가

간단하게 표로 나타낼 수 있습니다. 이 표는 약간 TODO 리스트와 일관되어 이러한 작업을 예정해 두었다고도 볼 수 있겠습니다.

| 항목                                 |   상태    | 비고                                           |
|------------------------------------|:-------:|----------------------------------------------|
| 해시체인 감사 로그와 변조 탐지                  | **구현됨** | 검증기 포함                                       |
| capability 정책 모델과 TOML DSL         | **구현됨** |                                              |
| 경로 정규화 (traversal, 심볼릭 링크, 대소문자)   | **구현됨** |                                              |
| macOS 커널 강제 (Seatbelt)             | **구현됨** | 파일, exec 경로, 아웃바운드 전체                        |
| `/dev/tty` 인라인 ask 승인              | **구현됨** | 응답 상한 있음, 초과 시 거부                            |
| Linux 커널 강제 (Landlock)             | **구현됨** | 파일, TCP 포트                                   |
| 런타임 중계 (seccomp user notification) | **구현됨** | **Linux 전용.** 자식 프로세스의 exec/연결/파일 열기를 감사에 남김 |
| 호스트 단위 egress 강제                   |   미구현   | 정책은 표현 가능하나 프록시 층이 필요                        |
| MCP 프록시 층                          |   미구현   |                                              |

강제 범위는 플랫폼마다 다르며, 같은 정책 파일이 두 OS에서 같은 결론을 내지는 않습니다. 정확한 차이는 아래와 같습니다.

| 정책 종류                     | Linux (Landlock + seccomp)    | macOS (Seatbelt)               |
|---------------------------|-------------------------------|--------------------------------|
| 파일 경로                     | 커널 강제 (inode 단위)              | 커널 강제 (정규 경로 단위)               |
| exec 경로/파일 이름             | 커널 강제 없음. 중계 층이 기록하고 `ask` 승인 | **커널 강제** (`deny`만, `ask`는 아님) |
| exec argv 조건 (`rm -rf` 등) | 중계 층이 기록하고 `ask` 승인           | 강제/기록 안 됨                      |
| 아웃바운드 전체 차단               | 커널 강제                         | 커널 강제                          |
| 포트 단위 egress              | 커널 강제 (ABI v4 이상)             | 강제 안 됨                         |
| 호스트 단위 egress             | 강제 안 됨 (프록시 층 필요)             | 강제 안 됨 (프록시 층 필요)              |
| 자식 프로세스 행위 기록             | `--mediate`로 켜짐 (기본 exec/연결)  | **기록 안 됨.** 중계 기구가 없음          |

곧 macOS에서는 `airlock run` 이 직접 띄운 프로세스 하나만 감사에 남고, 그 아래 자식들이 무엇을 실행하고 어디로 연결했는지는 남지 않습니다. `--mediate` 값은 macOS에서 적용되지 않으며, 그 사실이 배너와 감사 로그 제네시스 양쪽에 기록됩니다.

미구현 항목을 문서에만 적어 두지는 않으며, `airlock run`은 시작할 때 그 세션에서 무엇이 강제되지 않는지 직접 출력합니다.

```
airlock 0.1.0
  정책     baseline (22 규칙, 다이제스트 ae70ec11fe7a)
  강제     seatbelt (sandbox_init_with_parameters)
  중계     off (요청 exec-net)
  작업공간 /Users/me/work/proj
  승인     /dev/tty 인라인 프롬프트 (응답 상한 300초, 초과 시 거부)
  감사     ~/.local/share/airlock/sessions/1785073894508695000-38871
  한계     호스트 단위 egress 정책은 Seatbelt로 강제되지 않음. 프록시 층이 필요함
  한계     Seatbelt는 사람 승인을 표현할 수 없으므로 ask 파일 규칙은 프로파일에서 deny로 내려감
  한계     ask exec 규칙은 커널에서 강제되지 않음 ...: danger-rm, sudo-exec, ...
  한계     이 플랫폼에는 런타임 중계 기구가 없어 --mediate exec-net가 적용되지 않음 ...
  한계     중계가 꺼져 있어 자식 프로세스의 exec/연결/파일 열기가 감사에 남지 않음 ...
```

`airlock audit` 또한 `observe` 모드로 기록된 엔트리를 커널이 실제로 강제한 엔트리와 구분해 표시하므로, 강제되지 않은 기록이 강제된 기록처럼 보이는 일은 없습니다.

### 감사 로그가 탐지하는 것

감사 로그는 엔트리 내용 변조, 순서 바꾸기, 중간 삭제, 해시를 다시 봉인한 삽입, 꼬리 잘라내기, 다른 세션 엔트리 이식을 탐지하지만, **체인 전체를 처음부터 재계산할 수 있는 공격자**는 탐지하지 못합니다.

감사 로그 단독으로는 완전하지 않으며, 실제 방어는 강제 층이 감사 디렉토리를 에이전트에게 쓰기 금지하는 것(아래 0번 티어)과 조합해서 나옵니다. 정확한 보장 범위는 `docs/audit-format.md` 2절이 정본입니다.

## 정책

TOML 기반 선언적 DSL입니다. 전체 문법과 평가 의미론은 `docs/policy-dsl.md`가 정본입니다.

```toml
version = 1
name = "my-policy"

[defaults]
file = "deny"
exec = "ask"
egress = "deny" # allow 는 문법 수준에서 금지됨

[[rules]]
id = "workspace"
kind = "file"
path = "~/work/**"
action = "allow"
```

결정은 아래 순서로 내려갑니다. 이를 티어(tier)라고 하며, 먼저 매칭된 곳에서 멈춥니다.

```
0. 자기보호 규칙        감사 로그와 정책 파일 쓰기 금지. 완화 불가
1. 내장 forbid 규칙    시크릿 경로. overrides 로 지목해야만 완화됨
2. 사용자 규칙          선언 순서, 첫 매칭 승
3. 내장 ask/deny 규칙  지속성 확보 경로, 위험 exec
4. [defaults]
```

내장 forbid가 사용자 규칙보다 **위에** 있는 것이 핵심입니다. `~/work/**`를 통째로 허용해도 그 안의 `.env`는 여전히 막히며, 위 정책을 그대로 두고 두 경로를 물어보면 그 차이가 그대로 드러납니다.

```bash
$ airlock policy explain --file ~/work/src/main.rs --mode read
# 결정     allow
# 규칙     workspace (user tier)

$ airlock policy explain --file ~/work/.env --mode read
# 결정     forbid
# 규칙     env-files (baseline tier)
# 근거     애플리케이션 시크릿
```

시크릿 보호를 풀려면 어떤 규칙을 완화하는지 명시하고 근거를 남겨야 합니다. 근거가 없으면 로드가 실패합니다.

```toml
[[rules]]
id = "read-ssh-config"
kind = "file"
path = "~/.ssh/config"
mode = ["read"]
action = "allow"
overrides = "ssh-private-keys"
reason = "배포 대상 호스트 별칭을 읽어야 함"
```

이 완화는 정책 다이제스트에 반영되고, 다이제스트는 감사 로그 제네시스(genesis) 엔트리에 묶입니다. 곧 누가 언제 어떤 근거로 보호를 풀었는지 사후에 증명됩니다.

## 크레이트 구조

`airlock-policy`가 무엇을 허용할지 결정하고, `airlock-audit`이 무슨 일이 있었는지 기록하며, `airlock-broker`가 그 결정을 OS 경계에서 강제합니다.

- `crates/airlock` 플래그십 바이너리. `run`, `audit`, `policy`
- `crates/airlock-broker` OS 강제 층. `Enforcer` 트레이트와 플랫폼별 백엔드
- `crates/airlock-policy` capability 정책 모델과 평가 엔진
- `crates/airlock-audit` 해시체인 append-only 감사 로그와 검증
- `crates/airlock-canonical` 길이 접두 정규 인코딩. 아무것도 의존하지 않는 리프

의존은 한 방향으로만 흐릅니다. `airlock-canonical`이 바닥이고 그 위로 `airlock-audit`과 `airlock-policy`, 다시 그 위로 `airlock-broker`, 맨 위가 CLI인 `airlock`이 오며, 순환은 없습니다.

## 검증

```bash
$ ./scripts/check.sh
```

fmt, clippy(`-D warnings`), 전체 테스트, 라이브러리 코드 unwrap 및 expect 금지, 정책 프리셋 로드, 배포 메타데이터를 한 번에 확인합니다. CI(`.github/workflows/ci.yml`)가 Linux와 macOS에서 같은 스크립트를 돌리고, 여기에 더해 `x86_64`와 `aarch64` 교차 컴파일을 확인합니다. 중계 층은 아키텍처마다 seccomp arch 값과 syscall 번호가 다르므로 한 아키텍처에서만 컴파일되는 코드를 릴리즈에 넣지 않습니다. unwrap을 금지하는 이유는 브로커가 TCB이기 때문이며, 삼켜진 실패 경로 하나가 곧 강제 층의 구멍이 됩니다.

테스트는 규격 문서의 의무 사항을 그대로 따라가며, 주장에 그치지 않고 실제로 해 봅니다. 감사 로그는 실제로 변조된 체인을 만들어 탐지되는지 확인하고, 정책은 실제 심볼릭 링크와 경로 우회를 만들어 막히는지 확인하며, macOS 강제 층은 실제로 프로세스를 샌드박스에 넣고 시크릿 읽기가 거부되는지 확인합니다.

## 문서

- `docs/README.md` 문서 색인
- `docs/design.md` 전체 설계 (위협 모델, 아키텍처, 확정 결정, 기술 제약, MVP)
- `docs/policy-dsl.md` 정책 DSL 규격
- `docs/audit-format.md` 감사 로그 포맷 규격
- `SECURITY.md` 신고 경로와 무엇이 취약점이고 무엇이 알려진 한계인지
- `CHANGELOG.md` 변경 이력

설계 결정이 바뀌면 코드보다 먼저 `docs/`를 갱신합니다.

## 편리함을 위해

에이전트에게 정책을 생성 또는 수정하라 요청할 수도 있습니다. 다만 이러한 행위는 역설적으로 AI의 활동에서 보안성을 향상시킨다는 Airlock 프로젝트의 목적과 상충되기도 합니다.

정 원하시는 경우 그렇게 할 수도 있지만, 기본적으로 권장하지 않습니다.

## 라이선스

이 프로젝트는 AGPL-3.0 라이선스를 받습니다. [LICENSE](LICENSE) 파일에서 확인할 수 있습니다.

보안 도구는 소스 검증 가능성이 신뢰의 전제이므로 사용자가 자기 머신의 TCB를 직접 읽고 빌드해 확인할 수 있어야 한다 생각됩니다.
