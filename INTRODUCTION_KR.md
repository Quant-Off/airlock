# Airlock 소개

[![Language](https://img.shields.io/badge/INTRODUCTION-English_Ver-blue?style=for-the-badge)](INTRODUCTION.md)

[README.md](README.md)가 프로젝트 개요와 빠른 시작을 다룬다면, 이 문서는 Airlock이 실제로 무엇을 보장하고 무엇을 보장하지 않는지, 정책과 감사 로그가 어떻게 맞물리는지, 코드가 어떻게 구성되어 있는지를 설명합니다.

## 무엇을 보장하는가

아래 표는 현재 구현 상태이자 남은 작업 목록이기도 합니다.

| 항목                                           |    상태    | 비고                                                              |
|------------------------------------------------|:----------:|-------------------------------------------------------------------|
| 해시체인 감사 로그와 변조 탐지                 | **구현됨** | 검증기 포함                                                       |
| capability 정책 모델과 TOML DSL                | **구현됨** |                                                                   |
| 경로 정규화 (traversal, 심볼릭 링크, 대소문자) | **구현됨** |                                                                   |
| macOS 커널 강제 (Seatbelt)                     | **구현됨** | 파일, exec 경로, 아웃바운드 전체                                  |
| `/dev/tty` 인라인 ask 승인                     | **구현됨** | 응답 상한 있음, 초과 시 거부                                      |
| Linux 커널 강제 (Landlock)                     | **구현됨** | 파일, TCP 포트                                                    |
| 런타임 중계 (seccomp user notification)        | **구현됨** | **Linux 전용.** 자식 프로세스의 exec/연결/파일 열기를 감사에 남김 |
| 호스트 단위 egress 강제 (macOS)                | **구현됨** | `--egress-proxy`. 아웃바운드를 로컬 프록시 하나로 좁힘            |
| 호스트 단위 egress 강제 (Linux)                |   부분적   | 포트 축소까지만. netns 격리 전까지 우회 가능                      |
| egress DLP (시크릿 패턴 차단)                  |   미구현   | 프록시가 TLS를 종단하지 않음                                      |
| MCP 프록시 층                                  |   미구현   |                                                                   |

## 플랫폼별 강제 범위

강제 범위는 플랫폼마다 다르며, 같은 정책 파일이 두 OS에서 같은 결론을 내지는 않습니다. 정확한 차이는 아래와 같습니다.

| 정책 종류                    | Linux (Landlock + seccomp)                    | macOS (Seatbelt)                       |
|------------------------------|-----------------------------------------------|----------------------------------------|
| 파일 경로                    | 커널 강제 (inode 단위)                        | 커널 강제 (정규 경로 단위)             |
| exec 경로/파일 이름          | 커널 강제 없음. 중계 층이 기록하고 `ask` 승인 | **커널 강제** (`deny`만, `ask`는 아님) |
| exec argv 조건 (`rm -rf` 등) | 중계 층이 기록하고 `ask` 승인                 | 강제/기록 안 됨                        |
| 아웃바운드 전체 차단         | 커널 강제                                     | 커널 강제                              |
| 포트 단위 egress             | 커널 강제 (ABI v4 이상)                       | 강제 안 됨                             |
| 호스트 단위 egress           | `--egress-proxy`로 관측. 우회 가능            | `--egress-proxy`로 **커널 강제**       |
| 자식 프로세스 행위 기록      | `--mediate`로 켜짐 (기본 exec/연결)           | **기록 안 됨.** 중계 기구가 없음       |

곧 macOS에서는 `airlock run` 이 직접 띄운 프로세스 하나만 감사에 남고, 그 아래 자식들이 무엇을 실행하고 어디로 연결했는지는 남지 않습니다. `--mediate` 값은 macOS에서 적용되지 않으며, 그 사실이 배너와 감사 로그 제네시스 양쪽에 기록됩니다.

미구현 항목을 문서에만 적어 두지는 않으며, `airlock run`은 시작할 때 그 세션에서 무엇이 강제되지 않는지 직접 출력합니다.

```
airlock 0.1.0
  정책     baseline (22 규칙, 다이제스트 ae70ec11fe7a)
  강제     seatbelt (sandbox_init_with_parameters)
  중계     off (요청 exec-net)
  작업공간  /Users/me/work/proj
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

TOML 기반 선언적 DSL입니다.

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
0. 자기보호 규칙        감사 로그와 정책 파일 쓰기 금지. 예외 불가
1. 내장 forbid 규칙    시크릿 경로. overrides 로 지목해야만 열림
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

시크릿 보호에 예외를 두려면 어떤 규칙을 여는지 명시하고 근거를 남겨야 합니다. 근거가 없으면 로드가 실패합니다.

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

이 예외는 정책 다이제스트에 반영되고, 다이제스트는 감사 로그 제네시스(genesis) 엔트리에 묶입니다. 곧 누가 언제 어떤 근거로 보호를 열었는지 사후에 증명됩니다.

## 크레이트 구조

`airlock-policy`가 무엇을 허용할지 결정하고, `airlock-audit`이 무슨 일이 있었는지 기록하며, `airlock-broker`가 그 결정을 OS 경계에서 강제합니다.

- `crates/airlock` 플래그십 바이너리. `run`, `audit`, `policy`
- `crates/airlock-broker` OS 강제 층. `Enforcer` 트레이트와 플랫폼별 백엔드
- `crates/airlock-policy` capability 정책 모델과 평가 엔진
- `crates/airlock-audit` 해시체인 append-only 감사 로그와 검증
- `crates/airlock-proxy` 로컬 egress 프록시. 호스트 단위 아웃바운드 판정
- `crates/airlock-canonical` 길이 접두 정규 인코딩. 아무것도 의존하지 않는 리프

의존은 한 방향으로만 흐릅니다. `airlock-canonical`이 바닥이고 그 위로 `airlock-audit`과 `airlock-policy`, 다시 그 위로 `airlock-proxy`와 `airlock-broker`, 맨 위가 CLI인 `airlock`이 오며, 순환은 없습니다.

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
- `docs/egress-proxy.md` egress 프록시 층 규격
- `docs/policy-guide.md` 정책 작성 가이드
- `docs/limitations.md` 현재 구현의 전체 한계 목록
- `SECURITY.md` 신고 경로와 무엇이 취약점이고 무엇이 알려진 한계인지
- `CHANGELOG.md` 변경 이력

설계 결정이 바뀌면 코드보다 먼저 `docs/`를 갱신합니다.
