# 기여 가이드

[![Language](https://img.shields.io/badge/CONTRIBUTING-English_Ver-blue?style=for-the-badge)](CONTRIBUTING.md)

Airlock은 사용자 머신의 신뢰 가능한 컴퓨팅 기반(TCB)입니다. 여기에 들어간 코드가 틀리면 사용자는 막혔다고 믿는 것이 막히지 않은 채로 에이전트를 돌리게 됩니다. 그래서 기여 기준이 일반 애플리케이션보다 빡빡합니다. 아래 규칙은 대부분 그 한 가지 이유에서 나옵니다.

## 시작하기 전에

- 발견된 취약점에 대해 [SECURITY.md](SECURITY.md)의 신고 경로를 따릅니다. 무엇이 취약점이고 무엇이 알려진 한계인지도 해당 문서에 있습니다.
- 설계 배경은 [INTRODUCTION.md](INTRODUCTION.md)와 [docs/design.md](docs/design.md)를 먼저 읽어주세요. 지금 강제되지 않는 것은 [docs/limitations.md](docs/limitations.md)에 근거와 코드 위치까지 적혀 있습니다.
- 강제 층, 정책 평가 순서, 감사 포맷을 바꾸는 변경은 코드를 쓰기 전에 이슈로 논의해 주세요. 오타 수정이나 테스트 추가는 바로 PR로 보내도 됩니다.
- 질문은 이슈, 이메일 <qtfelix@qu4nt.space> 또는 [Discord](https://discord.gg/9utg4hp3m8)로 알려주세요.

## 개발 환경

툴체인은 `rust-toolchain.toml`이 `1.95.0`으로 고정합니다. CI와 로컬이 같은 컴파일러를 쓰기 위한 것이므로 이 값을 우회하지 마세요. 워크스페이스의 `rust-version`(1.88)은 하한선이고, 에디션은 2024입니다. `scripts/metadata-check.py` 때문에 `python3`가 필요합니다.

강제 층 테스트는 플랫폼 전용이며 환경이 충족되지 않으면 조용히 건너뜁니다.

- Linux는 Landlock을 지원하는 커널(5.13 이상)이 필요하고, 컨테이너 안이라면 seccomp 필터를 걸 수 있어야 합니다.
- macOS는 Seatbelt 백엔드가 그대로 돕니다.
- 한쪽 OS에서만 검증했다면 PR에 그 사실을 적어 주세요. 건너뛴 테스트는 통과가 아닙니다.

## 검증

올리기 전에 다음 명령을 실행하시면 됩니다.

```bash
$ ./scripts/check.sh
```

이 스크립트가 확인하는 것은 다음과 같습니다.

| 단계        | 내용                                                      |
|-----------|---------------------------------------------------------|
| fmt       | `cargo fmt --all -- --check`                            |
| clippy    | `cargo clippy --workspace --all-targets -- -D warnings` |
| test      | `cargo test --workspace --no-fail-fast`                 |
| unwrap 금지 | 라이브러리 코드(테스트 제외)에 `unwrap()` `expect(`가 없는지             |
| 정책 프리셋    | `examples/policy/*.toml`이 전부 로드되는지                      |
| 배포 메타데이터  | 크레이트 `description`과 의존 `version` 누락 여부                  |

CI(`.github/workflows/ci.yml`)는 Linux와 macOS에서 같은 스크립트를 돌리고, 여기에 `cargo-deny`(권고, 라이선스, 소스)와 `x86_64` `aarch64` 교차 컴파일을 더합니다. 중계 층은 아키텍처마다 seccomp arch 값과 syscall 번호가 다르므로 한쪽에서만 컴파일되는 코드는 들어갈 수 없습니다.

반복 작업 중에는 `cargo check --workspace`나 `cargo test -p <크레이트>`로 좁혀 돌리고, 올리기 직전에 전체를 한 번 실행해주세요.

## 워크스페이스 규칙

워크스페이스 개별 크레이트의 의존(dependency)은 한 방향으로만 흐르고 사이클은 없습니다.

```
airlock-canonical -> airlock-audit, airlock-policy -> airlock-broker -> airlock
```

- `crates/airlock` CLI 진입점 (`run`, `audit`, `policy`, `setup`)
- `crates/airlock-broker` OS 강제 층. Linux Landlock + seccomp, macOS Seatbelt
- `crates/airlock-policy` capability 정책 모델과 평가 엔진
- `crates/airlock-audit` 해시체인 append-only 감사 로그
- `crates/airlock-canonical` 길이 접두 정본 인코딩. 아무것에도 의존하지 않는 리프
- `crates/airlock-proxy` egress 프록시
- `crates/airlock-setup` 대화형 정책 마법사. UI 의존성(cliclack, console)은 이 크레이트 밖으로 나가지 않습니다

새 크레이트는 `crates/` 아래에 두면 멤버 glob이 인식합니다. 버전과 에디션, 라이선스는 워크스페이스에서 상속하고, 내부 크레이트는 `Cargo.toml`의 `workspace.dependencies`에 `path`와 `version`을 **둘 다** 적습니다. `version`이 없으면 crates.io 업로드가 거부됩니다.

`airlock-setup`의 프리셋은 `examples/policy` 사본이며 테스트가 동기화를 강제합니다. 예제 정책을 고쳤으면 프리셋도 같이 고쳐야 합니다.

## 코드 규약

- 주석과 Docstring은 기본적으로 쓰지 않습니다. 쓸 때는 한국어로, 코드가 하는 일이 아니라 **왜 그렇게 하는지**를 적습니다. 저장소의 기존 주석이 기준입니다.
- 라이브러리 코드에 `unwrap()`과 `expect(`를 쓰지 않습니다. 브로커가 TCB이므로 삼켜진 실패 경로 하나가 강제 층의 구멍입니다. 실패는 타입으로 돌려주세요.
- `unsafe`는 최소화하고 쓸 때는 `# Safety` 헤더로 근거를 남깁니다. panic 조건은 `# Errors` 또는 `# Panics`로 밝힙니다.
- **fail-closed.** 판단할 수 없으면 허용이 아니라 거부입니다. 주소를 읽지 못한 `connect`, 정규화할 수 없는 경로, 지원하지 않는 ABI는 전부 거부 쪽으로 붙습니다.
- 신뢰할 수 없는 값(에이전트 argv, 정책 파일 문자열, 호스트 이름, 네트워크 페이로드)은 화면이나 로그에 나가기 전에 `airlock-canonical`의 정제를 거칩니다. 제어 문자와 양방향 재정렬 문자가 사람이 읽는 줄을 조작하지 못하게 하기 위한 것입니다.
- 릴리즈 프로파일은 `overflow-checks = true`, `panic = "abort"`입니다. 오버플로를 성능 이유로 끄자는 제안은 받지 않습니다.
- 의존성 추가는 보수적으로 판단합니다. `deny.toml`의 라이선스 allowlist 안에 있어야 하고 와일드카드 버전은 금지입니다. TCB 크레이트(`broker`, `policy`, `audit`, `canonical`)에 의존을 늘리는 변경은 PR에 근거를 적어 주세요.

## 테스트 규약

테스트는 주장하지 말고 실제로 해야 합니다. 저장소의 기존 테스트가 기준선입니다.

- 감사 테스트는 실제로 변조된 체인을 만들어 탐지되는지 봅니다 (`crates/airlock-audit/tests/tamper.rs`).
- 정책 테스트는 실제 심볼릭 링크와 경로 순회, 유니코드 케이스 별칭을 만들어 막히는지 봅니다 (`crates/airlock-policy/tests/bypass.rs`).
- 강제 층 테스트는 실제 프로세스를 샌드박스에 넣고 시크릿 읽기가 거부되는지 봅니다 (`crates/airlock-broker/tests/`).

새 규칙이나 강제 기능을 넣었다면 **그 기능을 우회하려는 테스트**를 같이 포함하세요. 회귀를 고칠 때는 재현 테스트를 먼저 쓰고, 그 테스트가 수정 전에 실패하는지 확인하세요.

## 보안 경계를 건드리는 변경

`airlock-broker`, `airlock-policy`, `airlock-audit`, `airlock-canonical`을 고친다면 아래를 확인해 주세요.

- 정책 평가 티어 순서(자기보호 -> 내장 forbid -> 사용자 규칙 -> 내장 ask/deny -> defaults)는 바꾸지 않습니다. 사용자 규칙이 내장 forbid를 `overrides` 없이 완화할 수 있게 되는 변경은 그 자체로 취약점입니다.
- **강제되지 않는 것은 gap으로 선언해야 합니다.** 문서에만 적는 것은 안 됩니다. `airlock run` 배너와 감사 로그에 드러나야 하고, 강제되지 않은 규칙이 강제된 것처럼 보고되면 취약점입니다.
- 감사 로그 인코딩을 바꾸면 `docs/audit-format.md`를 먼저 고치고, 기존 체인을 다시 검증할 수 없게 되는지 CHANGELOG에 명시합니다.
- 규칙 id 문자 제약, 경로 정규화(NFC, 대소문자 접기, 심볼릭 링크, NUL, firmlink), 글로브 매칭은 전부 우회 표면입니다. 여기를 건드리면 해당 우회 시도 테스트가 따라와야 합니다.
- 승인 프롬프트는 에이전트가 만든 문자열을 브로커가 관측한 사실처럼 보여 주면 안 됩니다. 승인 채널(`/dev/tty`)은 자식에게 넘기지 않습니다.
- 외부 입력은 전부 신뢰 불가로 다룹니다. 에이전트 tool call, MCP 메시지, 정책 파일, 프록시로 들어온 페이로드가 여기에 해당합니다.

## 문서

- 설계 결정이 바뀌면 코드보다 `docs/`를 먼저 갱신합니다.
- `docs/audit-format.md`, `docs/policy-dsl.md`, `docs/egress-proxy.md`는 규격이며 정본입니다. 코드와 어긋나면 규격이 옳습니다.
- 한국어와 영어 문서는 쌍으로 유지합니다. `README.md` / `README_KR.md`, `SECURITY.md` / `SECURITY_KR.md`, `CONTRIBUTING.md` / `CONTRIBUTING_KR.md` 중 한쪽만 고치지 마세요.
- 사용자에게 보이는 동작이 바뀌면 `CHANGELOG.md`의 "출시 이전" 절에 추가합니다. 형식은 Keep a Changelog입니다.
- 한국어 문서에서는 유니코드 화살표 대신 `->` `<-`를 쓰고 em dash는 쓰지 않습니다.

## 커밋과 PR

커밋 메시지는 한국어로, 한 줄 요약에 필요하면 `-` 목록을 붙입니다. `feat` `chore` 같은 접두사와 마침표는 쓰지 않습니다.

```
정책 평가에서 케이스 별칭 우회 차단

- NFC 정규화 뒤 대문자 접기로 U+017F 표기를 잡음
- 대소문자 무구분 마운트 회귀 테스트 추가
```

커밋에 넣지 말아야 할 것은 다음과 같습니다.

- `airlock.toml` 등 개인 정책 파일 (`.gitignore` 대상)
- 감사 로그 세션 디렉토리. 경로에 시크릿이 담깁니다
- `target/`, 에디터 설정, 로컬 실험용 디렉토리

PR은 `master`를 타겟으로 보내고 본문에 다음을 포함해 주세요.

- 무엇을 왜 바꿨는지, 그리고 이 변경이 신뢰 경계를 바꾸는지
- 어느 OS에서 검증했는지, 건너뛴 테스트가 있는지
- 강제 범위나 정책 의미론이 바뀌었다면 갱신한 문서 위치

CI 세 잡(check, dependency audit, cross compile)이 전부 통과해야 병합합니다.

## 도움이 필요한 곳

`docs/limitations.md`가 사실상 TODO 목록입니다. 특히 다음이 열려 있습니다.

- Linux의 network namespace 격리. 지금은 자식이 프록시를 건너뛰고 같은 포트로 직접 나갈 수 있습니다
- macOS 자식 프로세스 관측. 중계 기구가 없어 `airlock run`이 직접 띄운 프로세스 하나만 감사에 남습니다
- MCP 프록시 층
- 예제 정책과 프리셋. 실제로 쓰는 에이전트 환경에서 나온 정책이 특히 도움이 됩니다

## 라이선스

기여물은 프로젝트와 같은 AGPL-3.0-only로 배포됩니다. PR을 보내면 이에 동의하는 것으로 봅니다. 보안 도구는 소스 검증 가능성이 신뢰의 전제이므로, 사용자가 자기 머신의 TCB를 직접 읽고 빌드해 확인할 수 있어야 합니다.
