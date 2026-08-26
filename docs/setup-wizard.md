# 대화형 설정 마법사 `airlock setup`

정책 파일을 손으로 쓰지 않고 질문 몇 개로 만드는 진입점이다. 정책 DSL을 모르는 사용자가 airlock을 쓰기 시작하는 기본 경로로 삼는다.

## 크레이트 구조

- `crates/airlock-setup` 마법사 엔진. 질문 흐름 · 프리셋 레지스트리 · 정책 생성 · 터미널 스타일.
- `crates/airlock`의 `cmd_setup.rs`는 CLI 배선만 한다. 다른 서브커맨드와 같은 패턴이다.

대화형 UI 의존성(cliclack, console, toml_edit)은 `airlock-setup`에만 둔다. 강제 층(`airlock-broker`)과 정책 엔진(`airlock-policy`)의 의존성 트리에는 UI 의존성이 절대 들어가지 않는다. TCB 경계를 `cargo tree`로 감사할 수 있게 유지하기 위함이다.

## 흐름

1. 시작 방식 선택 (claude-code / strict / developer 프리셋 또는 직접 설정)
2. 작업 공간 경로 입력 (기본값 cwd, 절대 경로 또는 `~` 경로만 허용, 홈 전체면 경고)
3. 출력 경로 결정 (기본 `./airlock.toml`, 기존 파일은 명시적 확인 없이 덮어쓰지 않음)
4. 생성 후 `Policy::load_str`로 검증. 검증을 통과하기 전에는 파일을 쓰지 않는다
5. 요약과 함께 바로 실행할 `airlock run` 명령을 안내

### 직접 설정

프리셋 없이 질문으로 정책을 처음부터 구성한다.

- 정책 이름 (기본값은 cwd 디렉토리 이름)
- 기본 동작 3종. file은 deny/ask/allow, exec는 ask/allow/deny, egress는 deny/ask만 제시한다. `[defaults].egress = "allow"`는 DSL이 문법 수준에서 금지하므로 선택지에 없다
- 시스템 툴체인 읽기·실행과 빌드 캐시 접근 여부 (file 기본이 allow면 불필요하므로 묻지 않음)
- 허용할 아웃바운드 호스트 목록. `host` 또는 `host:port` 형식을 빈 입력이 나올 때까지 반복 입력받고 기본 포트는 443, 중복은 걸러낸다

생성은 프리셋과 달리 toml_edit로 문서를 처음부터 조립하며(`custom.rs`), 파일 머리에 출처 주석과 함께 egress 규칙이 있으면 `--egress-proxy` 없이는 호스트 강제가 없다는 경고 주석을 남긴다. 규칙 id는 호스트를 슬러그로 바꿔 만들고(`egress-api-anthropic-com`), 443이 아닌 포트는 id 뒤에 붙인다.

## 프리셋

`examples/policy/*.toml`이 원본이다. crates.io 패키징이 패키지 루트 밖 파일을 담지 못하므로 `crates/airlock-setup/presets/`에 사본을 두고, 두 벌이 어긋나면 테스트(`presets_stay_in_sync_with_examples`)가 실패한다.

프리셋의 주석은 단순 설명이 아니라 보안 근거(Seatbelt egress 한계 등)를 담고 있다. 그래서 생성은 serde 직렬화가 아니라 toml_edit 기반이다. 프리셋 원문에서 출발해 값만 바꾸므로 주석이 그대로 보존된다. 현재 치환 지점은 `id = "workspace"` 규칙의 `path` 하나다.

## 스타일

cliclack의 `Theme` 트레이트를 `AirlockTheme`로 구현한다. 액센트는 256색 173(웜 코랄) 하나로 통일하고 `theme.rs`의 `ACCENT` 상수로만 바꾼다. 취소는 빨강, 오류는 노랑을 유지한다.

## 보안 규칙

- TTY가 아니면 실행을 거부한다 (종료 코드 2)
- 검증 실패 시 파일을 쓰지 않는다
- 덮어쓰기 확인의 기본값은 거부다
- 시크릿 경로 deny 기본값은 프리셋(베이스라인)이 유지하며 마법사는 완화 질문을 하지 않는다

## 로드맵

- 비대화형 모드 `airlock setup --preset <id> --yes` (CI · 스크립트용)
- egress 허용 호스트 추가 질문
- Codex 등 에이전트 프리셋 확장
- `airlock run` ask 승인 흐름과의 연계 안내
