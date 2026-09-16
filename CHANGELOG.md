# 변경 이력

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고 버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.

## 출시 이전

### 추가

- **`--mediate full`이 rename과 link 계열을 중계함.** `rename`, `renameat`, `renameat2`, `link`, `linkat`, `symlink`, `symlinkat`을 원본 `delete`와 목적지 `create`로 판정하며 하나라도 deny면 거부함. 같은 디렉토리 안 `rename`으로 자기보호 대상 정책 파일을 갈아 끼우는 경로가 이 수준에서 닫힘. 기본 수준 `exec-net`에는 넣지 않음
- **Linux seccomp 필터가 모든 중계 수준(`off` 포함)에서 `ioctl(TIOCSTI)`와 `ioctl(TIOCLINUX)`를 EPERM으로 거부함.** 자식이 상속한 터미널에 입력을 밀어 넣어 ask 승인 프롬프트를 위조하는 경로를 닫음. macOS는 Seatbelt가 이미 거부함. 정상 프로그램은 두 ioctl을 쓰지 않으며 bubblewrap과 flatpak이 같은 조치를 함
- **출력 로케일 (한국어·영문).** 모든 사람용 출력(CLI 도움말, 배너와 한계 목록, 승인 프롬프트, 감사 보고, 마법사, 생성되는 정책 파일의 주석)이 로케일을 따름. 결정 순서는 `AIRLOCK_LANG` -> `~/.config/airlock/config.toml`의 `locale` 키 -> `LC_ALL`/`LC_MESSAGES`/`LANG` 접두 -> 기본 한국어. 기계 판독 필드(JSON 키, `kind`·`status`·`verdict`, 스키마 이름, 규칙 id)와 **정책 다이제스트는 로케일과 무관하게 고정**임. 자세한 것은 `docs/i18n.md`
- **`airlock setup` 첫 질문이 언어 선택.** 답하는 즉시 나머지 질문이 그 언어로 나가고 선택이 구성 파일에 저장됨. 영문 프리셋(`examples/policy/en/*.toml`)이 추가되었으며 한국어판과 주석만 다르고 다이제스트가 같음을 테스트가 강제함
- `airlock audit report --json` 최상위에 `locale` 필드 추가. 이상 `detail` 산문이 로케일을 따르므로 리포트 본문 다이제스트가 생성 로케일에 묶이며, `report`와 `ack`는 같은 로케일에서 돌려야 함 (`docs/limitations.md` 7.18)
- **`airlock audit report`. 매일 이상여부 점검.** 범위 안의 모든 세션을 검증하고 결정·승인·거부된 exec·목적지별 아웃바운드를 집계해 한 번에 보고함. `--since`/`--until`은 그 날을 통째로 덮고, `--json`은 색상 코드 없는 안정된 스키마(`airlock.audit-report.v1`)로 나감. **이상이 하나라도 있으면 종료 코드가 비영**이므로 cron 이나 launchd 에 그대로 걸 수 있음. 종료 코드는 0 이상 없음, 2 증거 이상, 3 운영 이상, 64 인자 오류, 70 내부 오류임
- **판단 불가를 통과로 보고하지 않음.** 앵커 없음, 세션을 읽지 못함, 확인 체인 손상, **앵커에는 있는데 디렉토리가 없는 세션**을 전부 증거 이상으로 셈. 마지막 항목이 세션 통째 삭제를 잡으며, 남은 세션만 훑는 보고로는 그것이 "이상 없음" 으로 나옴
- **승인 집계가 사람 신원 있는 응답과 없는 응답을 나눔.** `--yes` 자동 승인은 `approver_uid`·`approver_tty`가 둘 다 없으므로 여기서 갈리며, 사람 확인처럼 보이지 않음. `--strict-approval`은 신원 없이 **허용된** 건만 이상으로 셈. 신원 없는 거부는 아무것도 통과시키지 않았으므로 세지 않음
- **`airlock audit ack`. 책임자 확인 기록.** 새 append-only 체인 `<감사루트>/reviews.jsonl`에 확인자 uid·euid(커널에서 직접 읽음), 관측된 터미널, 점검 범위, 세션 목록, **점검한 리포트의 다이제스트**, 판정을 남김. 도메인은 `airlock.review.v1\x00`으로 감사·앵커 체인과 분리해 교차 프로토콜 재사용을 막음
- **확인 도장이 범위에 묶임.** 기록되는 다이제스트가 `H(도메인 || 범위 || 본문)`이라 다른 범위에서 계산한 리포트에 같은 도장을 옮겨 찍을 수 없음. `ack`는 리포트를 다시 계산해 기록하며 호출자가 다이제스트를 넘기는 경로가 없음
- `airlock audit report`가 마지막 확인 시각과 확인자를 함께 보여 주고, **마지막 확인 이후 새 세션이 있으면 그 사실을 드러냄.** 확인 기록이 아예 없으면 "확인 기록 없음" 으로 보고하되 종료 코드는 올리지 않음. `reviewer_tty`가 없는 확인은 "터미널 미관측" 으로 표시하며 사람이 앉아 있었다는 근거로 쓰지 않음
- **`Event::EgressSummary` 방출.** egress 프록시가 연결 하나가 끝날 때 방향별 바이트와 지속 시간을 남김. `egress`가 시도와 판정이라면 이것은 결과이며, `decision`은 `allow`고 `rule`은 예약 id `airlock:egress-summary`로 판정이 아님을 밝힘. **방향별 바이트를 세지 못한 연결에는 훅을 부르지 않음.** 0은 "아무것도 나가지 않았다"는 사실 주장이라 모르는 것을 0으로 기록하지 않음
- **`max_bytes_out`. 총량 기반 차단.** `kind = "egress"` 규칙에 누적 반출 상한을 적을 수 있음. 초과 시 결정은 **`deny`로 고정**되며(`ask`로 두면 `--yes`가 무력화함) 감사 로그의 규칙 id가 `airlock:egress-quota`가 되고 한도·누적량·원래 규칙 id가 매칭 표기에 남음. **바이트 수는 연결이 끝나야 알 수 있으므로 한도를 넘긴 그 연결 자체는 막지 못하고 다음 연결부터 막힘**
- `airlock:` 이름 공간을 사용자 규칙 id 에서 통째로 예약함. 나중에 늘어나는 합성 id 하나를 예약 목록에 넣는 것을 잊어도 그 이름을 가져갈 수 없음
- **exec 화이트리스트.** `[defaults].exec`이 `allow`가 아닌 정책에서는 macOS Seatbelt와 Linux Landlock 모두 exec을 블랙리스트가 아니라 커널 화이트리스트로 걸음. `kind = "exec"` allow 규칙과 최상위 프로그램만 실행되고 나머지는 커널이 `execve`를 거부함. 프로그램 경로가 처음으로 커널 경계가 되었으며 argv 조건은 여전히 중계 층의 tripwire임
- **감사 포맷 v2와 세션 상위 앵커 체인.** 세션 종료 시 `<감사루트>/anchors.jsonl`에 최종 head를 잇는 append-only 줄을 남김. 세션 디렉토리 통째 삭제, 체인 재계산, 종료 뒤 덧붙이기가 탐지 가능해짐. `airlock run --anchor-dir <DIR>`로 다른 볼륨이나 원격 마운트로 분리할 수 있으며, **같은 트리에 두면 체인을 재계산할 수 있는 주체가 앵커도 같은 비용으로 재계산하므로 실질 탐지력이 없다는 사실을 배너가 직접 말함**
- `airlock audit verify`가 앵커 체인을 함께 검증하고 세션 head와 대조함. 앵커 파일이 없으면 통과가 아니라 "탐지 불가"로 표시하며, `--anchor-dir`로 분리한 앵커 루트를 지정할 수 있음
- **egress 프로토콜 축.** `egress` 규칙에 `protocol = "tcp"|"tls"|"http"`가 생기고 `[defaults].egress_plaintext`(기본 `deny`)가 평문 아웃바운드의 상한이 됨. 호스트만 적은 `allow`는 평문까지 열지 않으며, 평문이 막히면 감사 로그의 `rule`이 합성 규칙 `airlock:egress-plaintext`가 되고 원래 매칭된 규칙 id가 매칭 표기에 남음. 판정 지점은 정책 엔진 하나이며 프록시에는 하드코딩된 거부가 없음
- `airlock policy explain --host`에 `--protocol <tcp|tls|http>` 추가. 기본값은 `tcp`이며 평문 바닥이 결정을 바꿨는지를 출력에 드러냄
- **감사 엔트리의 `actor`가 실제 행위 주체가 됨.** 중계 층이 관측한 자손 pid를 `pid:<pid>`로 남기고, 브로커가 직접 부른 판정은 세션 actor를, 주체를 모르는 프록시 경로는 `airlock:unknown-peer`를 씀. 세 경우가 로그에서 구분됨
- **승인자 신원.** `Approval` 엔트리에 `approver_uid`(`geteuid(2)`)와 `approver_tty`(실제 터미널 장치 경로)가 들어감. 브로커가 직접 관측한 값만 넣으며, `--yes` 자동 승인은 **반드시 둘 다 `None`**이라 사람이 승인한 것처럼 보이지 않음. 이 구분은 테스트로 고정됨
- 제네시스에 `operator`와 `policy_signer` 자리 추가. 관측 경로가 없어 지금은 항상 `None`
- `Event::EgressSummary`(태그 `0x13`) 타입 추가. 방출자는 egress 프록시 층 하나임
- 배너가 exec 화이트리스트를 반영한 규칙 수와 gap을 보여 줌. 최상위 프로그램을 `prepare` 시점에 알려 주어 표시가 실제로 걸릴 프로파일과 어긋나지 않음
- 배너가 프록시 없는 세션의 평문 격차를 노출함. 중계 층은 `connect(2)`만 보므로 모든 연결이 `protocol=tcp`이고, 그 세션에서는 `protocol` 조건 규칙이 아무것도 매칭하지 않으며 평문 바닥도 발동하지 않음
- `airlock audit show`가 `egress_summary` 이벤트와 승인자 신원을 출력함. 신원이 없는 승인은 "승인자없음(사람 확인 아님)"으로 표시
- macOS에서 exec 제한 규칙을 `process-exec*` 차단으로 커널까지 내림. 경로와 파일 이름 조건이 강제되며 argv 조건은 표현할 수 없어 한계로 노출됨
- 감사 로그 제네시스에 중계 수준(`mediation`)을 기록. `exec` 엔트리가 없는 체인이 "아무 일도 없었음"인지 "중계가 꺼져 있었음"인지 구분됨
- 배너가 실제로 적용된 중계 수준과 작업 공간을 표시하고, 요청값이 무시되면 그 사실을 한계로 출력
- `ask` 승인에 응답 상한(기본 300초). 초과하면 `timed_out`으로 거부하며, 중계 중 감독 스레드가 세션 잠금을 쥔 채 멈추지 않음
- 작업 공간이 홈 전체나 파일시스템 루트가 되는 실행을 막음. 홈은 `--workspace`로 명시하면 경고와 함께 진행
- `Session` 계층 통합 테스트, CLI 통합 테스트, Landlock 심볼릭 링크 회귀 테스트, 나열 불가 디렉토리 테스트
- GitHub Actions CI. Linux와 macOS에서 `scripts/check.sh`를 돌림
- `SECURITY.md`, `CHANGELOG.md`, `rust-toolchain.toml`, 라이브러리 크레이트 `description`

### 수정

- **macOS 프록시 모드가 유닉스 도메인 소켓을 통째로 열던 문제.** `(allow network-outbound (remote unix))`를 무조건 방출해 샌드박스 안 프로세스가 바깥 유닉스 소켓 리스너로 데이터를 내보내고 상속된 `SSH_AUTH_SOCK`으로 ssh-agent에 서명을 요청할 수 있었으며, 살아 있는 docker.sock이면 컨테이너 데몬에 닿았음. 전부 프록시도 감사 로그도 거치지 않았음. 이제 `/private/var/run/mDNSResponder`와 `/private/var/run/syslog` 리터럴 두 개만 열고 배너와 `gaps()`에 그 목록을 드러냄. 자식 환경에서 `SSH_AUTH_SOCK`과 `DOCKER_HOST`를 벗김
- **앵커 재앵커링으로 종료 뒤 덧붙이기가 탐지되지 않던 문제.** 같은 세션의 두 번째 앵커 줄이 경고로만 남아, 체인과 앵커 파일에 append만 할 수 있는 공격자가 종료된 세션에 엔트리를 덧붙이고 새 앵커 한 줄로 검증을 통과시킬 수 있었음. 세션당 앵커는 정확히 하나이며 초과는 실패임. 앵커 뒤 엔트리(`entries_after_anchor`), `session_end` 뒤 엔트리, 앵커된 세션의 `head.json` 뒤처짐(`anchored_head_lag`, `fsync_per_entry = false`만 예외)이 전부 검증 실패와 증거 이상이 됨. `Session::finish()`를 두 번 부르면 오류
- **상대 심볼릭 링크 대상을 어휘적 부모에 붙여 해소하던 문제.** 심볼릭 링크된 디렉토리 아래의 `x -> ../id_rsa`를 커널은 링크 대상 쪽 파일로 여는데 엔진은 작업 공간 안 경로로 계산해 작업 공간 규칙으로 허용했음. 상대 대상은 해소된 부모에 붙이고, 매달린 링크도 같은 기준으로 계산함
- **macOS `/System/Volumes/Data/...` 표기가 전 티어를 비껴가던 문제.** firmlink 때문에 같은 파일의 두 번째 철자가 자기보호와 `~/.ssh/**` forbid에 매칭하지 않았음 (커널 Seatbelt는 막았지만 정책 판정, `explain`, `--observe`, 감사 귀속이 틀렸음). `/usr/share/firmlinks` 표(못 읽으면 내장 목록)에 있는 대상을 루트 표기로 접으며 요청 경로와 규칙 경로 양쪽에 적용함. 정책 다이제스트는 바뀌지 않음
- **프록시 평문 전달 경로의 bare-LF 요청 스머글링.** 헤드를 `\r\n`으로만 잘라 줄 안의 `\n`이 값에 남았고 그것이 업스트림에 그대로 재조립되어 두 번째 `Host`를 심을 수 있었음. CRLF 쌍이 아닌 CR과 LF, 헤더 값의 제어문자, obs-fold, 중복 `Host`, `HTTP/1.0`과 `HTTP/1.1` 이외의 버전, 비ASCII 호스트를 판정 전에 400으로 거부하고 업스트림에 접속하지 않음
- **중계 층이 `dirfd`를 부호 있는 64비트로 읽던 문제.** 커널은 하위 32비트만 보므로 상위 비트를 세운 값이 `AT_FDCWD`로 해석되어야 하는데 기준을 잃고 브로커 cwd에 붙였음. 커널과 같이 읽고 기준을 못 찾으면 거부함
- **Landlock 순회 예산이 루트 전체에서 공유되어 뒤쪽 루트가 통째로 빠지던 문제.** `/usr` 아래 큰 트리(안드로이드 SDK, CUDA 등)가 예산 20만을 다 쓰면 그 뒤의 `/bin`, `/sbin`, `/lib`, `/etc`, 작업 공간이 규칙을 하나도 못 받아 프로그램이 exec 조차 되지 않았음. 예산을 루트마다 새로 주고, 예산이 끊겨도 그 전에 검사를 마친 항목은 규칙을 받게 함
- **나열할 수 없는 디렉토리가 개별 허용 단계에서 도로 열리던 문제.** 순회는 `Denied`로 판정했지만 매칭되는 규칙이 없어 `blocked`가 false 라, 하위를 검사하지도 못한 채 규칙을 받았음. 순회 결과를 기억해 개별 허용에서 제외함
- **순회 순서가 `read_dir` 반환 순서에 의존하던 문제.** 파일시스템 해시 순서라 같은 정책이 머신마다 다른 강제 범위를 냈음. 이름 순으로 고정함
- **부분 강제 경고가 늘 켜져 있던 문제.** 디렉토리 전용 권한(`ReadDir` 등)을 일반 파일과 `/dev/null` 같은 장치에 걸어 커널이 EINVAL을 내고 크레이트가 ruleset을 `PartiallyEnforced`로 표시했음. 대상 종류에 맞는 권한만 걸어, 커널이 실제로 기능을 못 거는 경우와 구분됨
- **Landlock 심볼릭 링크로 정책 밖 트리가 열리던 문제.** 부분 허용 디렉토리의 링크 자식이 계획에 들어가 규칙이 링크 **대상** inode에 걸렸음. 링크는 계획에서 제외하고 순회로 발견한 경로는 `O_NOFOLLOW`로 연다
- **나열할 수 없는 디렉토리를 통째로 허용하던 문제.** `read_dir` 실패를 파일, 순회 중 사라진 항목, 열 수 없는 디렉토리로 나누어 마지막 경우만 허용에서 제외하고 한계로 보고
- **seccomp 필터가 아키텍처 불일치를 통과시키던 문제.** 32비트 바이너리가 exec/connect 중계를 우회해 `ask` 승인을 건너뛸 수 있었음. 이제 중계할 수 없는 ABI는 프로세스를 죽이며 x86_64의 x32 번호 체계도 함께 막음
- **`connect` 주소를 읽지 못했을 때 허용하던 문제.** 유닉스 소켓 통과와 판단 불가를 구분해 후자는 거부. `exec`과 `open`과 방향이 같아짐
- **macOS 프로파일이 `[defaults].egress = "deny"`와 모순되던 문제.** egress allow 규칙이 없으면 아웃바운드를 통째로 차단함. 같은 정책이 Landlock에서 TCP 전면 차단이 되는 것과 결론이 맞음
- **macOS 프로파일이 exec/egress 규칙을 조용히 버리던 문제.** 옮기지 못한 규칙은 전부 한계 목록에 나옴
- 사용자 규칙 id가 내장 규칙 id와 겹치면 로드 실패. 감사 로그의 `rule` 필드가 어느 티어를 가리키는지 알 수 없어지는 것을 막음
- 제네시스 argv가 실제 호출을 재현함. `--yes`, `--workspace`, `--mediate` 등이 빠지지 않음
- 시그널로 죽은 자식을 성공으로 보고하던 문제. 쉘 관례대로 128+시그널을 돌려줌
- Landlock 사전 필터가 대소문자를 구분해 대소문자 무구분 마운트에서 제한 규칙을 비껴갈 수 있었던 문제
- `verify`가 개행 없는 공백 마지막 줄을 조용히 넘기던 문제. 부분 쓰기로 실패시킴
- `x86_64`/`aarch64` 외 Linux 아키텍처에서 컴파일이 깨지던 문제. 아는 아키텍처를 늘리고 모르는 경우는 중계를 켤 때 런타임 오류로 알림
- Landlock 커널 부분 강제(`PartiallyEnforced`)를 조용히 수용하던 문제. 자식이 경고를 출력함
- 중계 층이 argv를 조용히 자르던 문제. 잘렸다는 표시가 엔트리에 남고 상한이 64에서 256으로 늘어남
- `docs/`가 `.gitignore`에 있어 규격 문서가 저장소에 없던 문제

### 변경

**아래 셋은 비호환 변경입니다.**

- **감사 포맷이 `airlock.audit.v2`가 됨.** 엔트리에 `v` 필드가 들어가고 도메인 상수가 `airlock.audit.v2\x00`로 바뀌었으며 `FORMAT_VERSION = 2`입니다. **이 변경 이전에 만든 체인은 다시 검증할 수 없습니다.** 검증자는 마이그레이션하지 않고 `FormatVersionUnsupported`로 거부합니다. 옛 체인은 그 버전의 airlock으로 검증해야 합니다. 근거는 `docs/audit-format.md` 7.1절
- **정책 다이제스트 도메인이 `airlock.policy.v2`가 됨.** `protocol` 축과 `[defaults].egress_plaintext`가 인코딩에 들어갔습니다. **한 글자도 바꾸지 않은 정책 파일이 이전과 다른 다이제스트를 냅니다.** 다이제스트를 고정값으로 비교하는 곳은 전부 갱신해야 합니다. 정책 파일 형식의 `version`은 여전히 `1`입니다
- **exec 기본 동작이 바뀜.** `[defaults].exec`이 `allow`가 아닌 정책은 이제 exec이 커널 화이트리스트가 됩니다. **같은 정책 파일로 전에는 돌던 프로그램이 커널에서 거부될 수 있습니다.** `kind = "exec"` allow 규칙으로 필요한 프로그램을 열거해야 하며, macOS의 `/bin/sh`는 dyld variant 기구로 `/bin/bash`를 다시 exec 하므로 둘 다 필요합니다. `[defaults].exec = "allow"`인 정책은 이전 동작 그대로입니다

- `Session::check_file`/`check_exec`/`check_egress`가 관측된 주체를 뜻하는 `Actor` 인자를 받음. `Session::finish`는 `Closed`를 돌려주며 앵커 기록 결과를 담음
- `EgressGate` 트레이트에 완료 훅 `finished` 추가. 기본 구현은 no-op 이라 기존 구현체가 깨지지 않음. `ProxyServer::live_connections`로 살아 있는 중계 연결 수를 볼 수 있음
- `Policy::evaluate_egress_with_usage` 추가. 누적 반출량을 함께 받아 총량 한도까지 한 지점에서 판정함. 기존 `evaluate_egress`는 누적량 0 으로 위임하므로 한도가 발동하지 않음
- `Session`이 닫힌 뒤의 append 를 거부함(`BrokerError::SessionClosed`). `session_end` 뒤에 붙는 엔트리는 체인을 앵커보다 길게 만들어 세션 전체를 "종료 후 덧붙이기" 로 보고하게 하므로, 늦게 도착한 결과 하나를 남기려다 무결성 보고를 깨뜨리지 않음. 브로커는 세션을 닫기 전에 살아 있는 중계 연결을 최대 2초 기다림
- `Matcher::Egress`에 `max_bytes_out` 필드 추가. 정책 다이제스트 인코딩에 `protocol` 다음 자리로 들어감. **도메인은 `airlock.policy.v2` 그대로이며 올리지 않았음.** 같은 v2 안에서 필드가 늘었으므로 이 변경 이전에 계산한 다이제스트와는 값이 달라짐
- `Enforcer` 트레이트에 `set_program` 추가. 기본 구현은 아무것도 하지 않음
- `airlock policy check`가 `egress_plaintext` 기본값을 함께 출력함
- `examples/policy`와 `crates/airlock-setup/presets`의 세 정책이 `[defaults].egress_plaintext = "deny"`를 명시함
- **`strict` 프리셋의 `toolchain-read`에서 `exec` 모드를 뺌.** 그대로 두면 exec 화이트리스트의 실효 범위가 `/usr`, `/bin`, `/System`, `/Library` 전체가 되어 사실상 시스템 전체였음. 필요한 프로그램을 `kind = "exec"` allow로 열거하는 방식으로 바꿔 `curl`, `nc`, `ssh`, `osascript`, `perl` 같은 반출 도구가 화이트리스트 밖으로 나감
- 제네시스 인코딩에 `tag(mediation)`이 추가됨. 이 변경 이전에 만든 체인은 해시가 달라지므로 다시 검증할 수 없음. 당시에는 포맷 버전을 올리지 않았고, 그 뒤 위의 v2 승격으로 함께 흡수됨
- `Mediation` 타입이 `airlock-audit`으로 이동. `airlock_broker::Mediation`은 재수출
- `TtyApprover`가 단위 구조체에서 `TtyApprover::new()`로 바뀜
- `rust-version`이 1.87에서 1.88로 올라감. let 체인을 쓰므로 1.87에서는 애초에 컴파일되지 않았음
- `scripts/check.sh`가 `--no-fail-fast`로 테스트를 돌림. 앞선 테스트 바이너리의 실패가 뒤쪽 강제 층 테스트를 통째로 가리던 것을 막음
