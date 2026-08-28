# Airlock 한계 목록

## 0. 이 문서에 대하여

이 문서는 Airlock 0.1.0(pre-release, 커밋 `fe02a87`) 시점에 **실제로 코드를 읽어 확인한** 한계를 한곳에 모은 것입니다. 기준일은 2026-08-03입니다.

`SECURITY.md`의 "취약점이 아닌 것" 절이 사용자에게 밝히는 요약이라면, 이 문서는 그 뒤에 있는 전체 목록입니다. `docs/design.md` 10장이 "설계를 바꾸는 외부 제약"을 다룬다면, 이 문서는 "지금 이 구현이 무엇을 못 하는가"를 다룹니다.

읽는 방법은 다음과 같습니다.

- **구조적**: 아키텍처를 바꾸지 않으면 없앨 수 없습니다. 경로 기반 중재의 TOCTOU가 대표적입니다.
- **미구현**: 설계는 있으나 코드가 아직 없습니다. Linux netns 격리와 egress DLP가 대표적입니다.
- **범위**: 지금 코드가 다루기로 한 범위 밖입니다. 어휘를 넓히면 해소됩니다.
- **결함**: 의도와 코드가 어긋납니다. 고쳐야 할 대상입니다.

각 항목에 `crate/file:line` 근거를 답니다. 근거 없는 항목은 이 문서에 넣지 않습니다.

> [!IMPORTANT]
> 이 문서는 코드가 바뀌면 같이 낡습니다. 특히 하드코딩 상수 목록(11장)과 문서 대비 어긋남(12장)은 커밋마다 달라질 수 있습니다.

---

## 1. 한 눈에 보기

가장 중요한 것부터입니다. 나머지 장은 이 표를 풀어 쓴 것입니다.

| #  | 한계                                                                 |  성격  | 이미 공개됨 |
|----|----------------------------------------------------------------------|:------:|:-----------:|
| 1  | 감사 로그는 서명도 앵커도 없어 쓰기 권한을 가진 공격자에게 무력하다  | 구조적 |     예      |
| 2  | 호스트 단위 egress는 어느 플랫폼에서도 강제되지 않는다               | 미구현 |     예      |
| 3  | macOS는 자식 프로세스의 행위를 하나도 기록하지 못한다                | 구조적 |     예      |
| 4  | 중계 층이 읽은 경로와 커널이 여는 대상이 다를 수 있다 (TOCTOU)       | 구조적 |     예      |
| 5  | 커널이 거부한 접근은 감사 로그에 남지 않는다                         | 구조적 |     예      |
| 6  | 세션 간 연결이 없어 세션 디렉토리 통째 삭제는 탐지되지 않는다        | 구조적 |   아니오    |
| 7  | `head`가 한 칸 뒤진 체인이 경고로만 처리되고 종료 코드는 0이다       |  결함  |   아니오    |
| 8  | Landlock 순회 예산(20만) 고갈 시 해당 루트 나머지가 목록 전용이 된다 |  범위  |    부분     |
| 8b | exec 화이트리스트가 `mmap(PROT_EXEC)`과 링커 루트 때문에 넓다        |  범위  |     예      |
| 9  | io_uring, `sendto`, 유닉스 소켓은 중계를 통째로 비껴간다             |  범위  |   아니오    |
| 10 | 정책 모델에 하드링크/rename/유닉스 소켓/환경 변수 어휘가 없다        |  범위  |   아니오    |
| 11 | 릴리스 바이너리/서명/SBOM/vendoring이 전부 없다                      | 미구현 |   아니오    |
| 12 | 규격 문서와 런타임 UX가 한국어 전용이다                              |  범위  |   아니오    |

---

## 2. 구조적 한계

아키텍처가 그대로인 한 남습니다. 완화는 가능하나 제거는 불가능합니다.

### 2.1 감사 로그는 재계산 공격에 무력하다

체인은 키 없는 SHA-256 prev-hash 링크입니다. HMAC도 서명도 TPM도 제3자 witness도 외부 앵커도 없습니다 (`airlock-audit/src/entry.rs:112-137`, 도메인 상수는 `entry.rs:9`).

`chain.jsonl`과 `head.json`에 쓸 수 있는 사람은 전체 이력을 밀리초 안에 다시 봉인할 수 있고, 그 결과는 검증을 통과합니다. 곧 감사 로그의 증거력은 전적으로 **강제 층이 감사 디렉토리를 에이전트에게 쓰기 금지하는 것**에서 나옵니다. 로그 자체는 같은 uid 공격자에게 아무 저항도 하지 않습니다.

`docs/audit-format.md` 2절이 이 경계를 정본으로 규정하고 `SECURITY.md`도 밝힙니다. 하드웨어 서명은 `docs/design.md` 11장의 미결 사항입니다.

### 2.2 경로 기반 중재의 TOCTOU

정책은 판정 때마다 `std::fs::canonicalize`를 부릅니다 (`airlock-policy/src/path.rs:126-154`). 중계 층은 대상 프로세스 메모리에서 `process_vm_readv`로 경로와 argv를 읽습니다 (`airlock-broker/src/notify.rs:395`).

승인 후 `SECCOMP_USER_NOTIF_FLAG_CONTINUE`로 재개하면 커널이 포인터 인자를 **다시** 읽으므로 (`notify.rs:521-525`), 대상의 다른 스레드가 그 사이에 경로나 `sockaddr`을 바꿔 쓸 수 있습니다. **사람이 승인한 경로가 실제로 열리는 경로라는 보장은 없습니다.**

파일 접근의 실제 경계는 inode에 규칙을 거는 Landlock이고, 중계 층은 그 위의 기록/승인 층입니다. 코드도 이를 그렇게 적어 두었습니다 (`notify.rs:13-17`, `session.rs:110-116`).

### 2.3 커널이 거부한 접근은 로그에 남지 않는다

Landlock과 Seatbelt가 EPERM을 낸 시점에 브로커는 개입하지 않습니다. gap으로 노출됩니다 (`landlock.rs:1190-1192`).

감사 로그는 "중계 층이 관측한 것"만 담습니다. 곧 **"에이전트가 무엇을 시도했는가"에 로그가 답하지 못합니다.** 강제가 강할수록 로그가 비는 역설이 있습니다.

### 2.4 세션은 서로 독립된 체인이고 상위 인덱스가 없다

실행마다 `sessions/{nanos}-{pid}` 디렉토리를 새로 만들고 (`airlock/src/paths.rs:66-70`), 제네시스의 `prev`는 항상 `Hash::ZERO`입니다 (`airlock-audit/src/log.rs:107-108`). 세션을 잇는 카운터도 루트 인덱스도 없습니다.

결과는 두 가지입니다.

- **세션 디렉토리를 통째로 지우면 탐지되지 않습니다.** `airlock audit list`는 살아남은 디렉토리를 열거할 뿐입니다 (`cmd_audit.rs:272-297`).
- 새 세션을 시작하는 것만으로 어떤 체인에서도 벗어납니다. 병렬 세션 사이에는 잠금도 순서 보장도 없고, 상대 순서는 신뢰할 수 없는 `ts` 값과 디렉토리 이름으로만 추정됩니다.

### 2.5 exec 규칙은 프로그램 경로까지만 경계이고 argv는 여전히 tripwire다

`[defaults].exec`가 `allow`가 **아니면** 두 강제 층이 exec을 커널 화이트리스트로 겁니다. 허용 목록 밖의 프로그램은 커널이 `execve` 자체를 거부합니다. Linux는 `AccessFs::Execute`를 읽기 권한에서 분리해 허용 목록에만 부여하고 (`landlock.rs:92-109`, `685-732`), macOS는 `(allow process-exec*)` 무조건 개방을 걷어내고 경로별 허용만 방출합니다 (`profile.rs:232-238`, `395-433`). 곧 프로그램 경로 단위 제한은 tripwire가 아니라 경계입니다.

경계가 되지 않는 것은 **argv 조건**입니다. `argv_contains`와 `argv_pattern`은 어느 커널 인터페이스로도 표현할 수 없어, 그 조건으로 좁힌 규칙은 프로그램 경로 판정으로만 내려갑니다. `sh -c 'r''m -rf /'`, base64 디코드, 인터프리터 경유는 그대로 남습니다 (`docs/policy-dsl.md` 7.1절). 이 사실은 gap으로 나옵니다 (`landlock.rs:799-805`).

`[defaults].exec = "allow"`인 정책은 이전과 같습니다. 그 설정에서는 화이트리스트를 아예 만들지 않고 exec 제한이 전부 커널 밖입니다. 그것도 gap으로 밝힙니다 (`landlock.rs:782-795`). `examples/policy`의 `claude-code.toml`과 `developer.toml`이 이 설정입니다. 화이트리스트가 걸리는 프리셋은 `strict.toml` 하나뿐입니다.

### 2.6 macOS에는 중계 기구가 없다

`effective_mediation`은 Linux가 아닌 모든 타겟에서 `Mediation::Off`를 돌려주고 (`session.rs:72-76`), `notify` 모듈 자체가 `#[cfg(target_os = "linux")]`입니다 (`lib.rs:14-15`).

프록시 없이 도는 macOS 세션의 체인에는 제네시스, 최상위 exec 판정 하나, `session_end` 셋만 남습니다. 자식 exec과 파일 접근은 어느 경우에도 기록되지 않습니다.

**아웃바운드 연결은 예외입니다.** egress 프록시는 커널 중계 기구가 아니라 브로커 프로세스 안의 판정 지점이라 중계 수준과 무관하게 동작합니다. `--egress-proxy` 세션에서는 `SessionGate::check`가 `Session::check_egress`를 부르므로 (`egress.rs:39-47`), 중계 수준이 `off`인 macOS에서도 자식의 연결이 판정되고 `egress`와 `egress_summary` 엔트리로 남습니다. 곧 macOS에서 자식 행위 중 감사에 남는 것은 아웃바운드뿐이며 그것도 프록시를 켰을 때만입니다.

`--mediate full`은 받아들여지고 아무 일도 하지 않으며, 그 사실이 배너와 제네시스에 남습니다 (`session.rs:87-94`).

### 2.7 Landlock은 `[defaults]`를 반영하지 않는다

허용 계획에서 빼는 것은 **실제로 매칭된 규칙이 막을 때뿐**이고, `[defaults]`로 떨어진 경로는 빼지 않습니다 (`landlock.rs:390`). 근거는 코드 주석에 있습니다 (`landlock.rs:371-378`). `[defaults].file = "ask"`인 베이스라인에서 기본값까지 반영하면 아무것도 허용되지 않아 프로세스가 exec조차 못 하기 때문입니다.

의도된 선택이지만 결과는 비대칭입니다. macOS 프로파일은 진짜 `(deny default)`인데 (`profile.rs:227`) Linux는 그렇지 않습니다. **같은 정책 파일이 두 OS에서 다른 커널 자세를 만들고, 이 차이는 gap 목록에 나오지 않습니다.**

---

## 3. 강제 층: Linux (Landlock)

### 3.1 순회 예산 20만이 고갈되면 그 루트 나머지가 목록 전용이 된다

`WALK_BUDGET = 200_000`이며 루트마다 새로 줍니다 (`landlock.rs:49`, `368-371`). 예산이 0이 되면 항목 루프가 끊기고 `truncated`가 서고 (`landlock.rs:422-426`), 그 뒤 디렉토리는 `ReadDir` 권한만 받습니다 (`landlock.rs:493`, `507`).

곧 `/usr` 어딘가에서 예산이 끊기면 **그 루트의 나머지 디렉토리는 전부 목록 전용**이 되고 그 안의 파일은 규칙을 하나도 못 받습니다. 개발 머신의 `/usr`는 20만을 넘기는 일이 드물지 않습니다. 이전에 예산이 루트 전체에서 공유되어 뒤쪽 루트가 통째로 굶던 문제는 고쳤지만(`CHANGELOG.md`), 루트 안쪽의 고갈은 그대로 남아 있습니다.

gap 보고는 각각 5개까지만 보여 줍니다 (`landlock.rs:570`, `576`). 4천 개가 잘렸어도 사용자는 5개만 봅니다.

### 3.2 시작 비용이 파일시스템 크기에 비례한다

시스템 루트 8개 + 임시 디렉토리 + 작업 공간 + 명시 allow 경로를 매 실행마다 단일 스레드로 순회합니다. 캐시가 없습니다. 최악의 경우 실행 한 번에 수백만 번의 `readdir`/`file_type`이 자식 exec 이전에 일어납니다.

exec 화이트리스트가 켜지면 순회 대상이 더 늘어납니다. 실행 허용 루트(`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` + 정책이 허용한 경로)를 **다시 한 번** 걷기 때문입니다 (`landlock.rs:685-711`). `/usr/lib`가 `/usr`의 대부분인 배포판에서는 시작 비용이 사실상 두 배가 됩니다. 예산은 루트마다 새로 주므로 3.1의 고갈 성질은 그대로입니다.

### 3.3 규칙이 inode에 걸리고 `prepare()` 시점에 고정된다

계획은 fork 이전 부모에서 세우고 (`landlock.rs:1130`), 적용은 `pre_exec`에서 합니다 (`landlock.rs:1171-1172`).

- **부분 허용 디렉토리 안에는 새 파일을 만들 수 없습니다.** 그 디렉토리는 `ReadDir`만 갖기 때문이며, 세션 내내 그렇습니다.
- 강제 이후 마운트된 파일시스템은 새 inode를 내놓으므로 어떤 규칙에도 걸리지 않고 접근 불가가 됩니다.
- 반대로 `Whole` 허용 서브트리 **안으로** 옮겨진 것은 읽을 수 있게 됩니다. 부모 디렉토리 inode에 권한이 걸려 있기 때문입니다.

### 3.4 심볼릭 링크는 계획에서 통째로 빠진다

`kind.is_symlink()`면 개수만 세고 건너뜁니다 (`landlock.rs:434-441`). 어떤 링크가 빠졌는지는 보고하지 않습니다 (`landlock.rs:582-588`).

정책 밖 트리가 링크로 열리던 문제를 막은 조치이지만, 부분 허용 디렉토리 안의 링크는 규칙을 받지 못합니다. pnpm/npm의 `node_modules/.bin`, cargo 산출물 링크, `.venv` 배치가 이 때문에 깨지고 어느 링크가 원인인지 알 수 없습니다.

### 3.5 명시 allow 규칙이 반영되는 조건이 좁다

세 조건을 모두 만족해야 합니다.

- 사용자 티어여야 합니다. 베이스라인 티어는 보지 않습니다 (`landlock.rs:541`).
- glob이 없어야 합니다. `*`나 `?`가 있으면 건너뜁니다 (`landlock.rs:553-555`).
- 이미 존재해야 합니다 (`landlock.rs:557`).

곧 `~/data/**` 같은 allow 규칙은 커널 수준에서 아무것도 열지 않고, 아직 없는 경로는 나중에도 만들 수 없습니다. **셋 다 gap으로 보고되지 않습니다.**

### 3.6 네트워크는 TCP connect 포트뿐이고 호스트는 버려진다

계획의 키는 포트뿐이며 (`landlock.rs:886-889`), 호스트는 gap 문자열을 만들기 위해서만 쓰입니다 (`landlock.rs:895-897`). 실제 규칙은 `NetPort::new(port, AccessNet::ConnectTcp)`입니다 (`landlock.rs:1098`).

`allow host="api.anthropic.com" port=443`은 커널에서 **443 포트의 모든 호스트**로의 TCP 연결을 엽니다. 클라우드 메타데이터 엔드포인트와 임의의 반출 목적지가 여기 포함됩니다.

`--egress-proxy`를 켜면 허용 포트가 프록시 포트 하나로 줄지만 이 한계의 성질은 그대로입니다. Landlock은 여전히 포트만 보므로 자식이 자기 환경에 적힌 프록시 포트로 외부 호스트에 직접 연결하면 프록시를 건너뜁니다. **곧 Linux의 `--egress-proxy`는 아직 fail-closed가 아니며**, 그 사실을 gap으로 냅니다. netns 격리가 들어와야 macOS와 같은 결론이 됩니다.

부수 효과 두 가지가 더 있습니다.

- **`port` 없는 egress allow 규칙 하나가 네트워크 강제를 통째로 끕니다** (`landlock.rs:890-893`, 가드는 `1050`과 `1095`). gap은 나오지만 강제는 이미 사라진 뒤입니다.
- **`deny` egress 규칙은 계획이 아예 보지 않습니다** (`landlock.rs:883-885`). `deny host="169.254.169.254"`는 커널 효과가 0이고, macOS와 달리 "옮기지 못했다"는 보고조차 없습니다.

### 3.7 TCP bind는 항상 막히는데 gap이 없다

`handle_access`는 `BindTcp`와 `ConnectTcp`를 함께 다루지만 (`landlock.rs:1052`) 규칙은 `ConnectTcp`만 추가합니다 (`landlock.rs:1095-1101`).

네트워크 제한이 켜지면 자식은 어떤 TCP 포트도 bind할 수 없습니다. 개발 서버, 언어 서버, 테스트 하네스가 이 때문에 실패하고 어떤 gap 문자열도 bind를 언급하지 않습니다.

### 3.8 UDP는 전혀 강제되지 않는다

Landlock ABI v10부터이며 crate가 아직 노출하지 않습니다. gap으로 밝힙니다 (`landlock.rs:1200-1204`). DNS 기반 반출과 QUIC/HTTP-3 아웃바운드는 커널 층을 통째로 비껴갑니다.

### 3.9 ABI 강등 중 일부가 gap에 나오지 않는다

`detect_abi()`가 커널 버전으로 ABI를 추정하고 8을 상한으로 잡습니다 (`landlock.rs:972-1000`).

- ABI < 4: 아웃바운드 제한 없음. **gap 있음** (`landlock.rs:1194-1198`).
- ABI < 6: 스코프 제한이 없어 자식이 **브로커와 감독 스레드에 시그널을 보낼 수 있고 추상 유닉스 소켓(ssh-agent, dbus)에 연결할 수 있습니다.** 근거는 주석에 있으나 (`landlock.rs:1056-1058`) **gap 문자열이 없습니다.**
- ABI < 3: `Truncate` 미중재. gap 없음.
- ABI < 5: `IoctlDev` 미중재. gap 없음.

### 3.10 부분 강제가 원시 stderr 경고 하나로 통과한다

`FullyEnforced`가 아니면 `warn_partial()`을 부르고 계속 진행합니다 (`landlock.rs:1178-1180`). 그 함수는 고정 문자열을 `libc::write(2, ...)`로 씁니다 (`landlock.rs:1036-1042`).

경고가 **자식의** fd 2로 나가므로 stderr를 리다이렉트하거나 에이전트가 삼키면 사라지고, 감사 체인에는 절대 남지 않습니다. `NotEnforced`만 중단시킵니다 (`landlock.rs:1173-1177`).

### 3.11 시스템 읽기 루트가 8개 고정이다

`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/etc`, `/proc/self`뿐입니다 (`landlock.rs:51-60`).

`/var`, `/run`, `/sys`, `/nix`, `/snap`과 `/proc/self` 밖의 `/proc`이 전부 닿지 않습니다. `/proc/cpuinfo`나 `/sys/devices/system/cpu`를 읽는 툴체인이 실패하고, **NixOS와 Snap 패키지 바이너리는 아예 실행되지 않습니다.** 쓰기 가능 장치 노드도 5개 고정입니다 (`landlock.rs:80-86`).

### 3.12 exec 화이트리스트는 걸리지만 허용 트리 안의 예외는 걸리지 않는다

이 절은 이전 판에서 "exec 규칙은 Landlock으로 강제할 수 없다"고 적혀 있었습니다. 그것은 **방향을 구분하지 않은 서술이라 절반만 맞았습니다.** Landlock은 allow만 표현하므로 결론이 방향마다 갈립니다.

- **표현 가능**: "이 경로들만 실행할 수 있다"(화이트리스트). `AccessFs::from_read(abi)`는 `Execute | ReadFile | ReadDir`이므로 (`landlock-0.4.6/src/fs.rs:112-123`) 읽기 권한을 그대로 주면 **읽을 수 있는 모든 파일이 실행 가능**해집니다. `Execute`를 읽기와 쓰기에서 떼어 내 허용 목록에만 부여하면 커널 강제 화이트리스트가 성립합니다 (`landlock.rs:92-109`).
- **표현 불가능**: "이 트리는 열되 그 안의 이 바이너리만 실행 금지"(허용 트리 안의 deny). 계획 단계에서 항목을 빼는 방식으로 파일 규칙은 이 문제를 우회하지만, 실행 허용이 `**` 패턴처럼 트리로 걸린 경우 그 안을 겨냥한 `kind = "exec"` 제한은 커널이 걸러 내지 못합니다. 실제로 걸린 트리 목록과 걸러지지 않는 규칙 id를 함께 gap으로 냅니다 (`landlock.rs:807-826`).

`examples/policy/strict.toml`의 `toolchain-read`가 `/usr/**`에 `mode = ["read", "metadata", "exec"]`을 주므로, **그 프리셋에서는 실행 허용이 시스템 전체 트리로 걸려 화이트리스트의 실효 범위가 좁지 않습니다.** 좁히려면 `kind = "exec"` allow 규칙으로 프로그램을 열거해야 합니다.

`kind = "file"` + `mode = ["exec"]` deny는 순회 단계에서 실제로 빠집니다. 실행 계획은 `FileMode::Exec`만 평가하고 읽기 계획은 `Read`/`Write`만 평가하므로 (`landlock.rs:206-212`, `380`), 실행만 막은 규칙이 읽기까지 좁히거나 그 반대가 되는 일은 없습니다.

`ask` exec 규칙은 허용 목록에 넣지 않으므로 커널에서 거부됩니다. Linux에는 중계 층이 있어 승인 흐름 자체는 남지만, 커널이 먼저 막으므로 승인해도 실행되지 않습니다. 이것은 macOS의 `ask` 처리와 결론이 같습니다.

### 3.13 실행 허용에 동적 링커 루트가 통째로 들어간다

`execve` 대상 바이너리만 `Execute`를 요구하는 것이 아닙니다. ELF 인터프리터(`ld-linux-*.so`, `ld-musl-*.so`)는 커널이 `open_exec()`으로 여는데 그 경로는 `__FMODE_EXEC`를 세우고, Landlock의 `file_open` 훅은 그것을 `LANDLOCK_ACCESS_FS_EXECUTE` 요구로 옮깁니다. 곧 **링커에 실행 권한이 없으면 동적 링크된 프로그램은 하나도 뜨지 못합니다.**

이 저장소의 개발 환경은 macOS이고 Linux에서 실제로 실행해 확인할 수단이 없습니다. 추측으로 좁히는 대신 링커가 사는 루트를 통째로 엽니다 (`landlock.rs:73`).

```
/lib  /lib64  /usr/lib  /usr/lib64
```

**그만큼 화이트리스트가 넓어집니다.** 배포판에 따라 이 아래에 실행 파일이 적지 않습니다. 데비안 계열의 `/usr/lib/git-core/*`, `/usr/lib/openssh/sftp-server`, `/usr/lib/gcc/*`가 정책이 따로 허용하지 않아도 실행됩니다. `/usr/bin`과 `/bin`은 열리지 않으므로 `curl`, `nc`, `python`, 쉘은 그대로 막힙니다. gap으로 실제로 열린 루트를 나열합니다 (`landlock.rs:713-723`).

좁히려면 실행할 바이너리의 `PT_INTERP`를 읽어 링커 하나로 특정해야 합니다. Linux에서 실제 실행 검증이 가능해진 뒤에 할 일로 남깁니다.

### 3.14 `mmap(PROT_EXEC)`은 Landlock이 매개하지 않는다

Landlock이 등록하는 LSM 훅에는 `mmap_file`도 `file_mprotect`도 없습니다. `AccessFs::Execute`는 `file_open` 경로에서 `__FMODE_EXEC`가 선 열기만 봅니다.

곧 **읽을 수 있는 파일을 실행 가능하게 매핑해 그 안으로 뛰는 경로는 화이트리스트 밖입니다.** 인터프리터, JIT, 자체 로더를 가진 런타임은 exec 화이트리스트를 거치지 않고 임의 코드를 돌릴 수 있습니다. 공유 라이브러리(`.so`) 로딩도 같은 이유로 `ReadFile`만 요구하며, 그래서 라이브러리는 실행 허용 밖에 있어도 잘 로드됩니다. gap으로 밝힙니다 (`landlock.rs:725-729`).

이것은 exec 화이트리스트가 **의도적 실행 경로만** 좁힌다는 뜻입니다. 코드 실행 자체를 막는 경계가 아닙니다.

---

## 4. 강제 층: macOS (Seatbelt)

### 4.1 SBPL이 표현할 수 없는 것

| 정책                      | 상태                    | 근거                             |
|-------------------------|-----------------------|--------------------------------|
| exec argv 조건            | **불가능**               | `profile.rs:549-552`           |
| 포트/호스트 단위 egress        | 프록시 층에서만 가능           | `profile.rs:312-318`           |
| `ask` (파일)              | deny로 강등              | `profile.rs:335`, `626-628`    |
| `ask` (exec), 화이트리스트 모드 | 허용 목록에 넣지 않음 = 사실상 거부 | `profile.rs:519-522`, `630-637`|
| `ask` (exec), `allow` 모드 | **프로파일에 넣지 않음** = 허용  | `profile.rs:519-522`, `639-642`|

`ask` exec 규칙은 두 모드 모두 프로파일에 방출하지 않습니다. 기구는 같지만 **결과가 정반대**입니다. `[defaults].exec = "allow"`이면 위에서 `(allow process-exec*)`가 통째로 열려 있으므로 방출하지 않는다는 것이 곧 허용이고, 화이트리스트 모드에서는 열린 것이 허용 목록뿐이므로 방출하지 않는다는 것이 곧 거부입니다. 배너 문구도 그에 맞춰 갈립니다 (`seatbelt.rs:265-272`).

`allow` 모드에서 방출하지 않는 이유는 사람이 승인한 실행이 커널에서 막혀 어떤 방법으로도 진행할 수 없게 되기 때문입니다. macOS에는 중계 층도 없으므로(2.6), 그 모드에서 `danger-rm`/`sudo-exec`/`pipe-curl-to-shell` 같은 규칙은 **강제되지도 기록되지도 않습니다.** 화이트리스트 모드에서는 커널이 거부하지만, 사람에게 물어볼 통로가 없어 승인으로 되돌릴 방법도 없습니다.

egress는 `--egress-proxy` 여부로 갈립니다. 플래그가 없으면 egress allow 규칙이 하나라도 있을 때 `(allow network-outbound)`로 아웃바운드가 통째로 열리고, 호스트 규칙은 전부 gap이 됩니다. 플래그가 있으면 프로파일이 `(allow network-outbound (remote ip "localhost:<프록시포트>"))` 하나로 좁아져 프록시가 유일한 출구가 되고, 호스트 판정이 실제 경계를 갖습니다. 규격은 `docs/egress-proxy.md`입니다.

### 4.1.1 프록시 모드에서도 DNS는 경계 밖이다

`--egress-proxy`가 아웃바운드를 루프백으로 좁혀도 자식의 이름 해석은 그대로 나갑니다. macOS의 `getaddrinfo`는 `network-outbound`가 아니라 mDNSResponder를 거치며, `mach-lookup` deny로도 막히지 않는 것을 Darwin 25.4에서 확인했습니다.

곧 자식은 `<유출데이터>.attacker.com` 질의로 데이터를 내보낼 수 있고, 그 질의는 프록시를 거치지 않으므로 감사에도 남지 않습니다. 이 사실은 프록시 모드의 enforcer gap으로 배너에 나옵니다 (`seatbelt.rs`의 `gaps`).

### 4.2 SBPL 방출이 대소문자를 구분한다

`sbpl::quote`와 정규식 이스케이프는 케이스 폴딩을 하지 않습니다 (`sbpl.rs:23-66`). 반면 정책 엔진의 제한 규칙은 대소문자를 무시합니다 (`airlock-policy/src/rule.rs:148`).

기본값이 대소문자 무구분인 APFS에서 베이스라인 `deny ~/.ssh`는 `(subpath "/Users/me/.ssh")`로 나가는데, 커널은 이를 `/Users/me/.SSH`에 적용하지 않습니다. 두 경로는 같은 디렉토리입니다. **정책 층이 잡았을 우회를 커널 프로파일이 놓칩니다.**

### 4.3 정규화 변형은 제한 규칙에만 방출된다

`forms_of`는 비ASCII일 때만 원본 + NFC + NFD를 냅니다 (`sbpl.rs:124-138`). allow 규칙은 일부러 한 형태만 냅니다 (`profile.rs:598-606`).

의도된 비대칭이지만 결과적으로, 디스크에 저장된 정규화 형태가 정책에 적은 것과 다르면 **allow 규칙이 조용히 접근을 못 열어 줍니다.** NFKC/NFKD는 어느 쪽도 다루지 않습니다.

### 4.4 override 완화가 커널 프로파일에 반영되지 않는다

`denied_overrides`로 모아 gap으로 보고합니다 (`seatbelt.rs:179-186`, `273-278`). 근거는 `docs/policy-dsl.md` 3.2절에 있습니다. SBPL이 "이 forbid에서 이 부분집합만 제외"라는 교집합을 표현하지 못하기 때문입니다.

곧 정당하게 완화한 사용자 규칙이 macOS에서는 실제로 동작하지 않습니다. fail-closed 방향이라 안전하지만, 정책 층과 커널의 결론이 갈립니다.

### 4.5 기본 열림 항목들

- `(allow process-exec*)` (`profile.rs:237`): **`[defaults].exec = "allow"`인 정책에만 방출됩니다.** 그 설정에서는 명시 deny가 없는 모든 exec이 허용됩니다. `ask`/`deny`/`forbid`이면 이 줄이 없고 허용 목록만 열립니다 (4.12).
- `(allow mach-lookup)` (`profile.rs:245`): 클립보드 두 개만 막고 (`profile.rs:247-248`) 나머지 XPC/Mach 서비스는 전부 닿습니다. XPC로 오가는 것은 정책 모델 밖이자 감사 로그 밖입니다 (gap: `seatbelt.rs:255-257`).
- `(allow file-read-metadata)` (`profile.rs:255`): 시스템 전체 경로의 존재/크기/mtime을 읽을 수 있습니다.

### 4.6 `(with no-report)`가 OS 자체 위반 로그를 끈다

`(deny file-write* (with no-report))` (`profile.rs:228`).

거부된 쓰기는 시스템 샌드박스 위반 리포트를 남기지 않습니다. 중계 층 부재(2.6)와 gap(`seatbelt.rs:252-254`)이 겹쳐, **막힌 쓰기는 어디에도 흔적을 남기지 않습니다.**

### 4.7 deprecated API 위에 서 있고 실패 이유를 버린다

`sandbox_init_with_parameters`를 직접 선언해 호출합니다 (`seatbelt.rs:19-28`, `143-146`). 10.8부터 deprecated입니다. 실패는 0이 아닌 반환값으로만 드러나고 오류 버퍼는 버립니다 (`seatbelt.rs:153-158`). 호출자는 고정 문자열을 받고 커널이 준 이유는 못 받습니다.

### 4.8 `sandbox-exec` 교차 검증 경로는 프로파일 전문을 `ps`에 노출한다

`wrapped.arg("-p").arg(text)` (`seatbelt.rs:229`). 같은 머신의 어떤 프로세스든 프로세스 테이블에서 정책 전문을 읽습니다. gap으로 밝히고 (`seatbelt.rs:279-285`) CLI는 이 경로를 고르지 않지만 (`cmd_run.rs:310-321`), `SeatbeltEnforcer`의 공개 API로는 남아 있습니다.

### 4.9 basename 규칙이 glob 메타문자를 이스케이프하지 않는다

`escape_regex_char`는 `. + ( ) [ ] { } ^ $ | \`를 이스케이프하지만 `*`와 `?`는 하지 않습니다 (`sbpl.rs:52-60`, `156-161`). 이 성질은 `deny` 방향에만 남습니다. `allow` 방향의 이름 규칙은 정규식이 아니라 `PATH` 해소 결과를 씁니다 (4.12).

`program = "a?c"`는 `^.*/a?c$`로 나가고 여기서 `?`는 정규식 수량자라 `a`가 선택적이 됩니다. **방출된 deny가 정책이 말하는 것보다 넓어집니다.**

### 4.10 프로파일 크기 상한 검사가 없다

`generate`는 패턴 × 정규화 변형마다 한 줄씩 무한히 덧붙입니다 (`profile.rs:598-620`). 사전 검사는 내부 NUL 바이트뿐입니다 (`seatbelt.rs:187-190`). 큰 정책은 커널의 컴파일 프로파일 상한을 넘길 수 있고, 그때의 실패는 진단 가능한 정책 문제가 아니라 spawn 시점의 일반 오류로 보입니다.

### 4.11 OS 버전 매트릭스가 러너 하나뿐이다

CI는 `macos-15` 하나만 돌립니다 (`.github/workflows/ci.yml:19`). `docs/design.md` 10.3절이 지적한 대로 OS 마이너 버전이 올라가면 이전에 참조하지 않던 리소스를 쉘이 읽어 거부가 생기는 회귀가 실제로 관측됩니다. 그 회귀를 잡을 매트릭스가 지금은 없습니다.

### 4.12 exec 화이트리스트도 argv를 보지 못하고 트리 허용은 그대로 넓다

`[defaults].exec`가 `allow`가 아니면 `(allow process-exec*)` 무조건 개방이 사라지고 정책이 허용한 경로에만 `process-exec*`가 열립니다 (`profile.rs:395-433`). 최상위 프로그램은 언제나 허용 목록에 들어갑니다. 그것이 빠지면 커널이 첫 `execve`를 거부해 프로세스가 아예 뜨지 못하기 때문이며, 그 경로는 실제로 spawn할 명령을 받는 `wrap` 시점에만 확실히 알 수 있어 거기서 프로파일을 다시 만듭니다 (`seatbelt.rs:103-136`, `195-200`).

그래도 남는 것이 셋입니다.

- **argv 조건은 여전히 볼 수 없습니다.** allow 방향도 마찬가지라, `argv_contains`로 좁힌 `allow` 규칙은 프로그램 경로 전체를 여는 것으로 내려갑니다. 정책이 말하는 것보다 넓습니다.
- **`**` 패턴 허용은 `(subpath ...)`가 되어 트리 전체를 엽니다.** `strict.toml`의 `toolchain-read`가 `/usr/**`에 exec 모드를 주므로 그 프리셋에서는 실행 허용이 시스템 전체입니다. Linux의 3.12와 같은 성질입니다.
- **허용 목록이 비면 실패합니다.** 조용히 넓히지 않고 `EnforcerUnavailable`로 spawn을 막습니다 (`seatbelt.rs:123-131`). fail-closed지만 실패 시점이 `prepare`가 아니라 `wrap`이라 배너보다 늦게 나옵니다.

이름만 적은 `allow` 규칙(`program = "cargo"`)은 지금 `PATH`에서 해소되는 경로만 엽니다 (`profile.rs:461-472`). `^.*/cargo$` 정규식으로 넓히면 에이전트가 작업 공간에 써 넣은 동명 바이너리까지 실행 대상이 되기 때문입니다. `deny` 방향은 반대로 정규식을 그대로 써서 넓게 잡습니다. **해소되지 않는 이름은 조용히 버리지 않고 옮기지 못한 규칙으로 보고하며, 그 프로그램은 커널에서 실행되지 않습니다.**

### 4.13 dyld variant 재실행은 최상위 허용만으로 덮이지 않는다

macOS의 `/bin/sh`는 자기 자신을 `/bin/bash`로 다시 exec하는 dyld variant입니다. 화이트리스트에 `/bin/bash`가 없으면 `/bin/sh`가 **최상위 프로그램인데도** 뜨지 못하고 다음 메시지를 남깁니다.

```
Failed to exec /bin/bash as variant for /bin/sh (1: Operation not permitted).
```

Darwin 25.4에서 확인했으며 회귀 테스트로 고정해 두었습니다 (`tests/enforce.rs`의 `a_variant_binary_needs_its_variant_allowed`). 어떤 바이너리가 variant인지 일반적으로 알아낼 방법이 없으므로 자동으로 덮지 않습니다. 정책에서 variant 대상을 함께 허용해야 합니다.

같은 성질이 다른 재실행형 런처(`env`, 래퍼 스크립트, 언어 런타임의 재실행)에도 적용됩니다. 화이트리스트는 **실제로 `execve`되는 모든 경로**를 담아야 하며, 최상위 하나만 담는 것으로는 부족합니다.

---

## 5. 중계 층 (seccomp user notification, Linux 전용)

### 5.1 중재되는 syscall이 기본 3개, 최대 6개다

`mediated_syscalls`가 `connect`, `execve`, `execveat`를 돌려주고 (`notify.rs:197-211`), `Level::Full`이 `openat`, `openat2`, 레거시 `open`을 더합니다 (`notify.rs:152-155`, `205`).

**어느 수준에서도 중재되지 않는 것**은 다음과 같습니다.

`unlink`/`unlinkat`, `rename`/`renameat`/`renameat2`, `truncate`, `mkdir`, `link`/`symlink`, `chmod`/`chown`, `socket`, `bind`, `listen`, `sendto`, `sendmsg`, `ptrace`, `clone`/`fork`/`vfork`, `memfd_create`, `mount`, `prctl`, `io_uring_*`.

곧 **파일 삭제와 이름 변경은 `--mediate full`에서도 기록되지 않습니다.** 연결 없는 UDP 전송(`sendto`/`sendmsg`)은 egress 관측과 승인을 통째로 비껴갑니다.

### 5.2 io_uring이 중계를 통째로 우회한다

필터는 syscall 번호만 봅니다 (`notify.rs:246-253`). `IORING_OP_OPENAT`, `IORING_OP_CONNECT`, `IORING_OP_WRITE`는 실행 시점에 syscall이 아니므로 알림을 만들지 않습니다. egress `ask`/`deny`와 파일 감사가 전부 우회되고 Landlock만 남습니다.

### 5.3 `FileMode::Delete`와 `FileMode::Metadata`는 런타임에 생성될 수 없다

`file_mode_for`가 `Read`, `Create`, `Write`만 돌려줍니다 (`notify.rs:534-543`).

`mode = ["delete"]`나 `mode = ["metadata"]`로 쓴 규칙은 중계 층이 절대 평가하지 않습니다. 그 규칙의 `ask`/`deny` 의미론이 발화하지 않습니다.

### 5.4 `openat2`의 쓰기가 읽기로 분류된다

`openat2`의 세 번째 인자는 `open_how` 구조체 포인터인데, 이를 읽지 않고 보수적으로 `FileMode::Read`로 잡습니다 (`notify.rs:649-651`, 근거는 같은 자리 주석).

의도는 보수적 판정이지만 효과는 반대입니다. **읽기 allow + 쓰기 deny인 경로에 `openat2`로 쓰면 허용됩니다.** 감사 엔트리도 mode를 `read`로 남깁니다.

### 5.5 argv와 경로 읽기에 하드 상한이 있고 잘림이 argv 자리를 차지한다

`MAX_CSTR = 4096`바이트 (`notify.rs:367`), `MAX_ARGV = 256`원소 (`notify.rs:680`), sockaddr 길이는 `2..=128`만 (`notify.rs:454`).

- `argv_contains = ["--force"]` deny 규칙은 `--force`를 257번째 이후에 두면 우회됩니다. 평가가 잘린 목록으로 돌기 때문입니다 (`notify.rs:722-724`).
- 더 나쁘게, **읽을 수 없는 원소 하나가 루프를 멈춥니다** (`notify.rs:716-719`). 그 뒤 인자는 평가되지 않습니다.
- 잘림 표시 문자열이 argv 벡터 **안으로** 들어가 (`notify.rs:686-687`) 감사 로그에 진짜 인자인 것처럼 기록됩니다. 프로그램이 그 문자열을 실제 인자로 위조할 수도 있습니다.

### 5.6 32비트와 x32 syscall은 프로세스를 죽인다

아키텍처 불일치는 `SECCOMP_RET_KILL_PROCESS`입니다 (`notify.rs:230-232`, x32는 `237-242`).

중계 상태에서 i386 바이너리를 돌리면 진단 없이 SIGSYS로 즉사합니다. errno도 감사 엔트리도 없습니다. multiarch 툴체인, 32비트 크로스 컴파일러, Wine은 중계가 켜진 동안 쓸 수 없습니다. 이 강경한 선택 자체는 32비트 바이너리가 `ask` 승인을 건너뛰던 문제의 수정이며(`CHANGELOG.md`), 우회보다 죽이는 쪽이 옳습니다.

### 5.7 모르는 아키텍처는 조용히 중계 0으로 강등된다

`NATIVE_ARCH`는 8개 아키텍처만 압니다 (`notify.rs:120-146`). `None`이면 필터가 만들어지지 않고 (`notify.rs:223`), 세션은 `Mediation::Off`로 진행합니다 (`session.rs:586-592`).

제네시스에는 올바르게 기록되지만 (`session.rs:478-483`), 사용자에게 가는 신호는 stderr 한 줄뿐입니다.

### 5.8 첫 `execve` 알림은 무조건 허용된다

`first_exec_seen` 일회성 우회입니다 (`notify.rs:575`, `615-622`). 정상 경로에서는 맞습니다. 최상위 exec은 이미 `session.rs:498`에서 검사했기 때문입니다. 다만 이는 알림 순서에만 의존하는 무검사 예외이며, 알리는 pid의 신원을 확인하지 않습니다.

### 5.9 감독 스레드 하나가 전역 세션 잠금을 쥐고 직렬화한다

`supervise`는 단일 블로킹 루프이고 (`notify.rs:565-674`), 모든 분기가 `session.lock()`을 잡으며 (`notify.rs:602`, `632`, `656`), 감사 로그와 승인자를 포함한 `Session` 전체가 Mutex 하나 뒤에 있습니다 (`session.rs:520`).

프로세스 트리 전체의 exec/connect/open이 스레드 하나로 직렬화됩니다. **블로킹 `ask` 프롬프트(최대 300초)는 트리의 모든 프로세스를 그동안 멈춰 세웁니다** (`approve.rs:8-10`).

### 5.10 Mutex 오염이 세션 중간에 중계를 조용히 끝낸다

잠금 실패 시 `break`합니다 (`notify.rs:604`, `634`, `658`). 루프가 끝나면 listener fd가 닫히고, 대상의 이후 중재 syscall은 `ENOSYS`를 받습니다. `Full`이면 모든 `openat`이 실패합니다. **관측이 멈춘 지점을 표시하는 감사 엔트리는 없습니다.**

### 5.11 `--mediate full`은 파일 open마다 fsync 하나를 직렬로 낸다

근거는 `notify.rs:158-162`. 각 `openat`이 `ioctl RECV` -> `process_vm_readv` -> 정책 평가 -> fsync 포함 감사 append -> `ioctl SEND`를 단일 스레드로 돕니다. 10만 개 파일을 여는 빌드는 10만 번의 직렬 fsync를 냅니다.

**결과적으로 내구성 있는 설정이 실용 불가능해, 기본값은 파일 열기를 아예 기록하지 않습니다.** gap으로 보고되지만 (`session.rs:102-106`), 실질은 감사 로그의 파일 접근 이야기가 기본적으로 비어 있다는 것입니다.

### 5.12 프로토콜이 항상 TCP로 하드코딩된다

`AF_INET`과 `AF_INET6` 두 분기 모두 `protocol: Protocol::Tcp`입니다 (`notify.rs:485`, `499`). UDP 소켓의 `connect`도 TCP로 감사되고 평가됩니다. `Udp`/`Tls`/`Http` 태그가 타입에는 있으나 (`airlock-audit/src/types.rs:139-144`) 아무도 방출하지 않습니다.

**감사 로그가 관측하지 않은 프로토콜을 단언합니다.**

### 5.13 INET이 아닌 피어는 평가 없이 통과한다

`Peer::NotInet => true` (`notify.rs:610-611`).

유닉스 도메인 소켓 연결(Docker 소켓, ssh-agent 소켓 포함)이 평가도 기록도 없이 지나갑니다. 추상 소켓은 Landlock ABI >= 6의 스코프만 막습니다(3.9).

---

## 6. 정책 모델

### 6.1 glob 표현력

- **문자 클래스/중괄호/부정/이스케이프가 없고, 없다는 사실이 조용합니다.** 세그먼트는 `*`와 `?`만 와일드카드이고 나머지 바이트는 리터럴입니다 (`glob.rs:102-106`). `~/.ssh/id_[rd]sa`는 문법 오류가 아니라 `id_[rd]sa`라는 이름의 파일 하나에 매칭됩니다. 로드는 성공하므로 사용자는 규칙이 살아 있다고 믿습니다. 반대로 이름에 `*`나 `?`가 실제로 든 경로를 지목하는 사용자 규칙은 **쓸 수 없습니다.**
- **`**`는 패턴당 4개까지**입니다 (`glob.rs:7`, `92-95`). 백트래킹 비용 때문입니다.
- **`a/**`는 `a` 자신에도 매칭합니다** (`glob.rs:377-383`). deny에는 안전하나 allow에는 의도보다 넓습니다. `~/work/**` allow는 `~/work` 디렉토리 자체의 delete까지 포함합니다.
- **`?`는 문자가 아니라 바이트**입니다 (`glob.rs:396-441`). 의도된 설계이며 문서화되어 있으나 (`docs/policy-dsl.md` 5절), `~/작업/?.pem`은 한글 한 글자에 매칭하지 않습니다.
- **패턴에 변수 치환이 없습니다.** `~/`와 `~` 단독만 확장되고 `~user`는 거부입니다 (`glob.rs:64-79`). `$VAR`, `${workspace}`, `XDG_*`가 없어 팀 공유 프리셋이 머신/사용자별로 이식되지 않습니다.

### 6.2 대소문자/유니코드 접기는 근사치다

`Rule::case_insensitive()`가 `action.is_restrictive()`를 그대로 돌려줍니다 (`rule.rs:148-150`). **실행 중인 볼륨이 대소문자를 구분하는지는 보지 않습니다.**

두 방향으로 부정확합니다.

- 대소문자를 구분하는 ext4에서 `deny ~/work/Secret`은 진짜 다른 파일인 `~/work/secret`까지 막습니다(과차단).
- 구분하지 않는 APFS에서 `allow ~/work/**`는 `~/Work/x`에 매칭하지 않습니다(과소매칭).

비UTF-8 바이트가 섞인 세그먼트는 ASCII 대소문자 비교만 받습니다 (`glob.rs:443-462`). APFS/HFS+의 실제 폴딩 표는 유니코드 simple uppercase와 완전히 같지 않고, NFKC/NFKD는 아예 다루지 않습니다.

### 6.3 경로 정규화가 못 보는 것

- **하드링크는 원리적으로 보이지 않습니다.** 크레이트 전체에 inode/device 동일성 개념이 없습니다 (`path.rs:126-197`). `ln ~/.ssh/id_rsa ~/work/x` 후 `~/work/x`를 읽으면 `ssh-private-keys` forbid가 통째로 비껴 갑니다. 심볼릭 링크는 양방향 평가로 잡지만 하드링크는 해소 대상이 없습니다.
- **바인드 마운트도 같은 구멍입니다.** `mount --bind ~/.ssh ~/work/ssh` 후에는 요청 경로도 해소 경로도 `~/work/ssh/...`입니다.
- **firmlink 별칭 확장이 로드 시점 1회, 선행 고정 접두에만 적용됩니다** (`glob.rs:169-217`, `engine.rs:61-74`). `**/.env`처럼 선행이 와일드카드인 패턴은 변형을 못 얻고, 로드 후 생긴 마운트/링크는 반영되지 않습니다.
- **런타임 요청 경로에도 `~`를 확장합니다** (`path.rs:199-201`). 커널은 `~`를 확장하지 않으므로, cwd에 실제로 `~`라는 디렉토리가 있으면 정책은 `$HOME/work/x`로 판정하고 커널은 `./~/work/x`를 엽니다.
- **cwd가 세션 시작 시점 하나로 고정되고 dirfd 개념이 없습니다** (`path.rs:199`, `session.rs:185`). 자식이 `chdir`한 뒤의 상대 경로는 잘못된 디렉토리에 묶여 판정됩니다. `docs/policy-dsl.md` 4.2절이 dirfd 기준 해석을 요구하지만 정책 API에는 그것을 받을 자리가 없습니다.
- **procfs 특수 파일 모델이 없습니다.** 베이스라인에 `/proc/<pid>/{mem,environ,fd/N}` 관련 규칙이 하나도 없습니다 (`baseline.rs:30-188`). 다른 프로세스의 `environ`(토큰이 흔히 있습니다) 접근이 `[defaults].file`로 떨어집니다.
- 매달린 링크 추적은 **40회**에서 포기하고 그 시점 경로로 판정합니다 (`path.rs:174-197`).

### 6.4 egress 어휘가 좁다

`HostPattern`은 `Any | Exact | Suffix | Ip` 4형태이고 프리픽스 길이가 없습니다 (`host.rs:111-117`). 포트는 단일값 `Option<u16>`입니다 (`dsl.rs:49`).

- **CIDR을 쓸 수 없습니다.** `10.0.0.0/8`, `169.254.0.0/16`, `fd00::/8` 같은 사설/링크로컬 대역을 한 줄로 막지 못하고 IP마다 규칙을 하나씩 써야 합니다.
- **포트 범위가 없습니다.** `8000-9000`이나 "443 외 전부 deny"를 표현할 수 없습니다.
- **프로토콜 축이 없습니다.** 브로커는 감사에 프로토콜을 남기는데 정책에는 그 축이 없습니다.
- **인바운드(listen/bind)와 유닉스 소켓은 어휘 자체가 없습니다.**
- 호스트 와일드카드는 선행 `*.` 또는 단독 `*`만 됩니다 (`host.rs:128-134`). `api.*.com`은 로드 거부이고, `*.example.com`은 apex에 매칭하지 않아 규칙 두 개가 필요합니다.
- **런타임 비ASCII 호스트는 매칭에서 빠집니다** (`host.rs:151-156`). 특정 IDN 호스트를 지목한 `deny`가 그 호스트의 유니코드 표기에 걸리지 않고 `[defaults].egress`로 떨어집니다. 기본값이 `ask`인 정책에서는 **deny가 ask로 격하**되고 감사 로그에 어떤 규칙이 걸렸는지도 남지 않습니다.
- **호스트명과 IP를 잇는 개념이 없습니다** (`engine.rs:502-509`). 파일과 달리 요청/해소 양방향 평가가 없어, DNS 리바인딩과 CNAME과 라운드로빈을 표현할 수 없습니다.
- 호스트 규칙은 **백엔드와 무관하게 항상** 경고를 냅니다 (`engine.rs:524-533`). 정책 로드는 그 세션이 `--egress-proxy`로 뜰지 모르므로, 경고 문구는 "프록시로 실행할 때만 강제된다"는 조건부 형태입니다. 프록시 없이 돌리면 그대로 미강제입니다.

### 6.5 결정 모델

- **사용자는 `forbid`를 만들 수 없습니다** (`engine.rs:243-245`, `156-164`). probe도 컴파일 상수입니다 (`baseline.rs:12-19`). 조직 차원의 "이 경로는 명시 override 없이는 못 연다"는 규칙을 자기 정책으로 표현할 수 없습니다.
- **베이스라인 `ask` 규칙은 사용자 규칙이 아무 흔적 없이 무력화합니다.** 티어 순서상 사용자 규칙이 위이기 때문입니다 (`engine.rs:421-425`). `sudo-exec`, `crontab-exec`, `shell-init-write`, `autostart-write`, `git-config-write`, `pipe-*-to-shell`은 `action = "allow"` 한 줄로 꺼지며 **`reason`도 `overrides`도 요구되지 않고 경고도 없습니다.** forbid 완화만 근거를 요구하는 비대칭입니다.
- **`overrides`가 문자열 하나입니다** (`dsl.rs:42`). 한 경로가 forbid 두 개에 걸리면 각각을 지목하는 사용자 규칙을 따로 써야 하고, 어느 조합이 실제로 통과하는지 로드 시점에 알려 주지 않습니다.
- **`overrides`는 forbid만 지목할 수 있습니다** (`engine.rs:273-278`). 베이스라인 `ask`를 의도적으로 여는 결정에는 근거를 남길 문법이 없어, 그 결정이 다이제스트에 "완화 의도"로 기록되지 않습니다.
- **`ask` 승인에 범위/수명 개념이 없습니다** (`model.rs:3-9`). "이번만", "세션 동안", "N회까지"가 모델에 없어 승인 캐싱 정책을 정책 파일로 표현할 수 없습니다.
- **양방향 평가는 더 제한적인 쪽을 채택하되 티어 정보를 잃습니다** (`engine.rs:436-448`). 감사에 남는 규칙이 사용자가 요청하지 않은 경로의 규칙일 수 있습니다.
- **`evaluate_resolved_file`은 양방향 평가를 건너뜁니다** (`engine.rs:466-473`). 공개 API이며 안전성이 문서 주석의 호출 규약에만 의존합니다. Landlock 외 백엔드가 쓰면 링크 우회 방어가 사라지는데 타입으로 강제되지 않습니다.

### 6.6 정적 분석이 witness 경로 근사다

`docs/policy-dsl.md` 1절은 "실행 없이 정적으로 답할 수 있어야 한다"고 선언하지만, 구현에는 패턴 대수가 없고 정적 답변은 "구체 경로 하나에 대한 답"뿐입니다.

- 파일 shadow 판정은 규칙의 **모든** 패턴 × **모든** 모드가 덮여야 경고합니다 (`engine.rs:578-594`). **부분 가림은 전부 미탐입니다.**
- exec은 매처가 **완전히 동일**할 때만 경고합니다 (`engine.rs:615-618`). `program="rm"` 뒤에 `program="rm", argv_contains=["-rf"]`를 두면 뒤 규칙은 영원히 도달 불가인데 경고가 없습니다.
- witness 합성이 `**` -> 세그먼트 `x`, `*` -> 빈 문자열이라는 근사라 (`glob.rs:135-160`) 오탐도 납니다.

### 6.7 무효한 완화 탐지가 하드코딩된 probe에만 걸린다

probe × 6개 모드로 사용자 규칙만 평가합니다 (`engine.rs:300-327`). forbid와 겹치지만 probe를 비껴가는 사용자 규칙은 **경고 없이 아무 일도 하지 않습니다.**

- `allow ~/.ssh/config`는 probe가 `id_rsa`/`id_ed25519`/`identity`뿐이라 조용히 무효입니다.
- `allow ~/work/**`를 써도 그 안의 `.env`는 계속 막히는데 로드 시 아무 신호가 없습니다. 사용자는 런타임에서야 이유를 압니다.
- 검사는 `Query::File`만 만듭니다 (`engine.rs:301-306`). exec/egress forbid가 생기면 검사 대상이 아닙니다.

### 6.8 capability 어휘 공백

`kind`는 `file`/`exec`/`egress` 셋뿐이고 (`model.rs:59-64`), 파일 모드는 6개이며 `ModeSet`이 `u8`이라 최대 8개까지만 늘어납니다 (`model.rs:100-107`, `165-168`).

**표현 자체가 불가능한 것들**입니다.

시그널/`ptrace`, 유닉스 도메인 소켓(곧 `SSH_AUTH_SOCK` 에이전트 하이재킹), System V/POSIX IPC와 공유 메모리, 환경 변수 읽기/전달, fd 상속과 SCM_RIGHTS fd 전달, `mount`/`pivot_root`/네임스페이스, `chmod`/`chown`/setuid/setgid 비트, xattr/ACL, 디바이스 노드와 파일 타입, 심볼릭/하드링크 **생성**, 경계를 넘는 `rename`, `bind`/`listen`, DNS 질의, 클립보드/XPC/D-Bus, 키체인/키링 API, 프로세스 수와 리소스 한도.

이 중 상당수(에이전트 소켓, 하드링크 생성, rename, chmod +s)는 파일 forbid를 우회하는 **실제 경로**입니다. 정책에 그 축이 없으므로 커널 백엔드가 막든 말든 정책 층은 그 사실을 기록도 표현도 못 합니다.

두 가지 더 있습니다.

- **파일 `exec` 모드와 `kind = "exec"`는 서로 만나지 않는 두 어휘입니다** (`rule.rs:167-219`, `engine.rs:475-500`). `path = "/usr/bin/**", mode = ["exec"], action = "deny"`는 `evaluate_exec` 결정을 바꾸지 않습니다.
- **질의가 한 번에 모드 하나입니다** (`rule.rs:109-112`). `O_RDWR` 한 번의 open을 호출자가 두 질의로 쪼개야 합니다.

### 6.9 exec 조건이 program과 argv뿐이다

env, cwd, uid, 부모 프로세스, 실행 파일 해시 같은 조건을 쓸 수 없습니다 (`rule.rs:113-116`).

`argv_pattern`의 `*`는 NUL로 이은 argv 전체에 대한 앵커 없는 glob이라 **인자 경계를 넘어 매칭합니다** (`rule.rs:201-206`). 특정 argv 인덱스를 지목할 방법도, `*`를 리터럴로 쓸 방법도 없습니다. argv가 `&[String]`이라 비UTF-8 argv를 표현할 수 없고, program basename 비교는 `to_string_lossy`를 쓰는데 (`rule.rs:28`) 이는 glob 쪽이 일부러 피한 손실 변환입니다 (`glob.rs:61-63`). **같은 크레이트 안에서 두 정책이 다릅니다.**

### 6.10 베이스라인 프리셋의 공백

`baseline.rs:30-188`이 전부입니다. **`forbid` 대상에 없는** 고가치 경로입니다.

- `~/.git-credentials`, `~/.config/git/credentials`, `~/.config/gh/hosts.yml` (GitHub CLI 토큰)
- `~/.vault-token`, `~/.azure/**`, `~/.oci/**`, `~/.terraform.d/**`, `~/.databrickscfg`
- `~/.m2/settings.xml`, `~/.gradle/gradle.properties`, `~/.gem/credentials`, `~/.composer/auth.json`, `~/.nuget/**`
- `~/.password-store/**`, `~/.local/share/keyrings/**`, `~/Library/Keychains/**`
- `~/.config/containers/auth.json` (podman)
- 프로젝트 로컬 `.npmrc`, `.pypirc`, `.netrc` (베이스라인은 `~/` 형태만 잡습니다)
- **`**/.envrc`** (direnv. 시크릿이자 쉘 코드 실행인데 `**/.env`/`**/.env.*` 어느 쪽에도 매칭하지 않습니다)
- `**/*.pem`, `**/*.key`, `**/*.p12`

**지속성 경로에 없는 것**입니다.

- **`.git/hooks/**`** (저장소 로컬 훅. `git commit` 한 번으로 실행됩니다)
- `/Library/LaunchAgents/**`, `/Library/LaunchDaemons/**` (시스템 전역)
- `/etc/systemd/system/**`, `/etc/profile.d/**`, `/etc/cron.{daily,hourly,weekly,monthly}`
- `~/.vimrc`, `~/.config/nvim/**`, `~/.tmux.conf`

**exec 베이스라인의 회피 용이성**입니다.

- 권한 상승 계열에 `su`, `pkexec`, `run0`이 없습니다 (`baseline.rs:199-214`).
- `danger-rm`은 argv 원소가 정확히 `-rf`여야 합니다 (`baseline.rs:195`). **`rm -r -f`, `rm -fr`, `rm --recursive --force`는 전부 빠져나갑니다.**
- `pipe-curl-to-shell`은 문자열 패턴이라 (`baseline.rs:223-238`) `curl -o /tmp/x && sh /tmp/x`나 `bash <(curl ...)`는 걸리지 않고, `|`와 `sh`가 우연히 든 무해한 argv에는 오탐으로 걸립니다.

**플랫폼 가정이 하드코딩입니다.** `XDG_CONFIG_HOME`/`XDG_DATA_HOME` 재정의를 읽지 않아 (`baseline.rs:50`, `137-141`), XDG 경로를 옮겨 쓰는 사용자는 gcloud/fish/systemd/autostart 보호를 통째로 잃습니다. snap/flatpak Firefox 프로필도 미포함입니다.

**갱신 채널이 없습니다.** `FILE_SPECS`/`EXEC_SPECS`가 `const`라 (`baseline.rs:30`, `190`) 새 시크릿 경로를 반영하려면 바이너리를 다시 배포해야 합니다. 정책이 얼마나 낡았는지 알리는 메타데이터도 없습니다.

### 6.11 정책 다이제스트

- **커밋하지 않는 것**: 정책 `name`, `version` 필드, 홈 경로, probe 목록, 강제 백엔드와 플랫폼, glob/호스트 매칭 의미론의 버전 (`digest.rs:39-53`). 곧 다이제스트는 "규칙 텍스트"를 커밋하지 "실효 동작"을 커밋하지 않습니다. 케이스 폴딩 규칙이 바뀌어도 같은 규칙 집합이면 다이제스트가 그대로입니다.
- **티어 0은 버전 문자열 하나로만 커밋됩니다** (`baseline.rs:7`, `digest.rs:41`). 자기보호 규칙을 바꾸면서 상수를 안 올리면 다이제스트가 변하지 않습니다.
- **firmlink 변형 패턴이 다이제스트에 들어가 머신 종속성이 생깁니다.** `add_resolved_variants`가 규칙을 넓힌 **뒤에** 다이제스트를 계산하고 (`engine.rs:215-221` -> `329`), 변형 패턴의 `raw`는 그 머신의 canonicalize 결과입니다 (`glob.rs:209-216`). macOS에서 베이스라인 `/etc/shadow`는 `/private/etc/shadow` 패턴을 하나 더 얻고 Linux는 얻지 않습니다. **같은 정책 파일이 OS마다 다른 다이제스트를 냅니다.** `docs/policy-dsl.md` 11절("머신에 종속되지 않게")에 직접 어긋납니다.

### 6.12 정책 로드와 출처 신뢰

- **`read_trusted`가 검사하지 않는 것**: 부모 디렉토리의 소유/권한(쓰기 가능한 부모면 파일을 통째로 갈아 끼울 수 있습니다), 파일 타입(소유자 소유의 FIFO면 통과하고 `read_to_string`이 무한 대기합니다), `nlink`, 파일 크기 상한, ACL/xattr (`path.rs:51-88`). 실효 uid가 아니라 실제 uid를 봅니다 (`path.rs:67`).
- **`load_str`은 공개 API이며 아무 출처 검사도 하지 않습니다** (`engine.rs:135`). 어느 함수를 쓰느냐로 신뢰 경계가 달라집니다.
- **정책 파일 하나만이고 합성/include가 없습니다.** 조직 기본 정책 + 프로젝트 정책 계층화, 프리셋 상속, 부분 재정의를 표현할 수 없습니다.
- **`home_dir()`의 `/` 폴백이 API에 남아 실제로 쓰입니다** (`path.rs:22-33`). `cmd_policy.rs:77`이 `home_dir()`을, `cmd_run.rs:103`이 `home_dir_checked()`를 씁니다. `HOME`이 비면 `airlock run`은 거부하는데 `airlock policy explain`은 `~/.ssh/**`를 `/.ssh/**`로 축소한 채 답합니다. **설명 명령과 실제 강제의 결론이 갈립니다.**
- **규칙 id에 한국어를 쓸 수 없습니다** (`dsl.rs:70-72`). 근거는 커널 프로파일 주석 탈출 방지이며 타당하지만, 사람이 읽는 이름과 기계 식별자를 분리할 `title`/`label` 필드가 없습니다.
- **자기보호 대상이 호출자가 열거한 리터럴 경로 목록입니다** (`baseline.rs:319-372`). 감사 루트의 **부모 디렉토리**를 지우거나 이름을 바꾸는 요청은 티어 0에 매칭하지 않고, `rename` 모드가 없어 "이동으로 무력화"를 표현하지 못합니다. 정책 파일 후보 목록이 CLI의 탐색 로직(`airlock/src/paths.rs:81`)과 따로 관리되어 탐색 후보가 늘면 자기보호가 조용히 뒤처집니다.

### 6.13 판정 비용이 선형이고 캐시가 없다

`lookup`은 티어별로 전 규칙을 선형 스캔하고 (`engine.rs:389-428`), 매칭마다 `(pat.len()+1) * (path.len()+1)` 크기의 메모 벡터를 새로 할당합니다 (`glob.rs:356-358`). 접두 트리도 인덱스도 없습니다.

**syscall 한 번마다 이 비용이 듭니다.** 규칙이 수백 개인 정책이나 긴 경로에서 중계 층의 지연으로 나타납니다.

---

### 6.14 `max_bytes_out` 은 다음 연결부터 막는다

`kind = "egress"` 규칙의 `max_bytes_out` 은 **한도를 넘긴 그 연결 자체를 막지 못합니다.** 판정은 연결 시작 시점에 이미 아는 누적량으로만 하고(`engine.rs` `evaluate_egress_with_usage`), 누적량은 연결이 끝난 뒤 `EgressSummary` 를 기록할 때 갱신됩니다(`session.rs` `record_egress_summary`).

곧 한도 10MiB 를 적었는데 한 연결이 1GiB 를 반출했다면 그 1GiB 는 나갑니다. 막히는 것은 그다음 연결입니다. **연결이 하나뿐인 세션에서는 한도가 한 번도 걸리지 않습니다.** 연결 도중에 끊으려면 프록시가 스트림을 세면서 한도에서 잘라야 하고, 그 자리는 `docs/egress-proxy.md` 5절이 표시한 내용 검사기 지점입니다.

누적량은 세션 안에서만 삽니다. 세션이 끝나면 0 부터 다시 세므로, 자식을 여러 번 나누어 실행하면 한도가 실행 횟수만큼 늘어납니다. 세션을 넘는 한도는 이 어휘에 없습니다.

`max_bytes_out` 은 **프록시가 있어야 의미가 있습니다.** 반출 바이트를 세는 층은 프록시뿐이므로 `--egress-proxy` 없이 도는 세션에서는 누적량이 늘 0 이고 한도가 한 번도 걸리지 않습니다. 로드 시 경고(`LoadWarning::QuotaRuleNeedsProxy`)와 Landlock gap 으로 노출하지만 그것은 공개이지 완화가 아닙니다.

---

## 7. 감사 로그

### 7.1 단일 위조 엔트리가 실패가 아니라 경고로 강등된다

`verify_stream`은 `head.seq == last_seq - 1 && head.hash == second_last_hash`를 크래시 잔여물로 보고 `Warning::HeadLagsByOne`만 냅니다 (`verify.rs:400-409`). CLI의 `verify_one`은 `Ok(report)`면 경고가 있어도 **0을 반환합니다** (`cmd_audit.rs:80-96`).

곧 `chain.jsonl`에 쓸 수 있으나 `head.json`을 건드리지 않은 공격자가 잘 만들어진 엔트리 **하나**를 덧붙이면(seq+1, prev = 마지막 해시, 해시 재계산. 비밀값이 필요 없습니다) `airlock audit verify`가 노란 "크래시 잔여물" 줄을 찍고 **0으로 끝납니다.** 일어나지 않은 행위에 대한 allow 판정이나 가짜 `session_end`를 위조하는 비용이 엔트리 하나이며 실패를 내지 않습니다.

### 7.2 시간은 벽시계뿐이고 신뢰할 수 없다

`SystemTime::now()` 하나입니다 (`time.rs:3-8`). 단조 시계 값을 함께 담지 않습니다.

- 세션 전에 `settimeofday`를 하면 임의의 시각을 가진 체인이 깨끗하게 검증됩니다. RFC 3161 TSA도 NTP 증명도 없습니다.
- **시계 되감기는 경고일 뿐이고** (`verify.rs:325-331`), 앞으로 점프하거나 모든 엔트리가 같은 시각인 경우는 아무것도 트리거하지 않습니다. 타임스탬프를 비감소로만 유지하면 경고조차 피합니다.
- 로컬 타임존을 기록하지 않아 다른 로그와의 상관 분석에 외부 정보가 필요합니다. `u64` 나노초라 2554년이 상한입니다.
- **`ts_rfc3339`는 저장되지만 해시에 들어가지 않습니다** (`entry.rs:80`, `112-137`). 파일의 사람 읽는 필드는 무엇이든 적을 수 있고 `verify`는 `ts`와 대조하지 않습니다. `airlock audit`만 `ts`에서 다시 유도하므로 (`cmd_audit.rs:237-240`) jq/grep/대시보드로 `ts_rfc3339`를 직접 읽는 도구는 공격자가 통제하는 문자열을 읽습니다.

### 7.3 내구성

- **`--no-fsync`가 선행 기록 보장을 무효화합니다** (`log.rs:144-148`, `180-190`). "결정을 기록한 뒤 행위를 허용한다"는 `docs/audit-format.md:49-60`의 규칙이 강제 불가능해지고, 전원 차단 시 실제로 실행된 행위의 엔트리 꼬리가 임의로 날아갑니다. 제네시스에 기록되고 뷰어가 표시하지만 그것은 공개이지 완화가 아닙니다.
- 엔트리 쓰기와 head 쓰기가 별개 단계라 (`log.rs:141-152`) 그 사이 크래시가 7.1의 상태를 만듭니다.
- 체인 파일 생성 뒤 부모 디렉토리 fsync가 없습니다 (`log.rs:96-102`). 디렉토리 생성 직후 크래시하면 체인 파일이 내구화되지 않은 세션 디렉토리가 남을 수 있습니다.

### 7.4 회전/보존/용량 관리가 없다

명시적 비목표입니다 (`docs/audit-format.md:17`). 크기/기간 검사가 없고 정리 코드도 없습니다.

`~/.local/share/airlock/sessions/`가 실행마다 디렉토리 하나씩 무한히 자랍니다. **수동 정리는 증거 파기와 구분되지 않습니다**(2.4).

`airlock audit list`는 호출마다 모든 세션의 전체 해시 체인을 다시 검증합니다 (`cmd_audit.rs:272-298`). 목록 조회가 점점 느려집니다.

### 7.5 디스크가 차면 중계 경로만 fail-closed다

감독 스레드에서는 append 실패가 거부로 이어집니다 (`notify.rs:606-608`). 반면 Landlock/Seatbelt 규칙은 spawn 이전에 한 번 설치되고 로그를 참조하지 않습니다 (`session.rs:518`).

디스크가 차면 중재되는 `exec`/`connect`/`open`은 거부되고(방향은 맞으나 자식은 설명 없는 실패의 벽을 봅니다), 커널이 이미 허용한 나머지는 조용히 기록 없이 진행됩니다. 세션은 중단되지 않고 "여기서 기록이 멈췄다"는 표시도 남지 않습니다. **쓰기가 실패한 것이므로 남길 수도 없습니다.**

### 7.6 `actor`가 행위 주체가 아니라 브로커 자신의 pid다

`format!("pid:{} {program}", std::process::id())`를 한 번 만들어 모든 레코드에 복사합니다 (`cmd_run.rs:177`, `session.rs:232`). 감독 스레드는 진짜 `notif.pid`를 알지만 (`notify.rs:591`) `check_file`/`check_exec`/`check_egress`가 pid 인자를 받지 않습니다.

곧 **어느 자손 프로세스가 `~/.ssh/id_ed25519`를 열었는지 로그로 복원할 수 없습니다.** 규격 자신의 예시 `pid:41233 claude`(`docs/audit-format.md:72`)와 어긋납니다.

### 7.7 결정은 기록하고 결과는 기록하지 않는다

`commit`은 결정 엔트리를 붙이고 끝냅니다 (`session.rs:225-273`). "그 syscall이 성공했는가"에 해당하는 필드도, errno도, 전송 바이트도, fd도 없습니다.

**허용된 존재하지 않는 파일 열기와 키를 반출한 열기가 로그에서 같아 보입니다.** 이미 열린 fd에 대한 읽기/쓰기는 전혀 기록되지 않습니다. open만 중재 지점이고 그마저 `--mediate full`에서만입니다.

아웃바운드 연결 하나에 대해서만 결과가 생겼습니다. `Event::EgressSummary` 가 방향별 바이트와 지속 시간을 남기지만 그것은 egress 프록시 층 전용이고 남는 구멍은 7.15절에 있습니다. 파일과 exec 에는 여전히 결과가 없습니다.

### 7.8 exec 엔트리가 요청 경로와 실제 cwd를 잃는다

`Event::Exec`은 `program: resolved`만 담습니다 (`session.rs:308-312`). 요청 경로는 `session.rs:298`에서 계산하고 버립니다. `file_access`는 둘 다 남기는데(`docs/audit-format.md:174`) exec은 그러지 않습니다. **규격이 명시적으로 원하는 심볼릭 링크 악용 증거가 exec에서만 사라집니다.**

exec 엔트리의 `cwd`는 세션의 `self.cwd`이지 호출 프로세스의 실제 cwd가 아닙니다 (`session.rs:311`). 중계 층은 `/proc/pid/cwd`로 해소했는데도 그렇습니다 (`notify.rs:630`). `chdir`한 자손은 틀린 cwd로 기록되어 상대 argv를 사후에 해소할 수 없습니다.

### 7.9 정규 인코딩이 위치 기반이고 버전 신호가 없다

`Encoder`는 태그 없는 위치 기반 바이트를 냅니다 (`encoder.rs:17-72`). 유일한 버전 신호는 도메인 상수 `b"airlock.audit.v1\x00"`입니다. **`pub const FORMAT_VERSION: u32 = 1`은 죽은 상수입니다.** 워크스페이스 어디에서도 참조되지 않습니다 (`airlock-audit/src/lib.rs:22`).

제네시스에 `tag(mediation)`을 더한 변경이 같은 `v1` 도메인 안에서 기존 모든 체인의 해시를 바꿨고, `CHANGELOG.md`가 이를 기록합니다. 그런 체인은 `HashMismatch { seq: 0 }`으로 실패하는데 이는 **위조 보고와 바이트 단위로 동일합니다.** 검증자는 "옛 포맷"과 "위조된 제네시스"를 구분할 수 없습니다. 앞으로의 필드 추가도 같고, `Entry`와 `Event`의 `deny_unknown_fields`(`entry.rs:36`, `event.rs:7`) 때문에 v1 검증자는 v2 줄을 하드 거부합니다.

길이 접두는 스키마 안에서 모호성을 없애지만 인코더는 자기 서술적이지 않습니다. `u64(n)`과 8바이트 `bytes`의 길이 접두는 구분되지 않으므로, 단사성은 인코더와 검증자가 **똑같이 컴파일된 스키마**를 가질 때만 성립합니다. 제3자 검증이라는 가치 제안(`docs/audit-format.md:136`)에 필요한 in-band 스키마 표시가 없습니다.

### 7.10 비UTF-8 경로가 인코더에 닿기 전에 파괴된다

규격은 "정규화하지 않고 저장된 바이트 그대로"라고 하지만(`docs/audit-format.md:107`), 모든 이벤트 필드가 Rust `String`이고 생산자가 `to_string_lossy()`로 변환합니다 (`session.rs:218-219`, `173`, `notify.rs:715`, `cmd_run.rs:183`).

유효하지 않은 UTF-8이 든 경로는 U+FFFD로 치환되어 기록됩니다. **유효하지 않은 바이트열만 다른 두 파일이 바이트 단위로 같은 엔트리와 같은 해시를 만듭니다.** 관측 층의 실제 충돌이며 정규 인코더의 단사성으로는 복구할 수 없습니다.

### 7.11 검증이 연결 관계와 작은 의미 규칙 몇 개만 본다

`verify_stream`이 보는 것: 파싱, `seq` 무결번, 단일 세션 id, 제네시스 `prev == 0`과 `session_start`, `prev` 연결, 해시 재계산, 승인 대상의 존재와 `ask` 여부, head 앵커 (`verify.rs:275-418`).

**보지 않는 것**: `policy_digest`를 실제 정책과 대조, `mediation`이 실제와 맞는지, `enforcement`가 무엇과 맞는지, `ts_rfc3339`와 `ts`의 일치, `session_end`가 체인을 끝내는지, `session`이 0이 아닌지, 결정이 기록된 규칙 id와 일관되는지.

SIGKILL로 죽어 `session_end`가 없는 체인이 경고 없이 깨끗하게 검증됩니다. `enforcement: landlock` / `mediation: full`을 주장하면서 실제로는 아무것도 강제되지 않은 체인도 깨끗하게 검증됩니다. **검증은 "사후에 편집되었는가"에 답하지 "정확한 기록인가"에 답하지 않습니다.**

### 7.12 실행 중인 로그를 검증할 수 없다

개행 없는 마지막 줄에 하드 실패하고 (`verify.rs:268-270`), head/체인 불일치가 정확히 하나를 넘으면 `HeadMismatch`입니다 (`verify.rs:410-416`). 인자 없는 `airlock audit verify`는 **최신** 세션을 기본으로 잡습니다 (`cmd_audit.rs:65-76`).

세션이 도는 중에 검증하면 일상적으로 거짓 `TruncatedFinalLine`이나 `HeadMismatch`가 납니다. **사용자가 무결성 실패를 소음으로 여기도록 길들여집니다.** 진짜 실패가 무시되는 정확한 경로입니다.

### 7.13 검증이 첫 문제에서 멈추고 메모리 상한이 없다

모든 검사가 즉시 `Err`를 냅니다 (`verify.rs:280-323`). 손상된 줄 하나가 그 뒤 전부를 가립니다. "앞부분을 검증하고 발견 사항을 모두 보고"하는 모드가 없고, 손상된 체인의 온전한 부분을 구제/증명할 방법도 없습니다.

`verify_stream`은 상한 없는 `String`으로 `read_line`을 하고 (`verify.rs:253-261`), `read_entries_lossy`는 **모든** 엔트리를 `Vec`으로 모읍니다 (`log.rs:222`). `audit show`가 이것을 쓰므로 (`cmd_audit.rs:184`) `--limit 50`이어도 스트리밍이 아닙니다. 조작된 긴 줄 하나(10 GB)면 OOM입니다.

### 7.14 프라이버시

- **디렉토리 모드 복구가 없습니다.** `DIR_MODE = 0o700`, `FILE_MODE = 0o600`을 `DirBuilder::mode`로 걸어 umask가 못 풀지만 (`log.rs:18-19`, `91-102`), `create_dir_all_private`는 디렉토리가 이미 있으면 그냥 돌아가고 모드를 검사하거나 고치지 않습니다 (`log.rs:29-32`). `~/.local/share/airlock`이 0755로 미리 있으면 그대로 남아 다른 로컬 사용자가 세션 디렉토리 이름(시작 시각과 pid)을 열거할 수 있습니다.
- **감사 대상 에이전트가 자기 감사 기록과 과거 모든 세션을 읽을 수 있습니다.** 자기보호 규칙 `self:audit-log`가 쓰기 모드만 막고 (`baseline.rs:322-335`), 자식에게서 제거하는 것은 `AIRLOCK_AUDIT_DIR` 환경 변수뿐인데 (`session.rs:454-455`) 기본 경로는 추측 가능합니다. **거부당한 시크릿 경로 목록, 사용자가 돌린 모든 명령의 argv, 승인 노트, 접속한 호스트, 작업 공간 배치가 신뢰하지 않는 쪽에 넘어갑니다.** 읽기를 티어 0에 넣지 않은 것은 완화 가능성을 위한 의도적 선택입니다 (`docs/policy-dsl.md` 3.1절).
- **로그 자체가 시크릿 저장소입니다.** 절대 경로, 전체 argv, cwd, 정책 파일 경로, 자유 텍스트 승인 노트를 담습니다 (`event.rs:27-41`, `cmd_run.rs:228-259`). 명령줄로 넘긴 비밀(`--token`, `PGPASSWORD=... psql`, bearer 헤더가 든 curl)이 회전 없이 영구 보존되는 디스크 파일에 그대로 적힙니다. **레드액션 훅도, 필드 단위 생략도, 기록 허용 목록도 없습니다.**
- `display::sanitize`는 뷰어 쪽에만 적용됩니다 (`display.rs:20-47`, `cmd_audit.rs:127`). 증거 충실도를 위한 옳은 선택이지만, `chain.jsonl`을 읽는 다른 모든 소비자(jq 파이프라인, SIEM, 미래의 웹 뷰어)가 터미널 이스케이프/bidi 스푸핑 문제를 물려받고 각자 다시 구현해야 합니다.

---

### 7.15 결과 기록이 프록시 층 전용이다

`Event::EgressSummary` 는 egress 프록시만 방출합니다. seccomp 중계 층은 `connect(2)` 만 보고 그 뒤로 오가는 바이트를 보지 못하므로 결과를 만들 수 없습니다 (`notify.rs`).

곧 **`--egress-proxy` 없이 도는 세션의 반출량은 전혀 알 수 없습니다.** 그런 세션의 체인에는 `egress_summary` 가 하나도 없으며, 그것을 "아무것도 나가지 않았다" 로 읽으면 안 됩니다. macOS 처럼 중계 층이 아예 없는 플랫폼에서는 프록시 없는 세션에 `egress` 엔트리조차 없습니다.

프록시가 있어도 남는 것.

- **방향별 바이트를 세지 못한 연결에는 엔트리가 없습니다.** 업로드 방향은 별도 스레드에서 세므로 그 스레드를 띄우지 못했거나 `join` 에 실패하면 반출량을 모릅니다. 0 으로 기록하지 않고 훅 자체를 부르지 않으므로, 허용된 `egress` 수와 `egress_summary` 수의 차이로만 그 사실이 드러납니다.
- **바이트 수는 하한입니다.** 목적지에 완전히 써 넣은 조각만 세므로, `write_all` 이 도중에 실패하면 그 조각(최대 16KiB)이 빠집니다.
- **세션이 닫힌 뒤에 도착한 결과는 버려집니다.** 브로커는 세션을 닫기 전에 살아 있는 중계 연결을 최대 2초 기다리고, 그 상한을 넘겨 도착한 결과는 경고로만 나갑니다. 긴 터널을 남긴 채 자식이 끝나면 그 연결의 반출량은 로그에 없습니다.
- **상관 id 가 없습니다.** 같은 목적지로의 동시 연결이 여럿이면 개별 연결을 되짚을 수 없고 합계만 남습니다.
- **무엇을 보냈는지는 여전히 모릅니다.** 얼마나 보냈는지만 압니다. 내용 검사는 `docs/egress-proxy.md` 5절의 후속입니다.

### 7.16 확인 기록은 사람을 증명하지 않는다

`reviews.jsonl` 은 "누가 언제 어느 범위를 점검했다" 는 주장을 append-only 체인으로 잠급니다 (`review.rs`). 그 체인이 주장하지 **않는** 것이 더 중요합니다.

- **`reviewer_uid` 는 확인 명령을 돌린 계정이지 그 계정 뒤에 앉은 사람이 아닙니다.** `getuid(2)` 로 직접 읽으므로 남의 계정으로 기록할 수는 없지만, 그 계정을 쓰는 스크립트가 매일 도장을 찍는 것은 막지 못합니다.
- **`reviewer_tty` 가 `null` 인 것은 사람이 확인하지 않았다는 뜻이 아니라 터미널을 관측하지 못했다는 뜻입니다.** 반대로 값이 있다고 해서 사람이 리포트를 읽었다는 증거가 되지도 않습니다. cron 이 `airlock audit ack` 를 부르면 아무 조건 없이 도장이 찍히며, 그것을 막을 방법이 이 층에는 없습니다. 검증자는 터미널 미관측을 경고로만 보고합니다.
- **마지막 확인 줄의 삭제는 체인 안에서 정합적입니다.** 하루치 점검이 지워진 사실은 세션과 대조해야 드러나며, `airlock audit report` 가 마지막 확인 시각과 그 이후 세션 수를 함께 보여 주는 것이 유일한 단서입니다.
- **재계산 공격에 무력합니다.** 2.1절과 같습니다. 키도 서명도 없으므로 이 파일에 쓸 수 있는 주체는 체인 전체를 같은 비용으로 다시 계산합니다. 실질 탐지력은 앵커와 마찬가지로 저장 위치의 분리에서만 나옵니다.
- **`ts` 는 감사 체인과 같은 벽시계입니다** (7.2). "매일" 점검했다는 주장의 시각도 그 시계 위에 있습니다.

### 7.17 매일 점검 보고가 보는 범위가 좁다

`airlock audit report` 는 체인에 있는 것만 집계합니다. 곧 **커널이 거부한 접근(2.3)과 중계가 꺼져 보이지 않은 행위(2.6)는 이상 목록에 나타나지 않습니다.** 강제가 강할수록 보고가 조용해지는 역설이 그대로 이어집니다.

그 밖에 이 보고가 하지 않는 것.

- **이상의 종류가 고정 목록입니다.** 무결성·앵커·읽기 실패와 미응답 `ask` 와 신원 없는 승인뿐이며, "평소와 다른 목적지" 나 "평소보다 많은 반출" 같은 기준선 비교가 없습니다. 임계값도 학습도 없으므로 정상적으로 도는 세션은 반출량이 얼마든 "이상 없음" 입니다.
- **앵커 루트를 여러 감사 루트가 공유하면 오탐이 납니다.** 앵커에는 있는데 이 루트에 디렉토리가 없는 세션을 삭제로 보고하기 때문입니다. 판단 불가를 통과로 만들지 않는 쪽을 택한 결과이며, 그 배치에서는 `--anchor-dir` 를 루트마다 나누어야 합니다.
- **세션마다 체인을 두 번 읽습니다.** 무결성 검증과 엔트리 집계가 각각 파일을 훑으므로 세션이 많아질수록 보고가 선형으로 느려집니다. 7.4 의 회전 부재와 겹칩니다.
- **사람용 출력은 목록에 상한이 있습니다.** 상한이 걸린 사실 자체는 함께 찍지만, 전부 보려면 `--json` 이 필요합니다.
- **리포트 본문 다이제스트는 경로에 묶입니다.** 감사 루트나 앵커 루트 경로가 달라지면 같은 사실이라도 다른 다이제스트가 나옵니다. 감사 루트를 옮기면 그 이전의 확인 도장은 재계산으로 대조되지 않습니다.

---

## 8. 승인 채널

### 8.1 응답 상한 300초가 트리 전체의 최대 정지 시간이다

`DEFAULT_ASK_TIMEOUT = 300초` (`approve.rs:26`). 초과하면 `TimedOut`이고 `Action::Deny`로 매핑됩니다 (`session.rs:252`).

감독 스레드가 묻는 동안 세션 잠금을 쥐므로(5.9), 5분은 프로세스 트리 전체의 최대 정지 시간이기도 합니다. `poll` 오류도 타임아웃 경로로 접혀 (`approve.rs:163-166`) 일시적 poll 실패가 조용히 거부가 됩니다.

### 8.2 헤드리스와 CI에서는 모든 `ask`가 거부된다

`TtyApprover::available()`이 시작 시 `/dev/tty`를 한 번 탐침하고 (`approve.rs:123-129`), 실패하면 CLI가 `RefuseAll`로 물러납니다 (`cmd_run.rs:163-170`).

CI, 데몬, 분리된 세션에서는 모든 `ask` 규칙이 조용히 `deny`처럼 동작합니다. **정책의 의미가 터미널이 붙어 있느냐에 따라 달라지고**, 신호는 stderr 한 줄뿐입니다.

탈출구는 `--yes` 하나이며 이는 검토 없이 전부 승인합니다 (`approve.rs:84-98`). 곧 **헤드리스 사용자는 승인 통제를 통째로 포기하는 쪽으로 밀립니다.** 감사 로그는 그들이 그렇게 했다는 사실만 성실히 기록합니다.

### 8.3 승인의 지속/묶음/속도 제한이 없다

`Approver::ask`는 현재 요청만 받고 (`approve.rs:56`), `Session::commit`은 모든 `Action::Ask`마다 캐시 없이 호출합니다 (`session.rs:248-249`).

"항상 허용"도, 규칙별 기억도, 스로틀도 없습니다. `--mediate full`에서 `ask` 파일 규칙 하나가 그 경로의 **모든** `openat`마다 프롬프트를 냅니다. **승인 피로가 구조적입니다.**

### 8.4 승인된 행위가 실행 전에 재검증되지 않는다

`commit`이 승인 시 `Action::Allow`를 돌려주고 (`session.rs:250-253`), 호출자가 그대로 `respond(fd, notif.id, true)`로 넘깁니다 (`notify.rs:660-672`). 이는 `CONTINUE` 플래그를 세웁니다.

사람이 `y`를 누른 시점과 커널이 syscall을 다시 실행하는 시점 사이에 대상은 자기 메모리의 경로나 주소를 바꿔 쓸 수 있습니다. **프롬프트는 관측한 것에 대해 정직하지만 앞으로 일어날 일에 대한 보증은 아닙니다.**

### 8.5 상속된 stdin으로 자식이 사용자의 답을 읽을 수 있다

`/dev/tty`는 양쪽 허용 목록에서 일부러 뺐지만 (`landlock.rs:56-60`, `profile.rs:32-37`), 같은 자리 주석대로 상속된 stdin/stdout/stderr는 그대로 둡니다. `Command`에 stdio 리다이렉션이 없습니다 (`session.rs:466-469`).

대화형 실행에서 fd 0/1/2는 **바로 그 터미널입니다.** 자식은 fd 1에 써서 그럴듯한 가짜 승인 프롬프트를 그릴 수 있고, fd 0을 읽어 브로커의 `read_line`(`approve.rs:236`)보다 먼저 사용자가 친 `y`를 가져갈 수 있습니다. **`/dev/tty`를 막는 것으로 이 경로가 닫히지 않습니다.**

### 8.6 프롬프트 내용이 잘린 관측만큼만 완전하다

`.fact("argv", format!("{argv:?}"))`가 `read_argv`가 만든 벡터를 그대로 렌더합니다 (`session.rs:302`). 곧 잘림 표시를 포함합니다(5.5). 사람은 256번째에서 끝났을 수도 있는 목록을 보고 승인하는데 커널은 전체 argv로 진행합니다.

---

## 9. 프로세스 감독

### 9.1 리소스 한도가 전혀 없다

`setrlimit`, `rlimit`, `cgroup`, `unshare`, `CLONE_NEW*` 어느 것도 `crates/`에 없습니다. `Command`는 인자/cwd/env만 설정합니다 (`session.rs:466-469`). macOS는 `(allow process-fork)`가 무조건입니다 (`profile.rs:137`).

CPU/메모리/fd/프로세스 수/디스크 할당량 상한이 없습니다. **fork 폭탄, OOM 유발 할당, 작업 공간 디스크 채우기가 전부 설계상 허용됩니다.**

### 9.2 네임스페이스가 없다

PID/마운트/유저/네트워크 네임스페이스 어느 것도 쓰지 않습니다. 격리 원시 기구는 Landlock(`landlock.rs:767`)과 seccomp(`notify.rs:274-281`)뿐입니다.

자식은 호스트의 모든 프로세스를 보고(3.11의 `/proc/self` 제한은 별개), 호스트 마운트 테이블과 uid를 공유하며, 호스트 네트워크 스택을 물려받습니다. **컨테이너나 VM 경계가 없습니다.**

### 9.3 시그널 처리와 전달이 없다

어디에도 시그널 핸들러가 없습니다. `run`은 `cmd.spawn()`(`session.rs:527`)에서 곧장 `child.wait()`(`session.rs:538`)로 갑니다.

브로커에 SIGTERM을 보내면 브로커가 기본 처분으로 죽고 **자식은 계속 삽니다.** 감독 스레드가 프로세스와 함께 죽으므로 listener가 닫히고, 고아가 된 자식의 중재 syscall이 `ENOSYS`를 받기 시작합니다. `ExecNet`이면 더 이상 exec도 connect도 못 하고 `Full`이면 파일도 못 엽니다. **자식은 감사도 승인 채널도 없는 망가진 상태로 살아남습니다.**

### 9.4 프로세스 그룹 격리가 없어 손자가 살아남는다

`setsid`도 `process_group`도 kill-on-drop도 없습니다. 직계 자식만 거둡니다 (`session.rs:538`).

손자는 추적도 수거도 되지 않고, 직계 자식이 끝나면 init으로 재부모화되어 계속 돕니다. Landlock 규칙과 seccomp 필터는 상속되고 되돌릴 수 없으므로 샌드박스 안에는 있지만, **감독도 감사도 전혀 받지 않습니다.**

### 9.5 살아남은 손자가 브로커를 무한 대기시킨다

`child.wait()` 반환 후 `run`은 정지 플래그를 세우고 `handle.join()`을 부릅니다 (`session.rs:544-548`). 감독 스레드는 루프 맨 위에서만 `stop`을 보고 (`notify.rs:577`) 그 외에는 `ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, ...)`에 막혀 있습니다 (`notify.rs:581`). 커널은 **어떤** 프로세스도 필터를 잡고 있지 않을 때만 그 ioctl을 실패시킵니다 (`notify.rs:587` 주석).

곧 직계 자식이 끝났는데 손자가 살아 있으면 listener가 열린 채 `RECV`가 막히고 정지 플래그는 관측되지 않아 `join()`이 영원히 블록됩니다. **`airlock run`이 명령을 끝내고도 매달립니다.** `--mediate off`에서는 감독 스레드가 없어 발생하지 않습니다.

### 9.6 환경 정화가 고정 거부 목록이다

`INJECTION_PREFIXES = ["LD_", "DYLD_"]`와 14개 정확 일치 목록입니다 (`session.rs:418-436`).

허용 목록이 아니라 거부 목록이라 목록에 없는 로더/인터프리터 훅은 그대로 통과합니다. `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `GEM_PATH`, `LUA_INIT`, `R_PROFILE`, `PYTHONHOME`, `GIT_CONFIG_GLOBAL`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`가 예입니다. `PATH`는 의도적으로 보존합니다 (`session.rs:438-441`).

### 9.7 강제 gap이 감사 체인에 절대 기록되지 않는다

`gaps`는 `run`에서 모아 `RunReport.gaps`에만 담깁니다 (`session.rs:463-464`, `514`). `GenesisInfo`는 `airlock_version`, `argv`, `cwd`, `policy_digest`, `policy_source`, `mediation`만 담고 (`airlock-audit/src/log.rs:56-63`) `airlock-audit`에서 `gaps`는 검색되지 않습니다.

**변조 탐지 로그가 중계 수준은 기록하면서 "강제 층이 강제하지 못한 것의 목록"은 절대 기록하지 않습니다.** 나중에 체인을 읽는 감사자는 호스트 단위 egress나 exec 규칙이나 `ask` 의미론이 실제로 유효했는지 복원할 수 없습니다. Landlock 순회 예산 절단(3.1), 버려진 macOS 규칙, `PartiallyEnforced`(3.10)가 전부 여기 해당합니다. **엔트리의 `enforcement` 필드는 백엔드가 스스로 밝힌 `kind()`이며 세션 내내 상수입니다** (`log.rs:72`).

### 9.8 gap 기구 자체의 한계

`fn gaps(&self) -> Vec<String>`이고 기본 구현이 `Vec::new()`입니다 (`enforcer.rs:19-21`). 생산자는 전부 한국어 산문을 냅니다.

기계가 읽을 수 없고, 규칙 id에 파싱 가능한 형태로 묶이지 않으며, 실행 간 비교가 안 되고, 도구로 검증할 수 없습니다. **`Vec::new()`를 돌려주는 백엔드는 완전한 강제를 주장하는 셈이고 그 누락을 탐지할 기구가 없습니다.**

그리고 gap 목록 자체가 구성상 불완전합니다. 확인된 누락은 3.9(ABI < 6 스코프), 3.7(TCP bind), 3.5(glob/미존재 allow 경로), 2.7(`[defaults]` 무시), 3.6(`deny` egress 폐기)입니다. **gap 목록은 이 제품의 주된 정직성 기구인데, 실질적인 강제 구멍 몇 개가 거기 나오지 않습니다.**

### 9.9 `Enforcer` 트레이트가 spawn 시점에만 작용한다

`prepare` -> `wrap`이 전부이며 `wrap`은 `Command`를 변형할 뿐입니다 (`enforcer.rs:9-22`).

런타임 철회, 정책 재적재, 세션 중간 강화, syscall 단위 개입, 정리를 표현할 수 없습니다. 자식이 exec한 뒤 enforcer는 더 이상 영향력이 없고, **백엔드가 "시작 후 강제가 실효했다"고 보고할 방법이 없습니다.**

---

## 10. 제품/운영

### 10.1 CLI 표면

- **`init`이 없습니다.** 서브커맨드는 `run`, `audit {verify,show,list}`, `policy {explain,check,profile}`뿐입니다 (`main.rs:31-41`). 온보딩은 예제를 손으로 복사하는 것입니다.
- **README의 빠른 시작이 정책 없이는 그대로 실패합니다.** 베이스라인에 egress allow가 하나도 없어 `airlock run -- claude`는 `api.anthropic.com`을 DNS로도 못 찾고 ENOTFOUND로 죽습니다. 이 사실은 `examples/policy/claude-code.toml:5-8`에만 적혀 있습니다.
- **학습 모드가 정책을 만들어 주지 않습니다.** `--observe`의 도움말은 "학습 모드"인데 (`cmd_run.rs:16-17`), 관측된 세션의 감사 로그를 정책 규칙으로 바꾸는 `policy generate`/`suggest`가 없습니다. 곧 "observe -> 로그 손으로 읽기 -> TOML 손으로 쓰기" 루프가 전부 수동이고, `docs/design.md` 8장이 스스로 꼽은 "false positive로 인한 개발자 불편" 리스크의 대응이 전문가의 수작업입니다.
- **`run`에 `--dry-run`이 없고 정책 시뮬레이션이 단건뿐입니다.** `policy explain`은 한 번에 파일 하나 또는 exec 하나 또는 호스트 하나만 평가합니다 (`cmd_policy.rs:112-139`). 정책 파일을 픽스처 집합에 대해 회귀 테스트할 방법이 없어 정책 리팩터링을 눈으로 검증합니다.
- **데몬/서비스 모드가 없습니다.** 일회성 래퍼뿐이라 `airlock run`으로 시작하지 않은 것은 전부 보이지 않고 강제되지 않습니다.
- **기계 판독 출력(`--json`)이 어디에도 없습니다.** 모든 출력이 하드코딩 ANSI가 섞인 한국어 산문입니다. 유일한 기계 인터페이스는 종료 코드인데 그 코드가 어디에도 문서화되어 있지 않습니다. SIEM 적재와 CI 게이팅이 지역화된 컬러 텍스트 스크래핑에 의존하게 됩니다.
- **`NO_COLOR`도 TTY 감지도 없습니다.** `is_terminal`/`atty`가 코드에 없어 파이프나 파일로 리다이렉트해도 이스케이프가 그대로 나갑니다.
- **쉘 자동완성과 man 페이지가 없습니다.**
- **`--audit-root`(전역)와 `--audit-dir`(`run` 전용)이 같은 개념의 두 이름입니다** (`main.rs:19-25`, `cmd_run.rs:19-20`). 둘 다 있으면 후자가 조용히 이깁니다.
- **감사 로그 수명 주기 관리가 없습니다.** `prune`, 회전, 보존 정책, 용량 상한, 내보내기가 전부 없습니다(7.4).

### 10.2 정책 파일 탐색

- **상위 디렉토리로 거슬러 올라가지 않습니다** (`paths.rs:79-90`). 하위 디렉토리에서 실행하면 프로젝트 루트의 정책을 통째로 무시하고 조용히 홈 설정이나 베이스라인으로 떨어집니다. 빈 후보 슬롯이 심기 공격 표면이라는 근거는 타당하지만 (`paths.rs:72-75`), **한 단계 위에 정책이 있는데도 경고가 없습니다.**
- **정책에는 `XDG_CONFIG_HOME`을 무시하면서 감사에는 `XDG_DATA_HOME`을 존중합니다** (`paths.rs:81` vs `60-62`). 같은 바이너리 안에서 XDG 동작이 일관되지 않고, XDG 설정 경로를 옮긴 사용자는 오류 없이 베이스라인 전용 강제를 받습니다.
- **정책을 못 찾았을 때의 폴백이 조용합니다** (`cmd_run.rs:114-130`). "정책 파일을 찾지 못했다"는 줄이 없고 배너에 이름/규칙 수/다이제스트만 나옵니다. `airlock.tml`로 오타 났거나 cwd가 틀린 경우를 다이제스트를 읽어야만 구분합니다.

### 10.3 배포와 공급망

- **릴리스가 없습니다.** git 태그 0개, GitHub 릴리스 0개, crates.io 미게시, Homebrew/deb/rpm/설치 스크립트 없음. 문서화된 설치 경로는 `cargo build --release`뿐입니다.
- **서명/공증/SBOM/재현 빌드 검증이 없습니다.** macOS 코드사이닝도 Sigstore/GPG 서명도 CycloneDX/SPDX SBOM도 없고, `rust-toolchain.toml:2`가 "재현 빌드를 위해" 툴체인을 고정하면서도 재현성을 확인하는 잡이 없습니다. **보안 TCB인데 소비자가 어떤 산출물의 출처도 검증할 수 없습니다.**
- **"air-gapped ready"는 원칙이지 제공된 능력이 아닙니다.** `docs/design.md:136`과 `:202`가 air-gapped 재현 빌드 원칙을 내세우지만, `cargo vendor` 디렉토리도 오프라인 번들도 `.cargo/config.toml` 소스 치환도 없고 빌드에 crates.io와 rustup 접근이 필요합니다. 곧 air-gap **친화적**(작은 의존성 트리, 커밋된 lockfile, TCB에 C 의존성 없음)이지만 air-gap **준비 완료**는 아닙니다.
- **TCB 빌드 그래프에 외부 크레이트 55개가 있고 신뢰가 관행에 의존합니다.** 직접 의존은 타당하나 (`Cargo.toml:21-28`), 전이 폐포에 빌드 시점에 실행되는 proc-macro 컴파일러(`syn`, `quote`, `serde_derive`, `clap_derive`, `enumflags2_derive`)가 있습니다. `cargo vet`/`cargo crev` 감사도 의존성 리뷰 정책도 없습니다. **TCB의 무결성이 상류 유지보수자 약 30명의 crates.io 계정 보안에 걸려 있고, 손상된 proc-macro 릴리스 하나는 RUSTSEC 권고가 나올 때까지 기존 CI 게이트를 전부 통과합니다.**
- **CI 액션이 커밋 SHA가 아니라 가변 태그로 고정되어 있습니다** (`ci.yml:21`, `32`, `57`). `cargo install cargo-deny --locked`도 실행마다 최신 버전으로 흐릅니다. 보안 도구를 게이팅하는 CI에서 탈취된 액션 태그가 실행됩니다.
- **MSRV를 선언하고 테스트하지 않습니다.** `rust-version = "1.88"`(`Cargo.toml:10`)을 검증하는 CI 잡이 없고, `rust-toolchain.toml:2-4`의 주석은 여전히 1.87이라고 말합니다. **공급망 관련 메타데이터에서 드리프트가 이미 일어나고 있습니다.**
- **`cargo deny`가 push/PR에서만 돌고 스케줄이 없습니다** (`ci.yml:3-6`). 커밋이 7개인 저장소에서 조용한 기간에 나온 RUSTSEC 권고는 다음 사람 push까지 탐지되지 않습니다.

### 10.4 테스트와 CI

- **실제로 테스트하는 것은 OS 이미지 둘뿐입니다.** `ubuntu-24.04`(x86_64, 특정 커널 하나)와 `macos-15`(arm64)입니다. **`aarch64-linux`는 `cargo check`만 하고 절대 실행되지 않습니다** (`ci.yml:62-75`). x86_64 macOS는 빌드도 테스트도 안 합니다. 워크플로 자신이 지적하듯 seccomp arch 값과 syscall 번호가 아키텍처마다 다른데 (`ci.yml:69-70`), **aarch64 중계 코드는 한 번도 실행되지 않은 채 배포됩니다.**
- **Landlock ABI/커널 버전 매트릭스가 없고 강제 층 테스트가 조용히 건너뛸 수 있습니다.** 워크플로가 Landlock 탐침 실패 시 "강제 층 테스트가 조용히 건너뜁니다"라고 스스로 적어 두고 진단만 출력합니다 (`ci.yml:37-42`, `|| true`). **초록 CI가 강제 층이 실제로 돌았음을 증명하지 않습니다.**
- **퍼징도 속성 기반 테스트도 벤치마크도 없습니다.** `proptest`/`quickcheck`/`arbitrary`/`criterion`이 어디에도 없고 `fuzz/` 디렉토리도 없습니다. **신뢰할 수 없는 입력에 가장 많이 노출된 파서들(정책 TOML, 감사 체인 줄, seccomp로 읽은 argv/경로, glob 엔진)이 한 번도 퍼징되지 않았습니다.** 큰 파일시스템에서의 시작 시간 확장성도 측정되지 않았는데, 이미 순회 예산 고갈이 실제 배포된 버그였습니다(`CHANGELOG.md`).
- **어느 머신도 전체 테스트를 돌리지 않습니다.** 테스트 함수 368개는 커밋 7개치고 충분하지만, 플랫폼 강제 테스트가 하드 게이트되어 있습니다 (`enforce.rs:1`은 macOS 전용, `landlock_enforce.rs:1`과 `mediation.rs:1`은 Linux 전용). "cargo test --workspace 통과"는 언제나 부분집합 통과입니다.
- **테스트가 없는 영역**: 컬러/비TTY 출력, XDG 환경 처리, 동시 세션, 읽기 전용/가득 찬 파일시스템 위의 감사 디렉토리, CLI 층의 비UTF-8 경로.

### 10.5 문서

- **규격과 설계와 변경 이력이 한국어 전용입니다.** `docs/design.md`(247줄), `docs/policy-dsl.md`(530줄. 정책 언어의 유일한 레퍼런스), `docs/audit-format.md`(219줄. 감사 포맷의 유일한 레퍼런스), `docs/README.md`, `CHANGELOG.md`에 영문판이 없습니다. `../README_KR.md`와 `../SECURITY_KR.md`만 있습니다.

  결과적으로 **영어권 보안 리뷰어는 프로젝트 자신이 정본이라 선언한 문서를 읽을 수 없고**(`docs/README.md:9`), 외부 감사와 커뮤니티 정책 기여가 사실상 한국어에 묶입니다.
- **런타임 UX도 한국어 전용입니다.** clap 도움말, 배너, 경고, 감사 렌더링, 오류, 승인 프롬프트 전부입니다. 로케일 전환이 없습니다. 곧 비한국어 사용자는 README는 영어로 읽어도 **제품의 정직성 이야기가 걸려 있는 바로 그 표면인 배너의 "한계" 줄과 ask 승인 프롬프트를 읽지 못합니다.**
- **종료 코드가 어디에도 문서화되어 있지 않습니다.** 실제로 쓰는 값은 0/1/2/3/4/64/70/78입니다 (`cmd_policy.rs:206-212`, `cmd_run.rs:63-153`, `cmd_audit.rs:101`, `267`).
- **한국어/영어 README 쌍의 동기화를 확인하는 CI가 없습니다.** 지금은 맞지만 첫 비동기 편집에서 조용히 갈라집니다.

### 10.6 성숙도와 플랫폼 지원

- **출시 이전, 단일 유지보수자, 외부 감사 없음.** 워크스페이스 전체가 0.1.0이고 (`Cargo.toml:6`), 커밋 7개, git 신원 두 개가 같은 사람입니다. `SECURITY.md:18`이 "0.x는 최신 마이너 버전만 지원"이라고 하는데 **실제로 릴리스된 버전이 0개라 지원 대상 집합이 비어 있습니다.** TCB의 bus factor가 1이고 신고 처리 이력이 없습니다.
- **`panic = "abort"`이고 크래시 보고 채널이 없습니다** (`Cargo.toml:43`). TCB의 잠재 패닉 하나가 곧 에이전트 세션 전체의 서비스 거부이며, abort 구조상 `session_end` 엔트리 없이 세션이 끝납니다. 텔레메트리 부재는 이 제품의 성격에 맞지만, 크래시 후 무엇을 모아야 하는지에 대한 로컬 안내도 없습니다.
- **실질 지원 범위는 "최신 macOS 또는 Landlock 가능 Linux의 대화형 터미널"입니다.** Windows/BSD는 강제 백엔드가 없어 `--observe`만 가능하고 (`cmd_run.rs:342-346`), WSL1은 Landlock이 없어 실패하며, WSL2와 컨테이너는 커널 설정과 seccomp 권한에 달렸는데 CI에 없습니다 (`SECURITY.md:50`). ask 승인은 추가로 `/dev/tty`를 요구해 모든 플랫폼에서 비대화형 맥락을 배제합니다. **이 범위를 하나의 지원 매트릭스로 적어 둔 곳이 없습니다.**

---

## 11. 하드코딩 상수

설정으로 바꿀 수 없는 값들입니다. 근거를 함께 답니다.

| 상수                   | 값                         | 위치                                      |
|----------------------|---------------------------|-----------------------------------------|
| Landlock 순회 예산 (루트당) | `200_000`                 | `broker/landlock.rs:49`                 |
| 시스템 읽기 루트            | 8개                        | `broker/landlock.rs:51-60`              |
| exec 런타임 루트 (Linux)   | 4개                        | `broker/landlock.rs:73`                 |
| 쓰기 가능 장치 노드 (Linux)  | 5개                        | `broker/landlock.rs:80-86`              |
| gap 보고 상한            | `take(5)` × 2             | `broker/landlock.rs:570`, `576`         |
| Landlock ABI 상한      | `V8`                      | `broker/landlock.rs:997`                |
| 중계 문자열 읽기 상한         | `4096` 바이트 (256바이트 청크)    | `broker/notify.rs:367`, `381`           |
| 중계 argv 상한           | `256` 원소                  | `broker/notify.rs:680`                  |
| sockaddr 길이 창        | `2..=128`                 | `broker/notify.rs:454`                  |
| `openat2` syscall 번호 | `437` (리터럴)               | `broker/notify.rs:205`                  |
| ask 응답 상한            | `300`초                    | `broker/approve.rs:26`                  |
| 폴백 종료 코드             | `77` (거부 있음) / `70`       | `broker/session.rs:398`                 |
| 시스템 읽기 서브패스 (macOS)  | 14개                       | `broker/profile.rs:23-38`               |
| 쓰기 가능 장치 노드 (macOS)  | 8개                        | `broker/profile.rs:46-55`               |
| `**` 개수 상한           | `4`                       | `policy/glob.rs:7`                      |
| 심볼릭 링크 추적 상한         | `40`회                     | `policy/path.rs:176`                    |
| 파일 모드 상한             | `u8` = 8개                 | `policy/model.rs:165`                   |
| egress shadow 탐침 포트  | `443`                     | `policy/engine.rs:597`                  |
| witness 합성 문자        | `x`                       | `policy/glob.rs:140-152`                |
| 정책 파일 권한 마스크         | `0o022`                   | `policy/path.rs:75`                     |
| egress witness 호스트   | `airlock-witness.invalid` | `policy/engine.rs:566`                  |
| 정책 버전                | `1` (마이그레이션 경로 없음)        | `policy/lib.rs:18`, `engine.rs:137-139` |
| 감사 디렉토리/파일 모드        | `0o700` / `0o600`         | `audit/log.rs:18-19`                    |
| 해시/세션 id 길이          | `32` / `16` 바이트           | `audit/types.rs:61-62`                  |
| 감사 도메인 상수            | `airlock.audit.v1\0`      | `audit/entry.rs:9`                      |
| `audit show` 기본 상한   | `50` 엔트리                  | `airlock/cmd_audit.rs:21`               |
| 다이제스트 표시 길이          | `12` hex 문자               | `airlock/cmd_audit.rs:124`              |

**상한이 없는 것**도 함께 적어 둡니다. 규칙 수, 규칙당 패턴 수, 정책 파일 크기, 경고 개수 (`policy/engine.rs:370-375`), SBPL 프로파일 크기 (`broker/profile.rs:598-620`), 감사 체인 한 줄의 길이 (`audit/verify.rs:253-261`), 감사 로그 총 크기.

---

## 12. 문서와 코드의 어긋남

| 항목                     | 문서가 말하는 것                                               | 코드가 하는 것                                                                                 |
|------------------------|---------------------------------------------------------|------------------------------------------------------------------------------------------|
| 다이제스트 머신 독립성           | `policy-dsl.md` 11절 "머신에 종속되지 않게", "경로 패턴은 작성된 그대로" | firmlink 변형이 다이제스트에 포함되어 macOS와 Linux의 baseline 다이제스트가 다름 (`engine.rs:215-221` -> `329`) |
| 중괄호 표기                 | `policy-dsl.md` 9절이 `~/.cargo/credentials{,.toml}`을 씀  | 중괄호 확장 미지원. 코드는 두 경로를 따로 적음 (`baseline.rs:96-97`)                                        |
| shell-history 목록       | `policy-dsl.md` 9절이 `~/.python_history` 등 "등"          | 코드는 정확히 5개 (`baseline.rs:107-113`). "등"에 해당하는 확장 없음                                      |
| 정적 결정 가능성              | `policy-dsl.md` 1절 "실행 없이 정적으로 답할 수 있어야"                 | 패턴 대수 없음. 정적 분석은 witness 경로 근사뿐 (`engine.rs:549-620`)                                    |
| 저장 바이트 보존              | `audit-format.md:107` "정규화하지 않고 저장된 바이트 그대로"            | 생산자가 `to_string_lossy()`로 U+FFFD 치환 (`session.rs:218-219`)                               |
| `actor` 예시             | `audit-format.md:72`의 `pid:41233 claude`                | 항상 브로커 자신의 pid (`cmd_run.rs:177`)                                                        |
| exec 엔트리 경로            | `audit-format.md:174`가 요청/해소 양쪽 보존을 요구                  | exec은 해소 경로만 남김 (`session.rs:308-312`)                                                   |
| `FORMAT_VERSION`       | 포맷 버전 상수 존재                                             | **죽은 상수.** 어디서도 참조되지 않음 (`audit/lib.rs:22`)                                              |
| MSRV                   | `rust-toolchain.toml:2` 주석이 1.87                        | `Cargo.toml:10`은 1.88                                                                    |
| `metadata`/`delete` 모드 | `policy-dsl.md` 6절이 지원 모드로 나열                          | 중계 층이 절대 생성하지 않음 (`notify.rs:534-543`)                                                   |
| 프로토콜 태그                | `audit/types.rs:139-144`에 `Udp`/`Tls`/`Http` 존재         | 아무도 방출하지 않고 항상 `Tcp` (`notify.rs:485`, `499`)                                            |
| `0x30 policy_reload`   | `audit-format.md:172`가 예약                               | 절대 방출되지 않음                                                                               |

---

## 13. 미구현 (설계는 있고 코드가 없음)

`docs/design.md` 6장 MVP 기준으로 6번이 남아 있고, 7장 로드맵은 전부 남아 있습니다.

| 항목                                       | 상태  | 무엇이 막혀 있는가                                                     |
|------------------------------------------|-----|----------------------------------------------------------------|
| egress 프록시 층 (macOS)                     | 구현됨 | `--egress-proxy`. `crates/airlock-proxy`, 4.1절                    |
| egress 프록시 층 (Linux netns)               | 미구현 | 현재는 Landlock 포트 축소까지만. 자식이 프록시 포트로 직접 나가면 우회됨              |
| 프록시의 TLS 종단과 SNI 관측                      | 미구현 | v1은 CONNECT 호스트명까지만 봄. 터널 내용은 해석하지 않음                       |
| MCP 프록시 층                                | 미구현 | MCP tool call 중재/기록. `crates/`에 `mcp` 문자열 0개                   |
| egress DLP (시크릿 패턴 차단)                   | 미구현 | 프록시 층의 후속                                                      |
| 감사 로그 하드웨어 서명                            | 미결  | TPM 2.0 vs Secure Enclave vs 소프트웨어 키링 미정 (`design.md:243-246`) |
| 정책 프리셋 배포/갱신 채널                          | 미결  | 서명된 번들 형태 미정. 베이스라인이 컴파일 상수                                    |
| ct-merkle 기반 inclusion/consistency proof | 연기  | 제3자 witness가 필요해지는 시점의 업그레이드 경로 (`design.md` 10.5)             |
| macOS Endpoint Security Framework        | 로드맵 | Apple 개별 승인/유료 개발자/notarization 필요 (`design.md` 10.3)          |
| ask 승인 TUI 알림                            | 미구현 | 현재는 `/dev/tty` 인라인 프롬프트뿐                                       |
| Windows/FreeBSD 백엔드                      | 없음  | `--observe`만 가능                                                |

---

## 14. 참고

- `SECURITY.md` "취약점이 아닌 것" 절이 이 문서의 요약이며 신고 판단의 기준입니다.
- `docs/design.md` 10장이 외부 기술 제약(플랫폼 API, 커널 ABI)을 다룹니다.
- `docs/policy-dsl.md`와 `docs/audit-format.md`가 각 층의 정본 규격입니다. **규격과 코드가 어긋나면 규격이 옳으며**, 그런 어긋남은 12장에 모았습니다.
- `airlock run`의 배너와 enforcer gap 목록이 그 세션에 실제로 적용된 한계를 런타임에 출력합니다. 이 문서가 전체 목록이라면 배너는 그날의 목록입니다.
