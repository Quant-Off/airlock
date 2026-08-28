# 보안 정책

[![Language](https://img.shields.io/badge/SECURITY-English_Ver-blue?style=for-the-badge)](SECURITY.md)

Airlock은 보안 도구이므로 이 문서가 신고 경로와 실제 보장 범위를 함께 밝힙니다.

이 문서를 참고하시어 프로젝트의 중요한 보안 보고 규칙을 따라 주시길 바랍니다.

## 취약점 신고

공개 이슈로 올리지 말고 <qtfelix@qu4nt.space>로 보내주세요. 다음이 포함되어 있는 경우 문제의 재현이 빠르게 진행됩니다.

- Airlock 버전(`airlock --version`)과 OS 버전
- 사용한 정책 파일과 `airlock policy check` 출력
- 재현 절차(가능하면 실패하는 테스트 형태로)
- 감사 로그 디렉토리(`chain.jsonl`, `head.json`; 경로에 시크릿이 담길 수 있으니 필요한 부분만 보내 주세요)

접수 확인은 3일, 초기 판단은 14일 안에 회신드리겠습니다. 수정 전 공개는 사용자를 위험에 두기 때문에 패치와 릴리즈 이후 공개를 원칙으로 합니다.

## 신뢰 경계

TCB(Trusted Computing Base)는 `airlock-broker`와 그 아래 `airlock-policy`, `airlock-audit`, `airlock-canonical`, `airlock-proxy` 뿐입니다. 에이전트, 에이전트가 띄우는 툴, MCP 서버, LLM은 전부 신뢰 경계 밖입니다.

곧 아래는 **취약점으로 판단합니다.**

- 정책이 deny 또는 forbid로 판정하는 접근이 커널에서 실제로 일어남
- 사용자 규칙이 내장 forbid를 `overrides` 없이 완화함
- 감사 로그 엔트리를 수정·삭제·삽입했는데 `airlock audit verify`가 통과함
- 승인 프롬프트가 에이전트가 만든 문자열을 브로커가 관측한 사실처럼 보여 줌
- 강제되지 않는 규칙이 강제된 것처럼 보고됨. 배너와 gap 목록에 나오지 않는 미강제도 포함됨
- 변조된 체인에 대해 `airlock audit report`가 이상 없음으로 끝남. 탐지 불가를 통과로 보고하는 것도 포함됨
- 자동 승인(`--yes`)이 사람이 확인한 승인처럼 표시되거나 확인 기록에 남음

## 취약점이 아닌 것

아래는 알려진 한계이며 Airlock이 배너와 문서에서 스스로 밝히는 범위입니다. 신고해 주셔도 전혀 문제 없지만, 설계상 그렇게 동작합니다.

- 감사 디렉토리와 앵커 디렉토리 **양쪽**에 쓰기 권한을 가진 공격자가 체인과 앵커를 함께 재계산함. `--anchor-dir`로 앵커를 분리하지 않으면 이 조건이 기본으로 성립합니다. `docs/audit-format.md` 2절이 이 경계를 규정합니다
- 호스트 단위 egress 정책이 강제되지 않음. 프록시 층이 없어 포트까지만 강제합니다(Linux) 또는 아웃바운드 전체 허용·차단만 가능합니다(macOS)
- 프록시 없이 도는 세션에서 평문 아웃바운드가 막히지 않음. 중계 층은 `connect(2)`만 보고 모든 연결을 `tcp`로 보고하므로 평문 바닥이 발동하지 않습니다
- exec 화이트리스트 모드에서 `/lib`·`/usr/lib` 트리가 통째로 실행 허용됨. 동적 링커에 `Execute`가 필요하기 때문이며, `mmap(PROT_EXEC)`은 Landlock이 아예 매개하지 않습니다
- `max_bytes_out` 한도를 넘긴 그 연결 자체는 막히지 않음. 바이트 수는 연결이 끝나야 알 수 있어 다음 연결부터 적용됩니다
- 확인 기록(`reviews.jsonl`)의 `reviewer_uid`가 계정을 가리킬 뿐 사람을 증명하지 못함. cron이 매일 `audit ack`를 부르는 것을 이 층에서 막을 수 없습니다
- macOS에서 `ask` 규칙이 커널 프로파일에서 deny로 내려감. Seatbelt는 사람 승인을 표현할 수 없습니다
- macOS에서 자식 프로세스의 개별 exec·파일 접근이 감사에 남지 않음. 런타임 중계 기구가 없습니다. 아웃바운드 연결은 예외로, `--egress-proxy`에서는 프록시 자체가 판정하고 기록합니다
- 중계 층(seccomp user notification)이 읽은 경로와 커널이 실제로 여는 대상이 다를 수 있음(TOCTOU). 파일 접근의 실제 경계는 Landlock입니다
- Landlock이 커널에서 거부한 접근 자체는 감사 로그에 남지 않음
- root 권한을 이미 가진 공격자, 커널 취약점, 물리 접근

## 검증

```bash
$ ./scripts/check.sh
```

fmt, clippy(`-D warnings`), 전체 테스트, 라이브러리 코드 unwrap 금지, 정책 프리셋 로드를 확인합니다. 강제 층은 주장에 그치지 않고 실제로 프로세스를 샌드박스에 넣어 시크릿 읽기가 거부되는지 확인합니다. Linux 전용 테스트는 Landlock을 지원하는 커널(5.13 이상)이 필요하며, 컨테이너에서는 seccomp 필터를 걸 수 있어야 합니다.
