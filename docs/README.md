# Airlock 문서

## 설계

- [design.md](design.md) 전체 설계 (개요, 위협 모델, 아키텍처, 확정 결정, 기술 제약, MVP, 로드맵, 리스크)

## 규격

구현의 정본입니다. 코드와 어긋나면 규격이 옳습니다.

- [audit-format.md](audit-format.md) 해시체인 감사 로그 포맷 `airlock.audit.v1`
- [policy-dsl.md](policy-dsl.md) capability 정책 DSL과 평가 의미론 `airlock.policy.v1`

## 저장소 루트

- [../SECURITY.md](../SECURITY.md) 신고 경로와 신뢰 경계, 무엇이 취약점이고 무엇이 알려진 한계인지
- [../CHANGELOG.md](../CHANGELOG.md) 변경 이력

설계 결정이 바뀌면 코드보다 먼저 이 디렉토리를 갱신합니다.
