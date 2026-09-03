# Airlock 문서

## 설계

- [design.md](design.md) 전체 설계 (개요, 위협 모델, 아키텍처, 확정 결정, 기술 제약, MVP, 로드맵, 리스크)
- [limitations.md](limitations.md) 현재 구현의 전체 한계 목록 (강제 층, 정책, 감사, 승인, 운영)

## 가이드

- [setup-wizard.md](setup-wizard.md) 대화형 설정 마법사 `airlock setup`의 구조와 흐름
- [i18n.md](i18n.md) 출력 로케일 (한국어·영문), 결정 순서와 다이제스트 결합

## 규격

구현의 정본입니다. 코드와 어긋나면 규격이 옳습니다.

- [audit-format.md](audit-format.md) 해시체인 감사 로그 포맷 `airlock.audit.v2`, 세션 상위 앵커 체인 `airlock.anchor.v1`, 매일 이상여부 점검과 책임자 확인 체인 `airlock.review.v1`
- [policy-dsl.md](policy-dsl.md) capability 정책 DSL과 평가 의미론 `airlock.policy.v2`
- [egress-proxy.md](egress-proxy.md) 호스트 단위 egress 강제와 프록시 프로토콜 `airlock.proxy.v1`

## 저장소 루트

- [../SECURITY.md](../SECURITY.md) 신고 경로와 신뢰 경계, 무엇이 취약점이고 무엇이 알려진 한계인지
- [../CONTRIBUTING.md](../CONTRIBUTING.md) 기여 가이드, 검증 절차와 보안 경계를 건드리는 변경의 기준
- [../CHANGELOG.md](../CHANGELOG.md) 변경 이력

설계 결정이 바뀌면 코드보다 먼저 이 디렉토리를 갱신합니다.
