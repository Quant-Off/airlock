#!/usr/bin/env bash
# 전체 검증. CI와 로컬에서 같은 것을 돌립니다
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== test =="
# --no-fail-fast 없이는 앞선 테스트 바이너리가 깨지는 순간 나머지가 실행되지 않습니다.
# 강제 층 테스트가 CLI 테스트 뒤에 있어서, 실패 하나가 다른 실패를 통째로 가렸습니다
cargo test --workspace --no-fail-fast

echo "== 라이브러리 코드 unwrap/expect 금지 =="
# 실패 경로를 삼키는 unwrap은 브로커가 TCB이므로 허용하지 않습니다.
# 테스트 코드는 제외합니다.
found=0
while IFS= read -r f; do
  if awk '/^#\[cfg\(test\)\]/{exit} /\.unwrap\(\)|\.expect\(/{print FILENAME": "NR": "$0; c=1} END{exit !c}' "$f"; then
    found=1
  fi
done < <(find crates -name '*.rs' -not -path '*/tests/*')
if [ "$found" -ne 0 ]; then
  echo "라이브러리 코드에 unwrap/expect가 있음"
  exit 1
fi
echo "없음"

echo "== 정책 프리셋 검증 =="
for p in examples/policy/*.toml; do
  echo "-- $p"
  cargo run -q -p airlock -- policy check --policy "$p"
done

echo "== 배포 메타데이터 =="
# description 이나 의존 version 누락은 릴리즈를 누르는 순간에야 드러납니다.
# 아직 crates.io 에 없는 크레이트는 cargo package 가 색인을 찾지 못하므로
# 매니페스트 자체를 검사합니다
cargo metadata --no-deps --format-version 1 | python3 scripts/metadata-check.py

# 의존이 없는 리프는 실제 패키징까지 검사할 수 있습니다
cargo package -p airlock-canonical --allow-dirty -q >/dev/null
echo "airlock-canonical 패키징 통과"

echo
echo "전부 통과"
