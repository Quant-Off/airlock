#!/usr/bin/env bash
# 전체 검증. CI와 로컬에서 같은 것을 돌립니다
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== test =="
cargo test --workspace

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

echo
echo "전부 통과"
