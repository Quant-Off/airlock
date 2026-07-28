#!/usr/bin/env python3
"""cargo metadata를 읽어 배포에 필요한 필드가 빠지지 않았는지 봅니다.

description이나 path 의존의 version 누락은 crates.io 업로드를 거부당하는 원인이며,
아직 색인에 없는 크레이트는 cargo package로 미리 잡을 수 없어 매니페스트를 직접 봅니다.
"""

import json
import sys

REQUIRED = ("description", "license", "repository")


def main() -> int:
    meta = json.load(sys.stdin)
    problems = []
    for pkg in meta["packages"]:
        name = pkg["name"]
        for field in REQUIRED:
            if not pkg.get(field):
                problems.append(f"{name}: {field} 없음")
        for dep in pkg["dependencies"]:
            if dep.get("path") and dep["req"] == "*":
                problems.append(f"{name}: {dep['name']} 의존에 version 없음")

    if problems:
        print("\n".join(problems))
        return 1
    print(f"크레이트 {len(meta['packages'])}개 이상 없음")
    return 0


if __name__ == "__main__":
    sys.exit(main())
