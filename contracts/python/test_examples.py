import json
from pathlib import Path

from oath_contracts import verify_signed_document


EXAMPLES = (
    "exec-assessment-v3.signed.json",
    "publish-assessment-v2.signed.json",
    "registry-verdict-v1.signed.json",
)


def main() -> None:
    root = Path(__file__).parent.parent / "examples"
    for name in EXAMPLES:
        document = json.loads((root / name).read_text(encoding="utf-8"))
        assert verify_signed_document(document), f"{name}: signature rejected"
        document["generated_at"] += 1
        assert not verify_signed_document(document), f"{name}: mutation was accepted"
    print(f"verified {len(EXAMPLES)} Python contract fixtures")


if __name__ == "__main__":
    main()
