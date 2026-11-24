"""Command dispatcher. Each stage prints "not built yet" and exits 1 for now."""

from __future__ import annotations

import sys

STAGES = (
    "data",
    "baselines",
    "llm-eval",
    "frontier",
    "train",
    "merge",
    "gate",
    "bench",
    "demo",
    "report",
)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in STAGES:
        sys.stderr.write(
            "usage: python -m cve2cwe <stage> [stage args...]\nstages: "
            + " ".join(STAGES)
            + "\n"
        )
        return 1
    stage, rest = argv[0], argv[1:]
    if stage == "data":
        from cve2cwe import data

        return data.main()
    if stage == "train":
        from cve2cwe import train

        return train.main(rest)
    if stage == "merge":
        from cve2cwe import merge

        return merge.main(rest)
    if stage == "llm-eval":
        from cve2cwe import llm_eval

        return llm_eval.main(rest)
    sys.stdout.write(f"{stage}: not built yet\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
