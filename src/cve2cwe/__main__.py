"""Command dispatcher. A stage that is not built yet prints that and exits 1."""

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
    "backlog",
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
    if stage == "baselines":
        from cve2cwe import baselines

        return baselines.main(rest)
    if stage == "frontier":
        from cve2cwe import frontier

        return frontier.main(rest)
    if stage == "train":
        from cve2cwe import train

        return train.main(rest)
    if stage == "merge":
        from cve2cwe import merge

        return merge.main(rest)
    if stage == "llm-eval":
        from cve2cwe import llm_eval

        return llm_eval.main(rest)
    if stage == "gate":
        from cve2cwe import gate

        return gate.main(rest)
    if stage == "bench":
        from cve2cwe import bench

        return bench.main(rest)
    if stage == "backlog":
        from cve2cwe import backlog

        return backlog.main(rest)
    if stage == "report":
        from cve2cwe import report

        return report.main(rest)
    sys.stdout.write(f"{stage}: not built yet\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
