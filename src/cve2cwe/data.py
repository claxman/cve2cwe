"""Build the CVE -> CWE dataset. Implements docs/DESIGN.md section 4.

Stages (in order): fetch, rule 1, rule 2, split (rule 3), label set (rule 4),
dedup (rule 5), cap (rule 6), write processed files, labels, stats, manifest,
dataset card, leakage checks.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import lzma
import os
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import ijson
import numpy as np
import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "configs" / "data.yaml"

# Canonical funnel order (pipeline order, not alphabetical). Used by the stdout
# log and the dataset card so the funnel always reads top to bottom.
FUNNEL_ORDER: tuple[str, ...] = (
    "rule_1_input",
    "rule_1_dropped_rejected",
    "rule_1_dropped_no_english",
    "rule_1_dropped_no_date",
    "rule_1_dropped_before_cutoff",
    "rule_1_kept",
    "rule_2_dropped_no_label",
    "rule_2_dropped_placeholder",
    "rule_2_dropped_multi_label",
    "rule_2_kept",
    "rule_3_split_train",
    "rule_3_split_dev",
    "rule_3_split_test",
    "label_set_size",
    "rule_4_train_kept",
    "rule_4_dev_kept",
    "rule_4_test_kept",
    "rule_5_dev_dropped_equals_test",
    "rule_5_train_dropped_equals_dev_or_test",
    "rule_5_train_within_dropped",
    "rule_5_train_conflicting_labels",
    "rule_6_train_dropped",
    "final_train",
    "final_dev",
    "final_test",
)


def _ordered_funnel(funnel: dict) -> dict:
    """Return funnel in the canonical pipeline order; append unknown keys at the end."""
    out: dict = {}
    for k in FUNNEL_ORDER:
        if k in funnel:
            out[k] = funnel[k]
    for k in funnel:
        if k not in out:
            out[k] = funnel[k]
    return out

# ---------------------------------------------------------------------------
# Config and small helpers.


def _load_config() -> dict[str, Any]:
    with CONFIG_PATH.open() as f:
        return yaml.safe_load(f)


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _config_hash() -> str:
    return _sha256_file(CONFIG_PATH)


def _git_commit() -> str:
    try:
        import subprocess

        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return ""


def _git_dirty() -> bool:
    """True if the working tree has uncommitted changes at the time of the call."""
    try:
        import subprocess

        out = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return bool(out.strip())
    except Exception:
        return False


def _package_versions() -> dict[str, str]:
    import importlib

    names = ["numpy", "scipy", "scikit-learn", "ijson", "requests", "pyyaml"]
    out: dict[str, str] = {}
    for n in names:
        try:
            mod_name = {"scikit-learn": "sklearn", "pyyaml": "yaml"}.get(n, n)
            mod = importlib.import_module(mod_name)
            out[n] = getattr(mod, "__version__", "unknown")
        except Exception:
            out[n] = "missing"
    return out


# ---------------------------------------------------------------------------
# Fetch.


def _download_to_file(url: str, path: Path, timeout: int = 600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        with tmp.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                if chunk:
                    f.write(chunk)
    tmp.rename(path)


def _is_valid_gzip(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as f:
            f.read(64)
        return True
    except Exception:
        return False


def _is_valid_xz(path: Path) -> bool:
    try:
        with lzma.open(path, "rb") as f:
            f.read(64)
        return True
    except Exception:
        return False


def fetch_raw(cfg: dict[str, Any]) -> tuple[str, dict[int, Path]]:
    """Download yearly feeds. Try official first; on any failure, use mirror.

    Returns (source, {year: path}).
    """
    raw_dir = REPO_ROOT / cfg["raw_dir"]
    refresh = os.environ.get("REFRESH") == "1"
    years = cfg["years"]

    # --- Official attempt ---
    official_dir = raw_dir / "official"
    official_paths: dict[int, Path] = {}
    official_ok = True
    official_err = ""
    for year in years:
        url = cfg["official_url"].format(year=year)
        path = official_dir / f"nvdcve-2.0-{year}.json.gz"
        try:
            if refresh or not path.exists():
                print(f"[fetch] official: {url}")
                _download_to_file(url, path)
            if not _is_valid_gzip(path):
                raise RuntimeError(f"{path} is not a valid gzip")
            official_paths[year] = path
        except Exception as e:  # noqa: BLE001
            official_ok = False
            official_err = f"{year}: {e}"
            print(f"[fetch] official failed for {year}: {e}")
            break

    if official_ok:
        return "official", official_paths

    # --- Mirror fallback for all years ---
    print(f"[fetch] falling back to mirror because official failed ({official_err})")
    mirror_dir = raw_dir / "mirror"
    mirror_paths: dict[int, Path] = {}
    for year in years:
        url = cfg["mirror_url"].format(year=year)
        path = mirror_dir / f"CVE-{year}.json.xz"
        if refresh or not path.exists():
            print(f"[fetch] mirror: {url}")
            _download_to_file(url, path)
        if not _is_valid_xz(path):
            raise RuntimeError(f"{path} is not a valid xz archive")
        mirror_paths[year] = path
    return "mirror", mirror_paths


def _record_url(cfg: dict[str, Any], source: str, year: int) -> str:
    key = "official_url" if source == "official" else "mirror_url"
    return cfg[key].format(year=year)


def _file_info(path: Path, url: str) -> dict[str, Any]:
    return {
        "url": url,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
        "downloaded_utc": datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }


# ---------------------------------------------------------------------------
# Stream-parse yearly feeds.


def iter_records(source: str, path: Path) -> Iterator[dict[str, Any]]:
    """Yield raw CVE dicts from a yearly feed, regardless of source wrapping."""
    opener = gzip.open if source == "official" else lzma.open
    with opener(path, "rb") as f:
        if source == "official":
            for item in ijson.items(f, "vulnerabilities.item"):
                yield item["cve"]
        else:
            for item in ijson.items(f, "cve_items.item"):
                yield item


# ---------------------------------------------------------------------------
# Field extraction.


def _english_description(cve: dict[str, Any]) -> str | None:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            v = d.get("value")
            if isinstance(v, str) and v.strip():
                return v
    return None


_CWE_RE = re.compile(r"^CWE-\d+$")


def _analyst_values(cve: dict[str, Any], source: str) -> list[str]:
    """All description values from weaknesses entries whose source matches."""
    out: list[str] = []
    for w in cve.get("weaknesses") or []:
        if w.get("source") != source:
            continue
        for d in w.get("description") or []:
            v = d.get("value")
            if isinstance(v, str) and v:
                out.append(v)
    return out


def _cwe_ids_for_source(cve: dict[str, Any], source: str) -> list[str]:
    """Distinct CWE-* values (sorted) from weaknesses entries of a given source."""
    vals = {v for v in _analyst_values(cve, source) if _CWE_RE.match(v)}
    return sorted(vals)


# ---------------------------------------------------------------------------
# Normalisation for dedup.

_NORM_CVE = re.compile(r"cve-\d{4}-\d{4,}", re.IGNORECASE)
_NORM_HEX = re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b", re.IGNORECASE)
_NORM_VER = re.compile(r"\bv?\d+(?:\.\d+){1,}[a-z0-9._-]*", re.IGNORECASE)
_NORM_NUM = re.compile(r"\d+")
_NORM_WS = re.compile(r"\s+")


def normalise(text: str) -> str:
    """Normalise for duplicate comparison. Never used as model input."""
    s = text.lower()
    s = _NORM_CVE.sub(" <cve> ", s)
    s = _NORM_HEX.sub(" <hex> ", s)
    s = _NORM_VER.sub(" <ver> ", s)
    s = _NORM_NUM.sub(" <num> ", s)
    s = _NORM_WS.sub(" ", s).strip()
    return s


# ---------------------------------------------------------------------------
# Rule 1 + pre-rule-2 coverage counts.


def _year_of(published: str) -> str:
    return published[:4]


def _in_test_window(published: str, cfg: dict[str, Any]) -> bool:
    return published[:10] >= cfg["test_start"]


def _coverage_bucket_init() -> dict[str, int]:
    return {
        "records": 0,
        "has_nvd_analyst_cwe": 0,
        "has_cna_cwe": 0,
        "has_adp_cwe": 0,
        "has_none": 0,
        "none_and_kernel": 0,
    }


def collect(
    source: str, paths: dict[int, Path], cfg: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, dict[str, int]]]:
    """Apply rule 1 and rule 2. Also build the pre-rule-2 coverage table.

    Returns (kept_records, funnel_counts, coverage_table).
    """
    funnel = Counter()
    coverage: dict[str, dict[str, int]] = defaultdict(_coverage_bucket_init)
    kept: list[dict[str, Any]] = []
    earliest = cfg["earliest_published"]
    nvd_src = cfg["nvd_source"]
    adp_src = cfg["adp_source"]
    kernel_src = cfg["kernel_source"]
    placeholders = set(cfg["placeholder_labels"])

    for year in sorted(paths):
        path = paths[year]
        print(f"[parse] {year}: {path.name}")
        n_in = 0
        for cve in iter_records(source, path):
            n_in += 1
            funnel["rule_1_input"] += 1

            # Rule 1a: drop Rejected.
            if cve.get("vulnStatus") == "Rejected":
                funnel["rule_1_dropped_rejected"] += 1
                continue
            # Rule 1b: drop no English description.
            desc = _english_description(cve)
            if desc is None:
                funnel["rule_1_dropped_no_english"] += 1
                continue
            # Rule 1c: drop before earliest_published.
            published = cve.get("published") or ""
            if not isinstance(published, str) or len(published) < 10:
                funnel["rule_1_dropped_no_date"] += 1
                continue
            if published[:10] < earliest:
                funnel["rule_1_dropped_before_cutoff"] += 1
                continue
            funnel["rule_1_kept"] += 1

            source_identifier = cve.get("sourceIdentifier") or ""

            # Pre-rule-2 coverage (by publication year and for the test window).
            nvd_vals = _analyst_values(cve, nvd_src)
            nvd_cwe_values = [v for v in nvd_vals if _CWE_RE.match(v)]
            has_nvd_analyst = bool(nvd_cwe_values)
            cna_cwes = _cwe_ids_for_source(cve, source_identifier)
            adp_cwes = _cwe_ids_for_source(cve, adp_src)
            has_cna = bool(cna_cwes)
            has_adp = bool(adp_cwes)
            is_kernel = source_identifier == kernel_src

            bucket_keys = [_year_of(published)]
            if _in_test_window(published, cfg):
                bucket_keys.append("test_window")
            for bucket_key in bucket_keys:
                b = coverage[bucket_key]
                b["records"] += 1
                if has_nvd_analyst:
                    b["has_nvd_analyst_cwe"] += 1
                if has_cna:
                    b["has_cna_cwe"] += 1
                if has_adp:
                    b["has_adp_cwe"] += 1
                if not (has_nvd_analyst or has_cna or has_adp):
                    b["has_none"] += 1
                    if is_kernel:
                        b["none_and_kernel"] += 1

            # Rule 2: NVD analyst label.
            if not nvd_vals:
                funnel["rule_2_dropped_no_label"] += 1
                continue
            distinct_nvd = set(nvd_vals)
            if distinct_nvd & placeholders:
                funnel["rule_2_dropped_placeholder"] += 1
                continue
            distinct_cwes = {v for v in distinct_nvd if _CWE_RE.match(v)}
            if len(distinct_cwes) == 0:
                # Non-placeholder non-CWE values (e.g. garbage). Count as no label.
                funnel["rule_2_dropped_no_label"] += 1
                continue
            if len(distinct_cwes) > 1:
                funnel["rule_2_dropped_multi_label"] += 1
                continue
            label = distinct_cwes.pop()
            funnel["rule_2_kept"] += 1

            kept.append(
                {
                    "cve_id": cve.get("id"),
                    "published": published,
                    "source_identifier": source_identifier,
                    "description": desc,
                    "label": label,
                    "is_kernel": is_kernel,
                    "cna_cwes": cna_cwes,
                    "adp_cwes": adp_cwes,
                }
            )
        print(f"[parse] {year}: {n_in} records read")
    return kept, dict(funnel), dict(coverage)


# ---------------------------------------------------------------------------
# Rule 3-6: split, label set, dedup, cap.


def split_by_date(
    records: list[dict[str, Any]], cfg: dict[str, Any]
) -> tuple[list, list, list]:
    train, dev, test = [], [], []
    train_end = cfg["train_end"]
    test_start = cfg["test_start"]
    for r in records:
        d = r["published"][:10]
        if d < train_end:
            train.append(r)
        elif d < test_start:
            dev.append(r)
        else:
            test.append(r)
    return train, dev, test


def pick_label_set(train: list[dict[str, Any]], cfg: dict[str, Any]) -> list[str]:
    counts = Counter(r["label"] for r in train)
    return sorted([lbl for lbl, c in counts.items() if c >= cfg["min_train_class_count"]])


def filter_to_label_set(split: list[dict[str, Any]], labels: set[str]) -> list[dict[str, Any]]:
    return [r for r in split if r["label"] in labels]


def dedup(
    train: list[dict[str, Any]],
    dev: list[dict[str, Any]],
    test: list[dict[str, Any]],
) -> tuple[list, list, list, dict[str, int]]:
    """Apply rule 5 duplicate rules. Returns (train, dev, test, counts)."""
    # Normalise once per record.
    def norm_all(xs: list[dict[str, Any]]) -> None:
        for r in xs:
            r["_norm"] = normalise(r["description"])

    norm_all(train)
    norm_all(dev)
    norm_all(test)

    test_norms = {r["_norm"] for r in test}
    dev_before = len(dev)
    dev = [r for r in dev if r["_norm"] not in test_norms]
    dev_dropped = dev_before - len(dev)

    dev_norms = {r["_norm"] for r in dev}
    forbidden = dev_norms | test_norms
    train_before = len(train)
    train = [r for r in train if r["_norm"] not in forbidden]
    train_dropped_cross = train_before - len(train)

    # Within-train conflicts (before dedup within train).
    label_sets: dict[str, set[str]] = defaultdict(set)
    for r in train:
        label_sets[r["_norm"]].add(r["label"])
    conflict_count = sum(1 for lbls in label_sets.values() if len(lbls) > 1)

    # Keep most recent per normalised text (stable).
    train_sorted = sorted(train, key=lambda r: r["published"], reverse=True)
    seen: set[str] = set()
    train_dedup: list[dict[str, Any]] = []
    for r in train_sorted:
        if r["_norm"] in seen:
            continue
        seen.add(r["_norm"])
        train_dedup.append(r)
    train_within_dropped = len(train) - len(train_dedup)

    counts = {
        "rule_5_dev_dropped_equals_test": dev_dropped,
        "rule_5_train_dropped_equals_dev_or_test": train_dropped_cross,
        "rule_5_train_within_dropped": train_within_dropped,
        "rule_5_train_conflicting_labels": conflict_count,
    }
    return train_dedup, dev, test, counts


def cap_train(train: list[dict[str, Any]], cap: int) -> tuple[list[dict[str, Any]], int]:
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in train:
        by_class[r["label"]].append(r)
    kept: list[dict[str, Any]] = []
    for _lbl, rows in by_class.items():
        rows.sort(key=lambda r: r["published"], reverse=True)
        kept.extend(rows[:cap])
    dropped = len(train) - len(kept)
    return kept, dropped


# ---------------------------------------------------------------------------
# Labels catalogue (MITRE CWE XML).


def fetch_cwe_names(cfg: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    """Download CWE catalogue zip, parse ID->name. Return map and raw-file info."""
    raw_dir = REPO_ROOT / cfg["raw_dir"] / "cwe"
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / "cwec_latest.xml.zip"
    refresh = os.environ.get("REFRESH") == "1"
    url = cfg["cwe_download_url"]
    if refresh or not path.exists():
        print(f"[fetch] cwe: {url}")
        _download_to_file(url, path)

    names: dict[str, str] = {}
    with zipfile.ZipFile(path) as z:
        xml_name = next(n for n in z.namelist() if n.endswith(".xml"))
        with z.open(xml_name) as f:
            tree = ElementTree.parse(f)
    root = tree.getroot()
    for elem in root.iter():
        if elem.tag.endswith("}Weakness") or elem.tag == "Weakness":
            cid = elem.get("ID")
            name = elem.get("Name")
            if cid and name:
                names[f"CWE-{cid}"] = name
    info = _file_info(path, url)
    return names, info


# ---------------------------------------------------------------------------
# Near-duplicate TF-IDF share.


def near_duplicate_share(
    train: list[dict[str, Any]],
    test: list[dict[str, Any]],
    thresholds: list[float],
) -> dict[str, float]:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import normalize

    if not test or not train:
        return {str(t): 0.0 for t in thresholds}
    texts = [r["description"][:2000] for r in train] + [r["description"][:2000] for r in test]
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000)
    X = vec.fit_transform(texts)
    X = normalize(X, norm="l2", axis=1, copy=False)
    n_train = len(train)
    X_train = X[:n_train]
    X_test = X[n_train:]
    # Batched max cosine per test record.
    max_sim = np.zeros(X_test.shape[0], dtype=np.float32)
    batch = 1024
    for i in range(0, X_test.shape[0], batch):
        chunk = X_test[i : i + batch]
        sims = chunk @ X_train.T
        # sparse -> dense max per row
        dense = sims.toarray() if hasattr(sims, "toarray") else sims
        max_sim[i : i + batch] = dense.max(axis=1) if dense.size else 0.0
    total = len(test)
    out: dict[str, float] = {}
    for t in thresholds:
        out[f"share_ge_{t:.2f}".replace(".", "_")] = float((max_sim >= t).sum() / total)
    return out


# ---------------------------------------------------------------------------
# Stats computation.


def _desc_length_percentiles(records: list[dict[str, Any]]) -> dict[str, int]:
    if not records:
        return {"p50": 0, "p90": 0, "p95": 0, "p99": 0, "max": 0}
    lens = np.array([len(r["description"]) for r in records])
    return {
        "p50": int(np.percentile(lens, 50)),
        "p90": int(np.percentile(lens, 90)),
        "p95": int(np.percentile(lens, 95)),
        "p99": int(np.percentile(lens, 99)),
        "max": int(lens.max()),
    }


def _list_agree(label: str, cwes: list[str]) -> bool:
    return bool(cwes) and cwes == [label]


def _split_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {
            "rows": 0,
            "date_range": [None, None],
            "rows_per_class": {},
            "kernel_share": 0.0,
            "desc_length": {"p50": 0, "p90": 0, "p95": 0, "p99": 0, "max": 0},
            "cna_nonempty_share": 0.0,
            "cna_agree_share": 0.0,
            "adp_nonempty_share": 0.0,
            "adp_agree_share": 0.0,
        }
    dates = sorted(r["published"][:10] for r in records)
    rows_per_class = dict(sorted(Counter(r["label"] for r in records).items()))
    kernel = sum(1 for r in records if r["is_kernel"]) / len(records)
    cna_nonempty = [r for r in records if r["cna_cwes"]]
    adp_nonempty = [r for r in records if r["adp_cwes"]]
    cna_agree = sum(1 for r in cna_nonempty if _list_agree(r["label"], r["cna_cwes"]))
    adp_agree = sum(1 for r in adp_nonempty if _list_agree(r["label"], r["adp_cwes"]))
    return {
        "rows": len(records),
        "date_range": [dates[0], dates[-1]],
        "rows_per_class": rows_per_class,
        "kernel_share": round(kernel, 6),
        "desc_length": _desc_length_percentiles(records),
        "cna_nonempty_share": round(len(cna_nonempty) / len(records), 6),
        "cna_agree_share": round(cna_agree / len(cna_nonempty), 6) if cna_nonempty else 0.0,
        "adp_nonempty_share": round(len(adp_nonempty) / len(records), 6),
        "adp_agree_share": round(adp_agree / len(adp_nonempty), 6) if adp_nonempty else 0.0,
    }


def _coverage_table(raw_coverage: dict[str, dict[str, int]], years: list[int]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    keys_in_order = [str(y) for y in years] + ["test_window"]
    for key in keys_in_order:
        b = raw_coverage.get(key, _coverage_bucket_init())
        n = b["records"]
        out[key] = {
            "records": n,
            "nvd_analyst_cwe_share": round(b["has_nvd_analyst_cwe"] / n, 6) if n else 0.0,
            "cna_cwe_share": round(b["has_cna_cwe"] / n, 6) if n else 0.0,
            "adp_cwe_share": round(b["has_adp_cwe"] / n, 6) if n else 0.0,
            "none_share": round(b["has_none"] / n, 6) if n else 0.0,
            "none_kernel_share": round(b["none_and_kernel"] / b["has_none"], 6)
            if b["has_none"]
            else 0.0,
        }
    return out


# ---------------------------------------------------------------------------
# Writing processed files, deterministically.


def _dump_jsonl_bytes(records: list[dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    for r in records:
        # Keep the key order from the design.
        row = {
            "cve_id": r["cve_id"],
            "published": r["published"],
            "source_identifier": r["source_identifier"],
            "description": r["description"],
            "label": r["label"],
            "is_kernel": r["is_kernel"],
            "cna_cwes": r["cna_cwes"],
            "adp_cwes": r["adp_cwes"],
        }
        buf.write(json.dumps(row, ensure_ascii=False))
        buf.write("\n")
    return buf.getvalue().encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
    tmp.replace(path)


def _write_gzip_mtime_zero(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as fout:
        with gzip.GzipFile(filename="", fileobj=fout, mode="wb", mtime=0) as gz:
            gz.write(data)
    tmp.replace(path)


def _sort_split(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records, key=lambda r: (r["published"], r["cve_id"]))


def enforce_lock(new_test_bytes: bytes, test_path: Path) -> None:
    """After first successful build, refuse to overwrite test.jsonl with different content."""
    if not test_path.exists():
        return
    current = test_path.read_bytes()
    if current == new_test_bytes:
        return
    if os.environ.get("RELOCK") == "1":
        print("[lock] RELOCK=1 set; overwriting test.jsonl")
        return
    new_sha = _sha256_bytes(new_test_bytes)
    cur_sha = _sha256_bytes(current)
    sys.stderr.write(
        "lock violation: a rebuild would change data/processed/test.jsonl.\n"
        f"  current sha256={cur_sha}\n  new     sha256={new_sha}\n"
        "Set RELOCK=1 to intentionally relock the test set.\n"
    )
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Dataset card renderer (kept here so no new file is added).


def _class_table_md(stats: dict, labels: list[dict]) -> str:
    name_by_id = {lbl["id"]: lbl["name"] for lbl in labels}
    train_rows = stats["splits"]["train"]["rows_per_class"]
    dev_rows = stats["splits"]["dev"]["rows_per_class"]
    test_rows = stats["splits"]["test"]["rows_per_class"]
    ids = sorted(set(train_rows) | set(dev_rows) | set(test_rows))
    lines = ["| CWE | name | train | dev | test |", "|---|---|---:|---:|---:|"]
    for cid in ids:
        lines.append(
            f"| {cid} | {name_by_id.get(cid, '')} | {train_rows.get(cid, 0)} "
            f"| {dev_rows.get(cid, 0)} | {test_rows.get(cid, 0)} |"
        )
    return "\n".join(lines)


def _coverage_table_md(stats: dict) -> str:
    cov = stats["coverage_pre_rule_2"]
    lines = [
        "| bucket | records | NVD analyst CWE | CNA CWE | CISA ADP CWE | none | none & kernel |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for key, b in cov.items():
        lines.append(
            f"| {key} | {b['records']} | {b['nvd_analyst_cwe_share']:.3f} "
            f"| {b['cna_cwe_share']:.3f} | {b['adp_cwe_share']:.3f} "
            f"| {b['none_share']:.3f} | {b['none_kernel_share']:.3f} |"
        )
    return "\n".join(lines)


def _split_summary_md(stats: dict) -> str:
    lines = [
        "| split | rows | date range | kernel share | desc p50 | p90 | p95 | p99 | max |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|",
    ]
    for split in ("train", "dev", "test"):
        s = stats["splits"][split]
        dr = s["date_range"]
        dl = s["desc_length"]
        lines.append(
            f"| {split} | {s['rows']} | {dr[0]} to {dr[1]} | {s['kernel_share']:.3f} "
            f"| {dl['p50']} | {dl['p90']} | {dl['p95']} | {dl['p99']} | {dl['max']} |"
        )
    return "\n".join(lines)


def _agreement_table_md(stats: dict) -> str:
    lines = [
        "| split | CNA nonempty | CNA agree | CISA ADP nonempty | CISA ADP agree |",
        "|---|---:|---:|---:|---:|",
    ]
    for split in ("train", "dev", "test"):
        s = stats["splits"][split]
        lines.append(
            f"| {split} | {s['cna_nonempty_share']:.3f} | {s['cna_agree_share']:.3f} "
            f"| {s['adp_nonempty_share']:.3f} | {s['adp_agree_share']:.3f} |"
        )
    return "\n".join(lines)


def _funnel_block_md(stats: dict) -> str:
    funnel = _ordered_funnel(stats["funnel"])
    lines = ["| step | count |", "|---|---:|"]
    for k, v in funnel.items():
        lines.append(f"| {k} | {v} |")
    return "\n".join(lines)


def _format_threshold(key: str) -> str:
    # Keys look like "share_ge_0_80" meaning threshold 0.80. Render as "0.80".
    body = key.removeprefix("share_ge_").replace("_", ".")
    try:
        return f"{float(body):.2f}"
    except ValueError:
        return key


def _near_dup_block_md(stats: dict) -> str:
    nd = stats["near_duplicate_test_to_train"]
    lines = ["| threshold | share |", "|---|---:|"]
    for k, v in nd.items():
        lines.append(f"| {_format_threshold(k)} | {v:.4f} |")
    return "\n".join(lines)


def _render_dataset_card(
    stats: dict, manifest: dict, labels: list[dict], out_path: Path
) -> None:
    md = f"""# Dataset card: cve2cwe

Generated from `data/processed/stats.json` and `data/processed/MANIFEST.json`.
Do not hand-edit numbers. Rebuild with `make data`.

## Source and licence

- Feeds: NVD JSON 2.0 yearly feeds for CVE-2021 to CVE-2026.
- Source actually used for this build: **{manifest["source"]}**.
- CWE catalogue: `{manifest["cwe_catalogue"]["url"]}`
  (sha256 `{manifest["cwe_catalogue"]["sha256"]}`).
- Licences: see `data/NOTICE.md`.

## Label definition

- One CWE id per record, taken from NVD analyst weaknesses entries
  (`source == "nvd@nist.gov"`).
- Records with no analyst CWE, or any placeholder (`NVD-CWE-Other`,
  `NVD-CWE-noinfo`), or more than one distinct CWE, are dropped.
- Label set: CWEs with at least `min_train_class_count` records in the train
  window (see `configs/data.yaml`).

## Cleaning funnel

{_funnel_block_md(stats)}

Rule 4 coverage (kept records over single-label records in that split):
- train: {stats["rule_4_coverage"]["train"]:.4f}
- dev:   {stats["rule_4_coverage"]["dev"]:.4f}
- test:  {stats["rule_4_coverage"]["test"]:.4f}

## Split logic

- Dates compared on the first 10 characters of `published`.
- train: published < train_end (config).
- dev:   train_end <= published < test_start.
- test:  published >= test_start.

{_split_summary_md(stats)}

## Second-source agreement

Share of records where the CNA or CISA ADP labelled it, and share of those
where their label equals the NVD analyst label. These fields are analysis-only
and never reach a model prompt.

{_agreement_table_md(stats)}

## Coverage over all non-rejected records (before rule 2)

Per publication year and for the test window.

{_coverage_table_md(stats)}

## Near-duplicate test-to-train (TF-IDF cosine)

{_near_dup_block_md(stats)}

## Class table

{_class_table_md(stats, labels)}

## Known biases

- Since 2026-04-15 NIST enriches only a priority subset of CVEs, so analyst
  labels in the test window are not a random sample.
- NVD analyst labels are noisy; see the agreement table above.
- The Linux kernel CNA (`is_kernel`) makes up a large share of records with no
  analyst, CNA or CISA ADP CWE in recent windows.

## How to rebuild

```
make data             # rebuild from raw; lock is enforced on test.jsonl
REFRESH=1 make data   # re-download raw files
RELOCK=1 make data    # allow a new test.jsonl to be written
```
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main entry.


def main() -> int:
    t0 = time.time()
    cfg = _load_config()
    processed = REPO_ROOT / cfg["processed_dir"]
    processed.mkdir(parents=True, exist_ok=True)

    start_utc = _utc_now_iso()
    # Read git state at the start of the run so git_dirty reflects the tree
    # before this run writes anything, not after.
    git_commit = _git_commit()
    git_dirty = _git_dirty()

    # 1. Fetch.
    source, raw_paths = fetch_raw(cfg)

    # 2. Rule 1 + rule 2.
    records, funnel, raw_coverage = collect(source, raw_paths, cfg)

    # 3. Split (rule 3).
    train, dev, test = split_by_date(records, cfg)
    funnel["rule_3_split_train"] = len(train)
    funnel["rule_3_split_dev"] = len(dev)
    funnel["rule_3_split_test"] = len(test)

    # 4. Label set (rule 4).
    labels_list = pick_label_set(train, cfg)
    labels_set = set(labels_list)
    train_before = {"train": len(train), "dev": len(dev), "test": len(test)}
    train = filter_to_label_set(train, labels_set)
    dev = filter_to_label_set(dev, labels_set)
    test = filter_to_label_set(test, labels_set)
    funnel["label_set_size"] = len(labels_list)
    funnel["rule_4_train_kept"] = len(train)
    funnel["rule_4_dev_kept"] = len(dev)
    funnel["rule_4_test_kept"] = len(test)
    coverage_rule_4 = {
        "train": round(len(train) / train_before["train"], 6) if train_before["train"] else 0.0,
        "dev": round(len(dev) / train_before["dev"], 6) if train_before["dev"] else 0.0,
        "test": round(len(test) / train_before["test"], 6) if train_before["test"] else 0.0,
    }

    # 5. Dedup (rule 5).
    train, dev, test, dedup_counts = dedup(train, dev, test)
    funnel.update(dedup_counts)

    # 6. Cap (rule 6).
    train, cap_dropped = cap_train(train, cfg["train_per_class_cap"])
    funnel["rule_6_train_dropped"] = cap_dropped
    funnel["final_train"] = len(train)
    funnel["final_dev"] = len(dev)
    funnel["final_test"] = len(test)

    # Strip internal fields.
    for r in train + dev + test:
        r.pop("_norm", None)

    # Sort deterministically.
    train = _sort_split(train)
    dev = _sort_split(dev)
    test = _sort_split(test)

    # Print funnel.
    print("\n=== funnel ===")
    for k, v in _ordered_funnel(funnel).items():
        print(f"{k}: {v}")
    print("rule_4_coverage:", coverage_rule_4)
    print()

    # 7. Labels catalogue.
    cwe_names, cwe_file_info = fetch_cwe_names(cfg)
    labels_payload = [{"id": lid, "name": cwe_names.get(lid, "")} for lid in labels_list]
    missing_names = [lid for lid in labels_list if not cwe_names.get(lid)]
    if missing_names:
        print(f"[warn] CWE names missing for: {missing_names}")

    # 8. Serialise.
    train_bytes = _dump_jsonl_bytes(train)
    dev_bytes = _dump_jsonl_bytes(dev)
    test_bytes = _dump_jsonl_bytes(test)

    # 9. Lock enforcement for test.jsonl.
    test_path = processed / "test.jsonl"
    enforce_lock(test_bytes, test_path)

    # 10. Near-duplicate share (before writing so stats include it).
    near_dup = near_duplicate_share(train, test, cfg["near_duplicate_thresholds"])

    # 11. Write processed files.
    train_gz = processed / "train.jsonl.gz"
    dev_path = processed / "dev.jsonl"
    labels_path = processed / "labels.json"
    stats_path = processed / "stats.json"
    manifest_path = processed / "MANIFEST.json"

    _write_gzip_mtime_zero(train_gz, train_bytes)
    _write_bytes(dev_path, dev_bytes)
    _write_bytes(test_path, test_bytes)
    _write_bytes(
        labels_path, (json.dumps(labels_payload, ensure_ascii=False, indent=2) + "\n").encode()
    )

    # 12. Stats.
    stats: dict[str, Any] = {
        "funnel": _ordered_funnel(funnel),
        "rule_4_coverage": coverage_rule_4,
        "splits": {
            "train": _split_stats(train),
            "dev": _split_stats(dev),
            "test": _split_stats(test),
        },
        "coverage_pre_rule_2": _coverage_table(raw_coverage, cfg["years"]),
        "near_duplicate_test_to_train": near_dup,
    }
    stats_bytes = (json.dumps(stats, ensure_ascii=False, indent=2) + "\n").encode()
    _write_bytes(stats_path, stats_bytes)

    # 13. Manifest.
    manifest: dict[str, Any] = {
        "source": source,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "config_sha256": _config_hash(),
        "package_versions": _package_versions(),
        "created_utc": start_utc,
        "finished_utc": _utc_now_iso(),
        "raw": {
            f"CVE-{year}": _file_info(raw_paths[year], _record_url(cfg, source, year))
            for year in sorted(raw_paths)
        },
        "cwe_catalogue": cwe_file_info,
        "processed": {
            "train.jsonl.gz": {"sha256": _sha256_file(train_gz), "rows": len(train)},
            "dev.jsonl": {"sha256": _sha256_file(dev_path), "rows": len(dev)},
            "test.jsonl": {"sha256": _sha256_file(test_path), "rows": len(test)},
            "labels.json": {"sha256": _sha256_file(labels_path), "rows": len(labels_payload)},
            "stats.json": {"sha256": _sha256_file(stats_path)},
        },
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    _write_bytes(manifest_path, manifest_bytes)

    # 14. Dataset card (rendered from stats and manifest; no hand-typed numbers).
    _render_dataset_card(stats, manifest, labels_payload, REPO_ROOT / "data" / "DATASET_CARD.md")

    # 15. Leakage checks.
    from cve2cwe import leakage

    leakage.run_all(train, dev, test, labels_payload, test_path, manifest, cfg)

    dt = time.time() - t0
    print(f"\n[done] data stage finished in {dt:.1f}s")
    print(
        f"splits: train={len(train)} dev={len(dev)} test={len(test)} labels={len(labels_list)}"
    )
    return 0
