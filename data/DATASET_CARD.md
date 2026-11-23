# Dataset card: cve2cwe

Generated from `data/processed/stats.json` and `data/processed/MANIFEST.json`.
Do not hand-edit numbers. Rebuild with `make data`.

## Source and licence

- Feeds: NVD JSON 2.0 yearly feeds for CVE-2021 to CVE-2026.
- Source actually used for this build: **official**.
- CWE catalogue: `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`
  (sha256 `bcda44c9abf61ff977f50c3c6649eea5a97a7b0626b0396c2c3ec4bfb973a3dc`).
- Licences: see `data/NOTICE.md`.

## Label definition

- One CWE id per record, taken from NVD analyst weaknesses entries
  (`source == "nvd@nist.gov"`).
- Records with no analyst CWE, or any placeholder (`NVD-CWE-Other`,
  `NVD-CWE-noinfo`), or more than one distinct CWE, are dropped.
- Label set: CWEs with at least `min_train_class_count` records in the train
  window (see `configs/data.yaml`).

## Cleaning funnel

| step | count |
|---|---:|
| final_dev | 2759 |
| final_test | 2266 |
| final_train | 42291 |
| label_set_size | 53 |
| rule_1_dropped_rejected | 6955 |
| rule_1_input | 263668 |
| rule_1_kept | 256713 |
| rule_2_dropped_multi_label | 814 |
| rule_2_dropped_no_label | 165702 |
| rule_2_dropped_placeholder | 23137 |
| rule_2_kept | 67060 |
| rule_3_split_dev | 2907 |
| rule_3_split_test | 2483 |
| rule_3_split_train | 61670 |
| rule_4_dev_kept | 2761 |
| rule_4_test_kept | 2266 |
| rule_4_train_kept | 56005 |
| rule_5_dev_dropped_equals_test | 2 |
| rule_5_train_conflicting_labels | 149 |
| rule_5_train_dropped_equals_dev_or_test | 48 |
| rule_5_train_within_dropped | 3574 |
| rule_6_train_dropped | 10092 |

Rule 4 coverage (kept records over single-label records in that split):
- train: 0.9081
- dev:   0.9498
- test:  0.9126

## Split logic

- Dates compared on the first 10 characters of `published`.
- train: published < train_end (config).
- dev:   train_end <= published < test_start.
- test:  published >= test_start.

| split | rows | date range | kernel share | desc p50 | p90 | p95 | p99 | max |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| train | 42291 | 2021-01-04 to 2025-09-29 | 0.120 | 278 | 685 | 1176 | 3487 | 3998 |
| dev | 2759 | 2025-10-01 to 2026-04-14 | 0.254 | 370 | 1156 | 2015 | 3998 | 3998 |
| test | 2266 | 2026-04-15 to 2026-11-18 | 0.717 | 694 | 1904 | 2569 | 3998 | 3998 |

## Second-source agreement

Share of records where the CNA or CISA ADP labelled it, and share of those
where their label equals the NVD analyst label. These fields are analysis-only
and never reach a model prompt.

| split | CNA nonempty | CNA agree | CISA ADP nonempty | CISA ADP agree |
|---|---:|---:|---:|---:|
| train | 0.436 | 0.570 | 0.196 | 0.919 |
| dev | 0.597 | 0.023 | 0.147 | 0.679 |
| test | 0.093 | 0.085 | 0.347 | 0.595 |

## Coverage over all non-rejected records (before rule 2)

Per publication year and for the test window.

| bucket | records | NVD analyst CWE | CNA CWE | CISA ADP CWE | none | none & kernel |
|---|---:|---:|---:|---:|---:|---:|
| 2021 | 16203 | 0.671 | 0.380 | 0.015 | 0.165 | 0.000 |
| 2022 | 24207 | 0.687 | 0.410 | 0.155 | 0.119 | 0.000 |
| 2023 | 27859 | 0.546 | 0.570 | 0.193 | 0.082 | 0.000 |
| 2024 | 39608 | 0.339 | 0.643 | 0.231 | 0.051 | 0.546 |
| 2025 | 47720 | 0.160 | 0.720 | 0.165 | 0.066 | 0.852 |
| 2026 | 101116 | 0.041 | 0.754 | 0.168 | 0.065 | 0.918 |
| test_window | 83820 | 0.030 | 0.737 | 0.177 | 0.074 | 0.938 |

## Near-duplicate test-to-train (TF-IDF cosine)

| threshold | share |
|---|---:|
| share_ge_0_80 | 0.0163 |
| share_ge_0_90 | 0.0035 |

## Class table

| CWE | name | train | dev | test |
|---|---|---:|---:|---:|
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | 429 | 2 | 7 |
| CWE-120 | Buffer Copy without Checking Size of Input | 1283 | 49 | 7 |
| CWE-125 | Out-of-bounds Read | 2053 | 109 | 240 |
| CWE-129 | Improper Validation of Array Index | 204 | 11 | 21 |
| CWE-1333 | Inefficient Regular Expression Complexity | 200 | 2 | 0 |
| CWE-190 | Integer Overflow or Wraparound | 670 | 31 | 40 |
| CWE-20 | Improper Input Validation | 908 | 4 | 10 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | 268 | 2 | 10 |
| CWE-203 | Observable Discrepancy | 342 | 5 | 1 |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | 1850 | 60 | 19 |
| CWE-269 | Improper Privilege Management | 455 | 2 | 50 |
| CWE-276 | Incorrect Default Permissions | 461 | 3 | 2 |
| CWE-287 | Improper Authentication | 847 | 1 | 8 |
| CWE-295 | Improper Certificate Validation | 322 | 15 | 9 |
| CWE-306 | Missing Authentication for Critical Functionality | 488 | 19 | 44 |
| CWE-312 | Cleartext Storage of Sensitive Information | 296 | 6 | 2 |
| CWE-319 | Cleartext Transmission of Sensitive Information | 240 | 4 | 1 |
| CWE-352 | Cross-Site Request Forgery | 1564 | 20 | 4 |
| CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization | 631 | 64 | 93 |
| CWE-400 | Uncontrolled Resource Consumption | 393 | 4 | 6 |
| CWE-401 | Missing Release of Memory after Effective Lifetime | 1015 | 154 | 233 |
| CWE-415 | Double Free | 296 | 22 | 67 |
| CWE-416 | Use After Free | 2206 | 153 | 363 |
| CWE-427 | Uncontrolled Search Path Element | 343 | 1 | 1 |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 1187 | 88 | 4 |
| CWE-476 | NULL Pointer Dereference | 2329 | 214 | 331 |
| CWE-502 | Deserialization of Untrusted Data | 506 | 17 | 11 |
| CWE-522 | Insufficiently Protected Credentials | 395 | 15 | 11 |
| CWE-532 | Insertion of Sensitive Information into Log File | 345 | 5 | 2 |
| CWE-59 | Improper Link Resolution Before File Access | 263 | 9 | 7 |
| CWE-601 | URL Redirection to Untrusted Site | 347 | 5 | 4 |
| CWE-611 | Improper Restriction of XML External Entity Reference | 319 | 5 | 0 |
| CWE-617 | Reachable Assertion | 269 | 19 | 25 |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 368 | 27 | 4 |
| CWE-667 | Improper Locking | 476 | 41 | 102 |
| CWE-668 | Exposure of Resource to Wrong Sphere | 374 | 3 | 1 |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | 402 | 4 | 3 |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component | 313 | 2 | 4 |
| CWE-755 | Improper Handling of Exceptional Conditions | 244 | 0 | 1 |
| CWE-77 | Improper Neutralization of Special Elements used in a Command | 879 | 111 | 9 |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 469 | 40 | 14 |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command | 1433 | 78 | 21 |
| CWE-787 | Out-of-bounds Write | 3000 | 371 | 230 |
| CWE-79 | Improper Neutralization of Input During Web Page Generation | 3000 | 240 | 31 |
| CWE-798 | Use of Hard-coded Credentials | 519 | 12 | 4 |
| CWE-835 | Loop with Unreachable Exit Condition | 231 | 16 | 30 |
| CWE-843 | Access of Resource Using Incompatible Type | 158 | 11 | 5 |
| CWE-862 | Missing Authorization | 1437 | 29 | 33 |
| CWE-863 | Incorrect Authorization | 825 | 43 | 65 |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | 3000 | 531 | 5 |
| CWE-908 | Use of Uninitialized Resource | 352 | 29 | 55 |
| CWE-918 | Server-Side Request Forgery | 525 | 15 | 12 |
| CWE-94 | Improper Control of Generation of Code | 562 | 36 | 4 |

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
