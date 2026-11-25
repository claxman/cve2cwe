---
license: apache-2.0
base_model: Qwen/Qwen3.5-4B
---

# cve2cwe-qwen3.5-4b

A LoRA adapter for Qwen/Qwen3.5-4B. It reads the English description of a CVE and answers with one CWE id, the one an NVD analyst would assign, from a fixed list of 53. This repo also holds a 4-bit GGUF of the merged model for local use.

Code, data preparation, evaluation and every run file: https://github.com/claxman/cve2cwe

## What it is for

Suggesting a CWE for CVE records that arrive without one. On 15 April 2026 NIST limited analyst labelling to a priority subset of CVEs, so many new records have no CWE.

## Training data

Public NVD CVE records with a single analyst-assigned CWE, split by publication date.

| Split | Rows | From | To |
|---|---|---|---|
| train | 42,291 | 2021-01-04 | 2025-09-29 |
| dev | 2,759 | 2025-10-01 | 2026-04-14 |
| test | 2,266 | 2026-04-15 | 2026-11-18 |

The test set was locked before training.

## Training

LoRA rank 16 on the full-precision weights with Unsloth, 2 epochs, batch 32, learning rate 2e-4. The loss is on the label and the end token only. Base revision 851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a. This adapter is seed 1 of three.

## Results on the locked test set

| System | Test accuracy |
|---|---|
| This adapter (seed 1) | 75.4% |
| Fine-tuned, mean of 3 seeds | 75.9% |
| TF-IDF + linear SVM | 72.7% |
| Claude Sonnet 5.5 with retrieved examples | 71.6% |
| Base model with retrieved examples | 65.7% |
| Base model zero-shot | 56.6% |

The pass bar was committed before the first test run. Intervals, per-class results, cost and later dev-only ablations are in the GitHub README.

## Limits

- All of the gain over the linear model is on Linux kernel CVEs. On other CVEs it scores 56.1%, against 56.4% for the linear model.
- The labels are noisy. Where CISA also labelled a test record, it agrees with NVD on 59.5%.
- It answers only from the 53 CWE ids it was trained on.
- It is a proof of concept, not a production system.

## Use

```
llama-server -m e2-seed1-merged.Q4_K_M.gguf --reasoning off --port 8080 --temp 0 -c 4096 --alias candidate-e2-seed1
```

`--reasoning off` turns thinking off on llama.cpp 1.0.0.

## Licence and credits

Adapter and GGUF: Apache 2.0, the licence of the base model. Data: NVD (a US government work), CVE descriptions under the CVE Terms of Use, CWE names under MITRE's terms. See data/NOTICE.md in the GitHub repo.
