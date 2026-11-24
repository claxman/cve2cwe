# cve2cwe: design

Written before any code. This is the specification the build follows. If code and this file disagree, either the code is wrong or this file gets a dated entry in the change log at the bottom.

## 1. The decision

Question: should labelling a CVE description with its CWE weakness type move from a frontier model to a small fine-tuned open-weight model?

The repo answers with evidence:

- a test set that is locked and split by publication date
- every cheaper option tried first: rules, a linear model, prompting, retrieval, a frontier model
- a small model fine-tuned three times with different seeds
- an acceptance bar committed before the final evaluation runs
- a gate script that prints PROMOTE or REJECT with the numbers behind it

A second question covers deployment: on what share of items can the small model answer alone, at what precision and cost, with a frontier model as the fallback for the rest?

## 2. Why this task

- A CWE label on a CVE is a standard enrichment field in exposure management. It drives grouping, remediation guidance and reporting.
- NVD analysts used to add it as part of routine analysis. Since 15 April 2026 NIST enriches only a priority subset of CVEs (https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth). CVEs outside that subset can arrive without an analyst CWE.
- The task is narrow, the output is one label and scoring is deterministic.

What is known at design time, stated plainly:

- This repo has produced no numbers yet. The data step measures how many CVEs lack a label and from which sources. See data/DATASET_CARD.md once it exists.
- CVE volume is small by LLM standards. This task alone will not change an AI bill. The repo therefore reports cost per 1,000 items and the volume at which self-hosting breaks even, so the same method can be applied to higher-volume tasks.
- Analyst labels are noisy. Where a second source (CISA ADP) labelled the same CVE, the data step reports how often the two agree. That rate bounds what any system can score.
- Since the policy change, analyst-labelled CVEs are the priority subset and not a random sample. The test set inherits that skew. The dataset card describes it.

Scoping note. Before this design was fixed, a scoping pass over the same public feeds measured label coverage and class counts, and fit one linear baseline on the proposed split to check that the task was neither trivial nor impossible. No number from that pass appears in this repo. The split date comes from the NIST policy date. The class threshold was set from label counts and coverage. Two parameters were informed by the linear baseline: description truncation at 2,000 characters and the per-class train cap of 3,000. No fine-tuned model existed at that point, and none touches the test set before the acceptance bar is committed.

## 3. Task definition

- Input: the English description of one CVE as published in the NVD feeds. Every system uses the first 2,000 characters.
- Output: exactly one CWE id from a fixed label set, for example CWE-416.
- Ground truth: the single CWE assigned by NVD analysts.
- The label set is closed. No abstain label is trained. Section 10 covers low-confidence items.
- A system never sees anything but the description. Other fields in the dataset are for analysis only.

## 4. Data

### 4.1 Source and licence

- NVD JSON 2.0 yearly feeds for CVE-2021 to CVE-2026.
- Official location: https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz. Confirm the link pattern on https://nvd.nist.gov/vuln/data-feeds before coding.
- Fallback if the official download fails: https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz, a community mirror of the same records. Use one source for all years, never a mix. The manifest records which one was used.
- The two sources wrap records differently (official: vulnerabilities[].cve, mirror: cve_items[]). The record fields are the same. Parse as a stream with ijson: the 2026 file is several hundred MB uncompressed.
- Raw files go to data/raw/ (not committed). Downloads are skipped when the file exists unless REFRESH=1.
- Licences: NVD content is a US government work. CVE descriptions are under the CVE Terms of Use, which require MITRE's copyright line and the licence text in any copy. CWE names are under MITRE's CWE terms. data/NOTICE.md carries all three, copied exactly from the official pages.

### 4.2 Record rules

Applied in this order. Every step prints and stores a count.

1. Drop records with vulnStatus "Rejected". Drop records with no English description. Keep published on or after 2021-01-01.
2. NVD analyst label: all values in weaknesses entries whose source is "nvd@nist.gov", any type. Drop the record if there is none, if any value is NVD-CWE-Other or NVD-CWE-noinfo, or if there is more than one distinct CWE. Count each reason separately.
3. Split on the first 10 characters of published: train before 2025-10-01, dev from 2025-10-01 to 2026-04-14, test from 2026-04-15.
4. Label set: CWEs with at least 200 records in the train window at this point. Drop records outside the label set from all three splits. Store coverage per split (kept records over single-label records).
5. Duplicates, compared on normalised text: lowercase; CVE ids, version strings, hex values and digit runs replaced by placeholder tokens; whitespace collapsed. Normalised text is for comparison only and is never model input.
   - Drop dev records whose normalised text equals a test record's.
   - Drop train records whose normalised text equals any dev or test record's.
   - Within train keep the most recent record per normalised text.
   - Never drop anything from test.
   - Also count normalised texts in train that carried conflicting labels before dedup.
6. Cap train at the 3,000 most recent records per class.

Why these choices:

- Date split with the newest records as test: this is how the model would be used, and a random split would let near-identical records sit on both sides.
- Test starts on 2026-04-15: the day the NIST policy took effect. It is also after the base model's release (confirmed from the Hub at Step 5), so the base model cannot have seen test records. That cannot be said for the frontier models.
- Placeholders dropped: NVD-CWE-Other and NVD-CWE-noinfo mean "no usable label", not a weakness type.
- Single label only: scoring stays deterministic.
- Minimum 200 per class: enough to learn and to evaluate a class.
- Cap of 3,000 per class, most recent first: stops two or three classes from dominating and favours current labelling habits.

### 4.3 Outputs (data/processed/, all committed)

- train.jsonl.gz (gzip written with mtime 0), dev.jsonl, test.jsonl. One JSON object per line, sorted by (published, cve_id). Keys: cve_id, published, source_identifier, description (full text, unmodified), label, is_kernel, cna_cwes, adp_cwes.
  - is_kernel: sourceIdentifier equals "416baaa9-dc9f-4396-8d5f-8c081fb06d67", the Linux kernel CNA.
  - cna_cwes: CWE-* values from weaknesses entries whose source equals the record's sourceIdentifier.
  - adp_cwes: the same for source "134c704f-9b21-4f2e-91b3-4a467353bcc0", CISA ADP.
  - cna_cwes and adp_cwes are for analysis only and never reach a prompt.
- labels.json: ordered list of {id, name}. Names come from MITRE's CWE download (https://cwe.mitre.org/data/downloads.html). That file is recorded in the manifest.
- stats.json:
  - the funnel counts from 4.2
  - per split: rows, date range, rows per class, share with is_kernel true, description length in characters (p50, p90, p95, p99, max)
  - per split, for cna_cwes and for adp_cwes: share of records where the list is not empty, and share of those where it equals [label]
  - a coverage table over all non-rejected records before rule 2, for each publication year 2021 to 2026 and for the test window: records, share with an NVD analyst CWE that is not a placeholder, share with a CNA CWE, share with a CISA ADP CWE, share with none of the three, and the share of that last group with is_kernel true
  - share of test records whose nearest train record has TF-IDF cosine similarity of 0.8 or more, and 0.9 or more
- MANIFEST.json: for each raw file the url, UTC download time, bytes and sha256. For each processed file the sha256 and row count. Also the git commit, a git_dirty flag (true if the working tree had uncommitted changes when the run started), a hash of configs/data.yaml and the creation time.

The build is deterministic: a second run on the same raw files produces byte-identical train, dev and test files.

### 4.4 Leakage and lock checks

In src/cve2cwe/leakage.py, called by the data stage and by the tests:

- no cve_id in more than one split
- newest train record is older than the oldest dev record, newest dev record is older than the oldest test record, and the boundaries equal configs/data.yaml
- zero normalised-text overlap between any two splits
- every label is in labels.json and none is a placeholder
- sha256 of test.jsonl equals the manifest. This is the lock: the test fails if test.jsonl changes.
- The lock is enforced on write. After a successful first build, the data stage never overwrites test.jsonl with different content. If a rebuild would change it, the stage exits with an error unless RELOCK=1 is set in the environment.

### 4.5 Dataset card and notice

- data/DATASET_CARD.md is rendered by code from stats.json and MANIFEST.json. No hand-typed numbers. Sections: source and licence, label definition, cleaning funnel, split logic, class table, known biases, how to rebuild.
- data/NOTICE.md: the CVE Terms of Use text and MITRE copyright line from https://www.cve.org/Legal/TermsOfUse, the NVD notice from https://nvd.nist.gov/developers/terms-of-use, the CWE terms from https://cwe.mitre.org/about/termsofuse.html. Copied, not paraphrased.

## 5. Scoring

- Parser: strip whitespace. The output must match `^CWE-[0-9]+$` and be in the label set. Anything else is invalid.
- Invalid counts as wrong in every metric. The invalid rate is also reported on its own.
- Primary metric: accuracy on the split.
- Also reported: macro-F1 over classes with at least 20 records in that split; accuracy for is_kernel true and false; accuracy on three label-noise slices (second source agrees with the label, disagrees, or is absent).
- Uncertainty: 95% bootstrap interval for each accuracy (10,000 resamples, fixed seed). For two systems on the same records, a paired bootstrap interval of the difference.
- The scorer reads prediction files and never calls a model. One scorer for every system.

Prediction files: outputs/{system}/{split}/{run_id}/predictions.jsonl with keys cve_id, raw_output, parsed (or null), confidence (number or null). Next to it run.json: system, split, seed, config, git commit, package versions, model revision, token usage where the API reports it, start and end time.

## 6. Systems compared

1. Majority class from train.
2. Keyword rules: a fixed table of about a dozen phrase patterns, each mapped to one CWE (for example "use after free" to CWE-416). Written once, not tuned. If zero or more than one rule fires the output is invalid.
3. TF-IDF linear: word 1 to 2 grams plus character 3 to 5 grams, linear SVM. Settings in config, any choice made on dev.
4. Base model zero-shot: the system prompt lists the label set with names and asks for the id only.
5. Base model few-shot: one example for each of the eight most frequent train classes, chosen by a written rule (most recent train record of that class under 400 characters).
6. Base model retrieval few-shot: the five most similar train records by TF-IDF cosine similarity, each cut to 600 characters, shown with their labels.
7. Claude Haiku 5.5 and Claude Sonnet 5.5, zero-shot and retrieval few-shot, same prompts. Haiku 5.5 was called with thinking disabled. Sonnet 5.5 does not accept thinking disabled or a temperature. It was called with thinking between_tools, the lowest setting it accepts.
8. The fine-tuned model. This is the candidate.

Rules for prompts: they live in configs/prompts.yaml. They may be revised on dev, never on test. Each revision is a commit.

Champion: the system other than the candidate with the highest accuracy on the locked test set. Picking the best baseline on the test set favours the champion, which is the conservative direction for a gate.

## 7. Fine-tune

- Base model: Qwen/Qwen3.5-4B, Apache 2.0, revision pinned to a commit hash in configs/train.yaml. The release date is read from the Hugging Face Hub API and recorded. The test window starts after it.
- Newer Qwen generations were not used. Qwen3.6 and Qwen3.8 have no open-weight model under 27B, and Qwen3.8-27B was released on 14 August 2026, inside the test window.
- Method: supervised fine-tuning with LoRA on bf16 weights, using Unsloth and PyTorch.
- Not 4-bit QLoRA, for three reasons: a 4B model fits in GPU memory without quantisation; Unsloth's guide for this model family advises against 4-bit (https://unsloth.ai/docs/models/qwen3.5/fine-tune, confirmed at Step 5); and an adapter trained on bf16 weights merges into the same weights it was trained on, so the served checkpoint is the trained model.
- Training text: the exact inference prompt (chat template, thinking disabled) followed by the label and the end-of-turn token. Loss on the label and the end-of-turn token only (the empty think block before the label is masked). A test asserts that the inference prompt is a prefix of the training text.
- The candidate's prompt is a short instruction with no label list.
- Starting values in configs/train.yaml: LoRA rank 16, alpha 16, dropout 0, adapters on the attention and MLP projection layers of the language stack only (0 adapters in the vision tower), learning rate 2e-4 with cosine warmup and decay (5% of total steps), adamw_torch_fused optimiser. per_device_train_batch_size 32, gradient_accumulation_steps 1, length-grouped sampling within shuffled mega-batches (not a global sort). max_seq_length is set to the overall maximum rendered token length rounded up to the next multiple of 64, measured with `python -m cve2cwe train --profile-lengths` after the 2,000-character description cut; training fails before step 1 if any example is longer, because a truncated example loses its label. Changes are made on dev only and each change is a commit.
- Epochs rule, recorded in configs/train.yaml as a comment: a 100-step probe on a random 3,200-row train sample estimates the full-epoch time as probe_time x 42,291 / 3,200. 2 epochs if the estimate is at most 12 minutes, 1 epoch if at most 25 minutes, stop and report if over 25 minutes.
- Two training lengths are compared: 1 epoch and 2 epochs, three seeds each. The first set ran at 1 epoch because a 100-step probe overestimated the epoch time (22.9 minutes estimated, 9.5 measured). The candidate is the length with the higher mean dev accuracy over its three seeds. A tie goes to 1 epoch. Only the chosen length's three checkpoints are evaluated on test.
- Seeds 1, 2 and 3. The seed controls adapter initialisation (`random_state` in FastLanguageModel.get_peft_model) and data order (`seed` and `data_seed` in SFTConfig, which feed the LengthGroupedSampler). Decoding is greedy. A repeat of the first 300 records found that 3 outputs differed between two identical runs at 32 concurrent requests, and none differed with one request at a time. Gate numbers come from the deterministic mode (enforce-eager, prefix caching off, one request at a time). Other LLM runs are batched and can differ on about 1% of outputs.
- Logged to Weights and Biases, public project: train loss every 10 steps, dev loss on a fixed 500-record dev sample (sample seed shared by every training seed) every 200 steps, learning rate, GPU memory, wall time.
- Outputs: the adapter is saved at the end of every epoch under /workspace/checkpoints/seed{N}/epoch{M}/. Each run writes run.json at the start and completes it at the end with seed, full config, git commit, git_dirty flag, package versions, start, end, training seconds, tokens per second, peak GPU memory, final train loss, every dev loss and the W&B URL.
- Model selection uses dev only.
- Shipped checkpoint: the seed with the median dev accuracy.
- Target: one seed trains in under an hour on one rented GPU.

## 8. Inference and serving

- The adapter is merged into the base weights and saved as a standalone bf16 checkpoint.
- Served with vLLM. Every LLM evaluation, base and fine-tuned, goes through the same OpenAI-compatible client, so the evaluated artifact is the one that would ship.
- Requests: thinking disabled through the chat template, temperature 0, at most 8 new tokens, logprobs on.
- Serving context length: 8,192 tokens. The candidate prompt is short, but the baseline prompts carry the full label list and up to 5 retrieval examples of 600 characters each; 8,192 fits them with headroom. The value lives in configs/serve.yaml and is passed to vLLM as `--max-model-len`.
- A request that would still exceed the server's context is recorded as invalid output in the prediction file; it is not silently truncated and it does not crash the evaluation run. Any other error is retried three times with backoff; if it still fails the run exits non-zero and no predictions.jsonl is written (the file is renamed in from a temporary name only at the end of a clean run).
- Confidence of a prediction: the product of the token probabilities of the generated label.
- Benchmark on a fixed sample of dev prompts at stated concurrency levels: p50 and p95 latency, records per second, the GPU, its hourly price with the date, cost per 1,000 records at full utilisation, and the monthly volume at which an always-on GPU costs the same as each Claude model.
- Spend ledger in results/: GPU hours by purpose, API spend from recorded token usage, both checked against the provider dashboards.

## 9. Gate

Draft until Step 9. The owner can change these numbers until then. Each change is a commit.

- G1 gain: the candidate's mean test accuracy over three seeds is at least the champion's plus 2.0 points.
- G2 noise: for every seed, the lower bound of the 95% paired-bootstrap interval of candidate minus champion is above zero.
- G3 must-pass: a pinned set of test records where the description names the weakness outright (the keyword table fires exactly once), the label agrees, and the champion is right. Every seed gets at least 98% of them.
- G4 validity: invalid output is at most 0.5% for every seed.
- Reported, not gated: macro-F1, kernel and non-kernel accuracy, label-noise slices, cost per 1,000 records, confidence routing.

Why a pinned must-pass set: requiring no regression on every test record would reject almost any classifier, because labels are noisy. The must-pass set is the part of the test set where a miss has no excuse.

Order of operations at Step 9:

1. All baselines have run on test.
2. The champion is named, the must-pass set is written to data/processed/must_pass.json with its sha256, and docs/ACCEPTANCE.md plus configs/gate.yaml are committed.
3. Only then do the three fine-tuned checkpoints run on test.
4. gate.py reads prediction files only and prints PROMOTE or REJECT with every number it used.

Guard (enforced by llm_eval.py): an LLM run whose system name starts with `candidate_` is refused on the test split unless `docs/ACCEPTANCE.md` contains a line "Status: final", `configs/gate.yaml` exists, and both are committed and unmodified. Baseline systems (`qwen35_4b_zero_shot`, `qwen35_4b_few_shot`, `qwen35_4b_retrieval`, Claude systems) are not subject to this guard.

## 10. Confidence routing

Reported, not gated.

- The small model answers only when its confidence clears a threshold. Other records go to a fallback, the best Claude system.
- Two thresholds are chosen on dev: the lowest confidence at which auto-labelled dev records are at least 95% accurate, and at least 97%.
- Both thresholds are written in docs/ACCEPTANCE.md before the candidate touches test.
- On test, for each threshold: the auto-label rate, accuracy on auto-labelled records, accuracy of the cascade over all records, and cost per 1,000 records for small model only, Claude only and the cascade.
- The same table is produced for the TF-IDF linear model, using its margin as confidence.
- No extra model runs: everything comes from existing prediction files.

## 11. Demo

- A GGUF export of the shipped checkpoint, served locally with llama.cpp's llama-server through the same OpenAI-compatible client as the evaluations.
- demo/app.py: paste a description, get the CWE id, its name, the confidence and the latency.
- The demo model is a quantised copy. Numbers in the README come from the bf16 checkpoint on vLLM, and demo/README.md says so.
- A notebook for a free hosted GPU is the fallback.

## 12. Reproducibility

- One command per stage: `make <stage>`, each a thin wrapper over `python -m cve2cwe <stage>`. On a machine without make the Python form is used directly.
- Three pinned environments: base (CPU: data, scoring, baselines, gate, demo client), train (Unsloth), serve (vLLM). Versions are whatever resolves on the build date, frozen in requirements/*.txt.
- Every parameter lives in configs/. Every run writes run.json.
- Raw predictions are committed under outputs/. Metrics are committed under results/.
- README tables are generated from results/ by report.py. Numbers are never typed by hand. Every price carries the date it was read.
- Tests: scorer, split and dedup, test-set lock, gate logic. CI runs lint and tests on every push.
- Secrets come from the environment only.

README contract: a decision memo first (question, result, recommendation, risks, next steps), then in this order: the problem and what it solves, how it was solved, where the dataset is, the training data, inference, the evaluation mechanism, the result. It names the tech stack and links the training dataset, the locked test set, the evaluation code, the raw model outputs and the results. It ends with honest limits.

## 13. Out of scope

- DPO and GRPO. Supervised fine-tuning comes first. The README gets one paragraph on when they would be added.
- A trained abstain class. Section 10 covers low-confidence records by routing.
- CWE hierarchy matching (crediting a parent or child CWE).
- Using the CNA's CWE as an input feature.
- Monitoring, drift alarms, threshold recalibration and a retraining pipeline. The README lists them as what production still needs. This repo is a proof of concept with evidence, not a production system.

## 14. Build order

1. Accounts.
2. Laptop tools.
3. Repo skeleton, git identity, secret guard (Appendix A).
4. Data (section 4).
5. GPU pod and toolchain smoke test: a tiny LoRA run, merge, vLLM, a few dev predictions. This proves the riskiest path before anything is built on it. The test set is not touched.
6. Scorer, CPU baselines, tests (sections 5 and 6).
7. Base-model and Claude baselines (section 6).
8. Full fine-tune, three seeds (section 7).
9. Acceptance commit, final evaluation, gate, error analysis (section 9).
10. Serving benchmark, cost, confidence routing, spend ledger (sections 8 and 10).
11. Demo (section 11).
12. README from results, pre-send checks.

## Appendix A. Skeleton (Step 3)

Create exactly these, no more.

- pyproject.toml: package cve2cwe under src/, Python 3.12, ruff and pytest settings.
- requirements/base.in: numpy, scipy, scikit-learn, pyyaml, requests, ijson, tqdm, huggingface-hub, openai, anthropic, gradio, pytest, ruff. Compile with `uv pip compile requirements/base.in -o requirements/base.txt` so every version is pinned.
- requirements/train.in and requirements/serve.in: one comment line each (GPU pod only, filled in at Step 5).
- src/cve2cwe/__init__.py with a version string.
- src/cve2cwe/__main__.py: a small command dispatcher. `python -m cve2cwe <stage>` for the stages data, baselines, llm-eval, frontier, train, merge, gate, bench, demo, report. Each stage prints "not built yet" and exits 1 for now.
- Makefile: setup, lint, test, and one target per stage that calls the dispatcher. setup creates .venv with uv (Python 3.12) and installs requirements/base.txt plus the package in editable mode. lint runs ruff. test runs pytest.
- scripts/setup_git.sh: sets repo-local user.name "Chaitanya Laxman", user.email "54215105+claxman@users.noreply.github.com" and core.hooksPath .githooks, then prints all three.
- .githooks/pre-commit (executable). Reject the commit if:
  - the author or committer email, read with `git var`, does not end in @users.noreply.github.com
  - any staged file is larger than 20 MB
  - the staged diff matches a key pattern. Each pattern needs the prefix plus a run of key characters, so that this file and the hook itself do not trigger it: `sk-ant-[A-Za-z0-9_-]{20,}`, `hf_[A-Za-z0-9]{30,}`, `ghp_[A-Za-z0-9]{30,}`, `github_pat_[A-Za-z0-9_]{30,}`, `AKIA[0-9A-Z]{16}`, `WANDB_API_KEY=[A-Za-z0-9_-]{20,}`, or a line that begins a PRIVATE KEY block
- .githooks/commit-msg (executable). Reject any commit whose message carries an AI co-author or generated-by trailer (for example `Co-authored-by: Cursor <cursoragent@cursor.com>`). Policy: commits carry one author, the person accountable for them; agent use is disclosed in README.md and AGENTS.md, not in the commit trailer.
- .gitignore: .venv*, .env, data/raw/, checkpoints/, wandb/, *.safetensors, *.gguf, __pycache__/, .pytest_cache/, .ruff_cache/, .DS_Store, *.egg-info/.
- .cursorignore: .env and .env.* but not .env.example, so a coding agent cannot read keys.
- .env.example: variable names only (WANDB_API_KEY, HF_TOKEN, ANTHROPIC_API_KEY), no values.
- LICENSE: MIT, Copyright (c) 2026 Chaitanya Laxman.
- README.md: title, one sentence on what the repo does, "Status: in progress", a link to docs/DESIGN.md, and this line: "Built agent-first: I own the scope, decisions and merges; coding agents wrote the code and ran it under my review."
- docs/ACCEPTANCE.md: a heading and "Draft. The acceptance bar is committed before the final evaluation runs."
- tests/test_smoke.py: imports the package and checks the dispatcher lists every stage.
- .github/workflows/tests.yml: on push and pull request, Python 3.12, install requirements/base.txt and the package, run ruff and pytest.
- .gitkeep in configs/, data/processed/, outputs/, results/, demo/.

Checks for Step 3:

- setup, lint and test pass.
- `git config --get user.email` prints the noreply address. `git config --get core.hooksPath` prints .githooks.
- Hook test without committing: run the hook directly with GIT_AUTHOR_EMAIL and GIT_COMMITTER_EMAIL set to test@example.com and confirm it exits 1. Stage a temporary file containing a fake key such as hf_ followed by 34 letters, run the hook, confirm it exits 1, then unstage and delete the file.
- With all files staged, the hook passes. That proves the patterns do not fire on this repo's own docs.

## Appendix B. File tree at the end of the build

```
AGENTS.md  README.md  LICENSE  Makefile  pyproject.toml
requirements/   base.in base.txt  train.in train.txt  serve.in serve.txt
configs/        data.yaml  prompts.yaml  systems.yaml  train.yaml  serve.yaml  gate.yaml
src/cve2cwe/
  __main__.py   command dispatcher, one entry per stage
  data.py       fetch, clean, dedup, split, manifest, stats, dataset card
  leakage.py    split and lock checks
  runinfo.py    one shared snapshot of git commit, dirty flag (any modified
                or untracked file outside outputs/ and results/), package
                versions and UTC time; captured once per process and reused
                by baselines, scorer, llm_eval and merge
  scorer.py     strict parser, metrics, bootstrap
  baselines.py  majority, keyword rules, TF-IDF linear
  prompts.py    shared chat-message builder: one build_messages for every
                LLM system (candidate, zero_shot, few_shot, retrieval); cuts
                the description to configs/systems.yaml max_description_chars
                and applies the chat template; used by train.py and llm_eval
  llm_eval.py   prompts and client for any OpenAI-compatible endpoint
  frontier.py   Claude reference runs
  train.py      Unsloth LoRA fine-tune
  merge.py      merge adapter, save bf16 checkpoint, export GGUF
  bench.py      latency, throughput, cost
  gate.py       PROMOTE or REJECT with evidence
  report.py     results to README tables, routing table, error analysis
scripts/        setup_git.sh  pod.sh  serve.sh
demo/           app.py  README.md
data/           NOTICE.md  DATASET_CARD.md
  processed/    train.jsonl.gz  dev.jsonl  test.jsonl  labels.json
                must_pass.json  MANIFEST.json  stats.json
outputs/        raw predictions per system, split and run
results/        metrics, per-class tables, gate, serving, routing, spend
docs/           DESIGN.md  ACCEPTANCE.md
tests/          test_smoke.py  test_scorer.py  test_split.py  test_gate.py
.githooks/pre-commit  .githooks/commit-msg   .github/workflows/tests.yml
```

## Change log

- 2026-11-24: Section 4.4 now says the lock is enforced on write. After the first successful build, the data stage refuses to overwrite data/processed/test.jsonl with different content unless RELOCK=1 is set.
- 2026-11-24: Added .githooks/commit-msg to reject any commit whose message carries an AI co-author or generated-by trailer. Appendix A and Appendix B updated accordingly. Policy: one author per commit, the person accountable for it; agent use is disclosed in README.md and AGENTS.md, not in the trailer.
- 2026-11-24: Section 4.3 now records a git_dirty flag in MANIFEST.json alongside git_commit. The flag is read at the start of the run, so it reflects the working tree before the data stage writes anything.
- 2026-11-24: The first two commits (design and skeleton) were rewritten once, before any results existed, to drop an automatic Co-authored-by trailer. File contents were not changed. History is not rewritten after this point.
- 2026-11-24: scripts/pod_setup.sh is replaced by scripts/pod.sh (subcommands push, run, pull, ssh). The pod address lives in .pod (gitignored), not in the script. Appendix B updated.
- 2026-11-24: Section 7 updated to say Qwen3.6 and Qwen3.8 were considered and ruled out: neither generation has an open-weight model under 27B, and Qwen3.8-27B was released on 14 August 2026, inside the test window. Qwen3.5 is the newest Qwen generation with a small open-weight model released before the test window.
- 2026-11-24: Section 7 starting values and target now match configs/train.yaml: per_device_train_batch_size 32, gradient_accumulation_steps 1, length-grouped sampling within shuffled mega-batches, max_seq_length set to the overall max rendered token length rounded up to the next multiple of 64 (training fails if any example is longer), adamw_torch_fused optimiser, dev loss on a fixed 500-record sample (sample seed shared across training seeds) every 200 steps, train loss every 10 steps, epoch rule tied to a 100-step probe. "Loss on the label tokens only" becomes "Loss on the label and the end-of-turn token only": the empty think block before the label is masked. Adapters attach to the language stack only; vision-tower LoRA module count must be 0.
- 2026-11-24: Added src/cve2cwe/prompts.py (shared chat-message builder that applies the 2,000-character input cut once for both train and inference) and configs/systems.yaml (holds max_description_chars; Step 6 extends it with per-system identifiers). Appendix B updated. A CI test asserts a 3,000-character description is cut to 2,000.
- 2026-11-24: Section 8 adds the 4,096-token serving context length and the rule for requests that still exceed it (and for any other serving error): recorded as invalid output in the prediction file, not silently truncated, not crashing the run.
- 2026-11-24: Training (Step 8) started before Steps 6 and 7 to use GPU time while the CPU baselines are built. Training reads train.jsonl.gz and the dev sample only; test.jsonl is not opened at this point.
- 2026-11-24: Added a 2-epoch training set alongside the 1-epoch set. Section 7 epochs bullet updated. configs/train.yaml now has a `run_tag` key: with a tag the W&B run name, the checkpoints folder and the outputs/train folder are `<tag>-seed<N>`; with no tag they stay `seed<N>` so the 1-epoch set keeps its names. scripts/pod_train_seeds.sh now refuses to start while any `cve2cwe-*` tmux session exists (the launcher re-points the train venv). All three clean checks (pod.sh train-seeds, the frozen-tree check, train.py git_dirty) now use `git status --porcelain`, so an untracked source file also counts as dirty; `unsloth_compiled_cache/` is .gitignored and stays out of the check. scripts/pod.sh pull now syncs only `outputs/` and no longer swallows errors; results/ (including results/pod.json) is built on the Mac.
- 2026-11-24: Added src/cve2cwe/scorer.py (the only CWE parser; coverage and test-lock checks; accuracy, invalid rate, macro-F1 with support threshold, kernel and CISA ADP slices, per-class table; 10,000-resample bootstrap for accuracy and a paired bootstrap of two systems; writes results/<system>/<split>/<run_id>.json) and src/cve2cwe/baselines.py (majority, keyword and TF-IDF+LinearSVC, run as `python -m cve2cwe baselines`, plus the top-5 cosine retrieval index used by the next step). configs/systems.yaml now carries `scoring` (bootstrap_resamples 10000, bootstrap_seed 20261124, macro_f1_min_support 20) and the `keyword_rules` table.
- 2026-11-24: Added src/cve2cwe/runinfo.py. One shared snapshot of git commit, dirty flag, package versions and UTC time, captured once at process start and reused for every file a process writes. `git_dirty` is now defined as any modified or untracked file outside `outputs/` and `results/`; the two artefact directories are ignored because the process itself fills them. baselines, scorer, llm_eval and merge all go through runinfo; train.py keeps its own pre-side-effects capture.
- 2026-11-24: Section 8 serving context length lifted from 4,096 to 8,192 tokens. Baseline prompts carry the full label list (53 lines) and up to 5 retrieval examples of 600 characters; 8,192 fits them with headroom. The value lives in configs/serve.yaml and is passed to vLLM with `--max-model-len`. The same section now also specifies the error policy exactly: context-length rejections are recorded as invalid and counted in run.json, any other error is retried three times with backoff, then the run exits non-zero and no predictions.jsonl is written (the file is renamed in from a temporary name at the end of a clean run).
- 2026-11-24: Added configs/serve.yaml (max_model_len, gpu_memory_utilization, max_num_seqs, host, port). scripts/serve.sh now reads it and accepts `--revision`, `--port`, `--max-model-len`, `--gpu-memory-utilization`, `--served-model-name`.
- 2026-11-24: Step 7 added src/cve2cwe/llm_eval.py (full runs: `python -m cve2cwe llm-eval --system {candidate,zero_shot,few_shot,retrieval} --split {dev,test} --model <served> --name <output>`; 32 concurrent requests; temperature 0; max 8 new tokens; logprobs on; thinking disabled; parsing only through scorer.parse; `--repeat-check 300` resends the first N records and fails if any raw output differs). The old lenient parser and the Step 5 smoke command were removed. prompts.py now exposes one `build_messages(system_name, description, examples=…)` builder for every LLM system; the candidate prompt is byte-identical and a golden test pins it. Section 9 gains a guard (enforced by llm_eval): a candidate_* run on the test split is refused until docs/ACCEPTANCE.md contains "Status: final" and configs/gate.yaml exists, with both committed and unmodified.
- 2026-11-24: Step 7 tightened src/cve2cwe/merge.py. `--adapter` and `--out` are required; smoke defaults removed. The adapter's base model must match configs/train.yaml, the base commit actually loaded must match the pinned revision, every adapter key must sit in the language stack (vision-tower keys abort the merge), and a run.json is written to outputs/merge/<run_name>/ with the adapter path, output path, loaded base commit, distinct module prefixes, every output file with its size, and git state.
- 2026-11-24: seed2 and seed3 of the 1-epoch set record git_dirty true. The check at that commit used git diff-index, which also flags timestamp-only changes. Verified on 2026-11-24 in /workspace/run-225b6dd: git diff HEAD --stat is empty, so no file content differed from commit 225b6dd.
- 2026-11-24: Claude systems run on the test split only. Their prompts are not tuned on dev and the champion is chosen on test.
- 2026-11-24: Section 7 no longer says greedy decoding leaves no noise at inference. A repeat of 300 records differed on 3 outputs at 32 concurrent requests and on none with one request at a time. Gate numbers come from the deterministic mode. Other LLM runs are batched and can differ on about 1% of outputs.
- 2026-11-24: Claude Sonnet 5.5 does not accept thinking disabled or a temperature. It was called with thinking between_tools, the lowest setting. Haiku 5.5 was called with thinking disabled.
- 2026-11-24: Section 9 G2 reads "lower bound above zero". An interval that sits entirely below zero does not pass.
