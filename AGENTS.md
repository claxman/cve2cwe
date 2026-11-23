# Rules for coding agents working in this repo

Read docs/DESIGN.md before any work. It is the specification. This file is how to work.

## What this repo is

cve2cwe labels a CVE description with the CWE weakness type an NVD analyst would assign, using a small fine-tuned open-weight model. It then decides, with evidence, whether that model should replace a frontier model for the task. The output that matters is a decision someone can act on, backed by numbers that a run produced.

## How to work

1. One work order at a time. Do only what the current work order asks. Do not start the next step. Do not add files that are not in the design's file tree without asking.
2. Do the work yourself: write the code, run the commands, read the output, fix what fails. Ask the user only for what you cannot do: browser sign-ins, secrets, payments and design decisions.
3. If the design is unclear or looks wrong, stop and ask. Do not change a design decision on your own.
4. When something fails, show the exact error and try the smallest fix. After three failed attempts, stop and report. Do not swap a library, a model or the approach to get past an error.
5. For fast-moving libraries (unsloth, vllm, transformers, trl, peft, anthropic, openai, gradio, llama.cpp), read the documentation for the installed version before writing code against them. Do not rely on memory.

## Evidence rules

- Never invent, estimate or round a number. Numbers in README.md and docs come only from files under results/ and data/processed/ that a run produced.
- A weak or failed result is reported as it is.
- Every run writes a run.json with seed, config, git commit, package versions, start time and end time.
- Never edit a prediction file or a results file by hand.

## Test set rules

- data/processed/test.jsonl is locked. Never change it after the data step. Never read it in training code. Never draw few-shot examples, thresholds or hyperparameters from it.
- Until docs/ACCEPTANCE.md is committed as final, no fine-tuned checkpoint is evaluated on test.
- The fields cna_cwes and adp_cwes never go into a model prompt.

## Engineering rules

- Parameters live in configs/. No magic numbers in code.
- Dependencies are pinned. Three environments: base, train, serve.
- One command per stage.
- Run lint and tests before reporting a step as done.
- Small files. Comments say why, not what.
- Plain language in comments, docs and commit messages. No hype. No em dashes.
- Public sources only. No code, data, prompts, names or figures from any employer or private source.

## Secrets

- Keys come from the environment or a local .env that is never committed and never printed.
- Never echo a key. Never write one to a log, a notebook output or a tracked file.
- Never ask the user to paste a key into the chat. Ask them to put it in .env.

## Git

- Author and committer identity is the GitHub noreply address set by scripts/setup_git.sh. Never change it. Never bypass the pre-commit hook.
- Never commit or push until the user says "commit".
- One commit per finished step, with the message "Step N: what was done".
- No force push, no history rewriting, no amend after a push.
- After a commit, print `git log -1 --format='%h %an <%ae> %s'` and `git status --short`.

## Report at the end of every work order

1. Files created or changed.
2. Commands run and whether each passed.
3. The check results the work order asked for, copied from the terminal.
4. Anything that deviates from docs/DESIGN.md, and why.
5. Open questions for the user.

Keep the report short. Then stop.
