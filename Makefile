PY := .venv/bin/python
UV := uv

.PHONY: setup lint test data baselines llm-eval frontier train merge gate bench backlog demo report

setup:
	$(UV) venv --python 3.12 .venv
	$(UV) pip install --python $(PY) -r requirements/base.txt
	$(UV) pip install --python $(PY) -e .

lint:
	$(PY) -m ruff check .

test:
	$(PY) -m pytest

data:
	$(PY) -m cve2cwe data

baselines:
	$(PY) -m cve2cwe baselines

llm-eval:
	$(PY) -m cve2cwe llm-eval

frontier:
	$(PY) -m cve2cwe frontier

train:
	$(PY) -m cve2cwe train

merge:
	$(PY) -m cve2cwe merge

gate:
	$(PY) -m cve2cwe gate

bench:
	$(PY) -m cve2cwe bench

backlog:
	$(PY) -m cve2cwe backlog

demo:
	$(PY) -m cve2cwe demo

report:
	$(PY) -m cve2cwe report
