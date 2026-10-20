.PHONY: setup lint test data features train evaluate replay run-local clean

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := uv pip
# Works even if the editable install's .pth is ignored (macOS hidden-file flag).
export PYTHONPATH := src

setup:
	uv venv $(VENV)
	$(PIP) install --python $(PY) -e ".[dev,postgres]"

lint:
	$(VENV)/bin/ruff check src tests
	$(VENV)/bin/ruff format --check src tests

test:
	$(VENV)/bin/pytest -q

# Generate the synthetic datasets used for training and evaluation.
data:
	$(PY) -m generator.generate --preset synth_normal_v1
	$(PY) -m generator.generate --preset synth_bf_v1
	$(PY) -m generator.generate --preset synth_hard_v1

features:
	$(PY) -m training.build_features --dataset synth_normal_v1
	$(PY) -m training.build_features --dataset synth_bf_v1
	$(PY) -m training.build_features --dataset synth_hard_v1

train:
	$(PY) -m training.train

evaluate:
	$(PY) -m training.evaluate

# Replay a dataset file through the service in real time (file source, stdout sink).
replay:
	SOURCE=file SOURCE_FILES=data/raw/synth_bf_v1/auth.jsonl SINK=stdout \
	REPLAY=1 $(PY) -m detector

run-local:
	SOURCE=file SINK=stdout $(PY) -m detector

clean:
	rm -rf data models reports .pytest_cache .ruff_cache
