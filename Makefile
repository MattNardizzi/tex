.PHONY: install test test-quiet run lint clean

# Default to Python 3.12.
PYTHON ?= python

# ---- Install ---------------------------------------------------------------

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e ".[dev]"

# ---- Tests -----------------------------------------------------------------
#
# `make test` is the canonical command for confirming the test pass
# count. From a clean install the expected output is:
#
#     720 passed in ~22s
#
# If the suite hangs or errors before this number, the most common
# cause is a missing Postgres driver — check that both
# psycopg[binary] and asyncpg are installed (see requirements.txt).

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

test-quiet:
	$(PYTHON) -m pytest tests/ -q --tb=line

# ---- Run -------------------------------------------------------------------

run:
	$(PYTHON) -m uvicorn tex.main:create_app --factory --reload --host 0.0.0.0 --port 8000

# ---- Hygiene ---------------------------------------------------------------

lint:
	$(PYTHON) -m ruff check src/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
