# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

# Version can be overridden: make publish VERSION=1.2.3
VERSION ?= $(shell python -c "import massmarket_client; print(massmarket_client.__version__)")

.PHONY: all test bench lint format build publish clean reuse

all: format lint test build

test:
	pytest tests/ -vv --benchmark-skip -n auto --random-order

bench:
	pytest tests/ -v --benchmark-only

format:
	black massmarket_client/ tests/ *.py

lint: format
	black --check massmarket_client/ tests/ *.py
	reuse lint
	# ruff check massmarket_client/ tests/

build:
	${PYTHON} -m build -n

publish: build
	${PYTHON} -m twine upload dist/massmarket_client-${VERSION}*

clean:
	rm -rf build/ dist/ *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete
	rm -rf patch_logs shop_data result

LIC := MIT
CPY := "Mass Labs"

reuse:
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights pyproject.toml Makefile README.md *.py massmarket_client/*.py tests/*.py misc-utils/*.py *.nix .github/workflows/test.yml .gitignore coingecko-notes.md testcats.md
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights --force-dot-license .env.sample flake.lock
