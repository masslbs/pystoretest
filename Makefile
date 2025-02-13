# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

PHONY: test
test:
	pytest -v -x --benchmark-skip -n auto

bench:
	pytest -v --benchmark-only

lint:
	black .
	reuse lint
	# ruff check .

LIC := MIT
CPY := "Mass Labs"

reuse:
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights Makefile README.md *.py misc-utils/*.py *.nix .github/workflows/test.yml .gitignore coingecko-notes.md testcats.md
	reuse annotate --license  $(LIC) --copyright $(CPY) --merge-copyrights --force-dot-license .env.sample flake.lock eth_account-0.13.4.tar.gz eth_keys-0.6.1.tar.gz massmarket-4.0-pre.tar.gz
