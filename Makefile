# ai-memory's test and distribution targets. This file is the CI definition:
# .github/workflows/ci.yml calls these targets and enforces the per-suite counts,
# so it is changed by humans only (.github/agent-protected.txt).
#
# Suites are plain `python3 <file>` scripts, as in setup, found by glob, so a new
# suite needs no change here. Every target that finds nothing to run says so and
# exits 0; whether "nothing" is acceptable is decided by ci.yml's import-state
# step, not here.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

PYTHON ?= python3

# The server venv, from the same requirements-v2.txt the host installs.
VENV := .venv
VENV_PY := $(CURDIR)/$(VENV)/bin/python
VENV_STAMP := $(VENV)/.requirements-v2.stamp
# The auth proxy runs on requirements.txt's wheels (aiohttp, PyJWT, OpenTelemetry).
PROXY_VENV := .venv-proxy
PROXY_PY := $(CURDIR)/$(PROXY_VENV)/bin/python
PROXY_STAMP := $(PROXY_VENV)/.requirements.stamp

PY_SUITES = $(sort $(wildcard memory-mcp/test_*.py memory-keeper/test_*.py tests/test_*.py))
SH_SUITES = $(sort $(wildcard tests/test_*.sh))
# The proxy's suites need its own wheels, so they run under the proxy venv.
PROXY_SUITES = $(sort $(wildcard auth-proxy/test_*.py))

.PHONY: venv venv-proxy test test-affected check-distribution test-proxy-import test-mirror-hook test-http

venv: $(VENV_STAMP)
venv-proxy: $(PROXY_STAMP)

# A stamp, not the interpreter: bin/python is a symlink to the system python.
$(VENV_STAMP): requirements-v2.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install -q -r requirements-v2.txt
	touch $@

$(PROXY_STAMP): requirements.txt
	$(PYTHON) -m venv $(PROXY_VENV)
	$(PROXY_PY) -m pip install -q -r requirements.txt
	touch $@

# Each run is announced by an `=== RUN <suite>` line; ci.yml attributes the
# `---- pass=N fail=F` summary that follows to that suite.
test: $(VENV_STAMP) $(PROXY_STAMP)
	@n=0; \
	for f in $(PY_SUITES); do echo "=== RUN $$f"; $(VENV_PY) $$f; n=$$((n+1)); done; \
	if [ -f memory-mcp/test_client_policy.py ]; then \
	  echo "=== RUN memory-mcp/test_client_policy.py --wiring"; \
	  $(VENV_PY) memory-mcp/test_client_policy.py --wiring; n=$$((n+1)); \
	fi; \
	for f in $(PROXY_SUITES); do echo "=== RUN $$f"; $(PROXY_PY) $$f; n=$$((n+1)); done; \
	for f in $(SH_SUITES); do echo "=== RUN $$f"; bash $$f; n=$$((n+1)); done; \
	if [ $$n -eq 0 ]; then \
	  echo "make test: no suites yet (memory-mcp/test_*.py, memory-keeper/test_*.py, tests/test_*.py, auth-proxy/test_*.py, tests/test_*.sh)"; \
	else \
	  echo "make test: $$n suite runs passed"; \
	fi

# The repository is small enough that "affected" is everything.
test-affected: test

# Each MANIFEST's files alone, in an empty directory, import against the wheels
# the host installs (setup's bin/check-memory-v2-manifest, ADR 0010).
check-distribution: $(VENV_STAMP)
	MEMORY_MCP_PYTHON=$(VENV_PY) bash .github/ci/check-distribution.sh

# proxy.py starts in /opt/es-memory/app-v2 next to memory-mcp's MANIFEST files, so
# it is imported from exactly that file set; a MANIFEST entry named like one of
# its dependencies (jwt.py) would shadow the wheel, which the assertion catches.
test-proxy-import: $(PROXY_STAMP)
	@if [ ! -f auth-proxy/proxy.py ]; then echo "make test-proxy-import: no auth-proxy/proxy.py yet"; exit 0; fi; \
	d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	cp auth-proxy/proxy.py "$$d/"; \
	for m in $$(grep -vE '^\s*(#|$$)' memory-mcp/MANIFEST | sed 's/\r$$//; s/^[[:space:]]*//; s/[[:space:]]*$$//'); do \
	  mkdir -p "$$d/$$(dirname "$$m")"; cp "memory-mcp/$$m" "$$d/$$m"; \
	done; \
	cd "$$d" && $(PROXY_PY) -I -c 'import os, sys; sys.path.insert(0, os.getcwd()); import proxy, jwt, aiohttp.web; assert "site-packages" in jwt.__file__, jwt.__file__; assert isinstance(proxy.app, aiohttp.web.Application); print("PASS  proxy imports from the app-v2 file set; jwt from " + jwt.__file__)'

test-mirror-hook:
	@if [ ! -f hooks/test-mirror-file-memory.sh ]; then echo "make test-mirror-hook: no hooks/test-mirror-file-memory.sh yet"; exit 0; fi; \
	echo "=== RUN hooks/test-mirror-file-memory.sh"; \
	bash hooks/test-mirror-file-memory.sh hooks/mirror-file-memory.rb

# Not part of test or test-affected, and not wired into CI (C26 does that).
test-http:
	@if [ ! -f tests/http_roundtrip/run.py ]; then echo "make test-http: tests/http_roundtrip/run.py does not exist" >&2; exit 1; fi
	@$(MAKE) --no-print-directory venv
	$(VENV_PY) tests/http_roundtrip/run.py
