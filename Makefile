.PHONY: build test lint e2e ci

CARGO ?= cargo

build:
	$(CARGO) build --locked --verbose

test:
	$(CARGO) test --locked --verbose -- --nocapture

lint:
	$(CARGO) clippy --locked --verbose -- -D warnings

e2e:
	bash tests/e2e/fault_matrix.sh

ci: lint test build
