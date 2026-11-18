.PHONY: install test lint dev

install:
	./scripts/install.sh

test:
	./scripts/test.sh

lint:
	.venv/bin/ruff check src tests sdk
	.venv/bin/mypy src

dev:
	./scripts/dev.sh
