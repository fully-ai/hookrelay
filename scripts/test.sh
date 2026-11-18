#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/ruff check src tests sdk
.venv/bin/mypy src
.venv/bin/pytest -v
