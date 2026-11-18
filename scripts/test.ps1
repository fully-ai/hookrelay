$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
.\.venv\Scripts\ruff check src tests sdk
.\.venv\Scripts\mypy src
.\.venv\Scripts\pytest -v
