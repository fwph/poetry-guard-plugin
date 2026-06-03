# AGENTS.md

## Project Overview

Plugin for Poetry that wraps dependency installs/updates with a validation process to check for potential supply chain attacks

## Code Style & Conventions

- **Line length**: 120 characters (black and flake8 are configured accordingly)
- **Type annotations**: required on all functions and class attributes; mypy enforces this
- **`import regex as re`**: always use the `regex` library aliased as `re`; never `import re`
- **No `assert` outside tests**: use explicit `if`/`raise` for runtime invariants

## Project Layout

- `poetry_guard_plugin/` — main package (namespace package, no `__init__.py`)
- `test/` — pytest tests; no `__init__.py` in this directory
- `test/test_data/` — static test fixtures

## Testing

- **pytest** only; write plain `def test_*()` functions
- **No class-based test grouping** unless there is a genuine shared-state reason (extremely rare)
- Use the `test_data` fixture (defined in `test/conftest.py`) to get a `Path` to `test/test_data/`

## HTTP

- Prefer `aiohttp` for HTTP clients and servers

## Dependencies

Managed with Poetry v2. Install everything (including dev tools) with:

    poetry install

Lint/format/type-check commands:

    poetry run flake8 .
    poetry run black .
    poetry run mypy .
    poetry run bandit -r . -ll
    poetry run pytest
