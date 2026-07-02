# AGENTS.md

## Project Overview

Plugin for Poetry that wraps dependency installs/updates with a validation process to check for potential supply chain
attacks

## Architectural Thesis

Poetry Guard is intended to be a developer-local and CI-friendly supply chain guardrail, not a replacement for a
full software composition analysis platform, internal package proxy, or curated artifact repository. The gap it targets
is the moment when a Poetry workflow is about to trust newly resolved or newly downloaded package code.

This is especially relevant for individual developers and small organizations, where internal package proxies and
curated repositories are often unrealistic to set up and maintain. Even mature organizations can struggle to make
package proxy policy effective across all developer machines and CI environments. Poetry Guard should therefore focus on
the practical "last mile" control: intercepting dependency changes during `poetry add`, `poetry update`, `poetry lock`,
and `poetry install`, then applying policy before the dependency becomes trusted project state or executable code.

Architecturally, the strongest version of the plugin is:

- a thin Poetry integration layer that hooks lockfile writes and artifact installation
- an independent policy pipeline that aggregates validator findings
- pluggable validators for known vulnerability intelligence, package metadata drift, malicious package heuristics,
  provenance signals, and organization-specific policy
- clear fail-open/fail-closed behavior, selected by mode rather than hidden in exception handling

The Poetry hook layer may ultimately require improvements or patches to Poetry's plugin model. Treat direct interaction
with Poetry internals as adapter code that should stay small, well tested, and easy to revise when Poetry changes.

## Recommended Policy Modes

The project should grow toward explicit modes rather than a single ambiguous validation behavior:

- **warn**: advisory mode for first adoption and exploratory development. Run validators and report findings, but do not
  block installs or lockfile writes.
- **enforce**: default protective mode for regular personal development. Block high-confidence malicious package
  signals, policy violations, and scanner failures that make validation inconclusive for a newly trusted artifact.
- **offline**: cached and local-signal mode for travel, constrained networks, or reproducible environments. Avoid
  network calls and make clear when a verdict is missing because the cache has no prior data.
- **ci**: deterministic mode for automation. Prefer fail-closed behavior, stable output, no random cache refresh, and
  clear machine-readable reporting for build logs or future SARIF/JSON output.

Mode semantics should be explicit in tests. Security-sensitive checks should not silently pass because a validator,
subprocess, network request, or Poetry adapter failed.

## Code Style & Conventions

- **Line length**: 120 characters (black and flake8 are configured accordingly)
- **Type annotations**: required on all functions and class attributes; mypy enforces this
- **`import regex as re`**: always use the `regex` library aliased as `re`; never `import re`
- **No `assert` outside tests**: use explicit `if`/`raise` for runtime invariants
- **Bump validator cache versions on semantic changes**: whenever a validator's logic, rule IDs, severity mapping, or
  emitted messages/details change in a way that should invalidate cached findings, increment that validator's
  `rules_version`

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
