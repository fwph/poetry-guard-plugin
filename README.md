# Poetry Guard

Poetry Guard is a Poetry plugin for catching risky dependency changes before they become trusted project state.

The project is aimed at individual developers, small teams, and CI workflows that cannot realistically depend on a
well-maintained internal package proxy or curated repository. Those controls are valuable, but they are expensive to
operate well. Poetry Guard focuses on the practical gap left behind: the moment a Poetry workflow is about to resolve,
lock, download, or install new third-party code.

## AI Status

This project so far has leaned heavily on the use of both Codex and Claude Code agents; keep in mind that this
is currently highly experimental and not fully human-reviewed (including this README! I have small children, side
projects require some acceleration).

## Goals

- Detect suspicious dependency changes during normal Poetry workflows.
- Combine known vulnerability intelligence with malicious package and metadata heuristics.
- Guard both lockfile changes and artifact installation.
- Provide a local-first control that is useful for personal development and small organizations.
- Keep the policy engine independent from Poetry-specific integration details.

## Non-Goals

- Replace a full software composition analysis platform.
- Replace internal package mirrors, curated repositories, SBOM tooling, or release attestations.
- Prove that a package is safe.
- Block every possible supply chain attack.

Poetry Guard should be one layer in a broader supply chain posture. Its job is to make risky dependency changes harder
to miss at the point where developers and CI systems are most likely to introduce them.

## Why This Exists

Python dependency workflows increasingly face attacks that are not just "known vulnerable version" problems:

- typosquatting
- dependency confusion
- maintainer account compromise
- malicious new releases
- install-time code execution
- suspicious package metadata drift
- newly uploaded packages with little history

Large organizations may address some of this with internal proxies, package allowlists, repository policy, and dedicated
security teams. Many developers and small teams do not have that machinery. Poetry Guard is designed for that reality.

## Approach

Poetry Guard plugs into Poetry and validates package changes in two places:

- Lockfile validation checks new or upgraded packages before lock data is written.
- Artifact validation checks downloaded package archives before installation.

Validation is coordinated through a small policy pipeline. Validators can produce findings for a package, and the
pipeline decides whether those findings are accepted, ignored, warned about, or blocked according to project policy.

Current validators include:

- OSV checks for known vulnerabilities and malicious package reports.
- PyPI metadata checks for maintainer changes, missing repository URLs, and very new releases.
- GuardDog artifact scans for suspicious source-code and package-metadata patterns.

The design intentionally keeps validators pluggable. Future validators could check PyPI attestations, Sigstore data,
organization allowlists, package age policies, project ownership signals, or custom internal rules.

## Recommended Modes

Poetry Guard should grow toward explicit policy modes:

- **warn**: run checks and report findings without blocking. This is useful during first adoption or when tuning rules.
- **enforce**: block high-confidence malicious package signals, configured severity thresholds, and validation failures
  that make a newly trusted artifact inconclusive. This is the intended day-to-day protective mode.
- **offline**: use cached verdicts and local signals without network calls. Missing cache data should be reported
  clearly.
- **ci**: run deterministically with strict failure behavior and stable output for automation.

The key principle is that validation behavior should be explicit. A scanner crash, subprocess failure, network problem,
or Poetry integration issue should not silently become "package accepted" unless the selected mode says so.

## Current Status

This repository is an early implementation. The core architecture is in place:

- `poetry_guard_plugin/plugin.py` wires the plugin into Poetry.
- `poetry_guard_plugin/locker.py` validates new or upgraded lockfile packages.
- `poetry_guard_plugin/executor.py` validates artifacts before install.
- `poetry_guard_plugin/pipeline.py` loads validators, handles caching, and aggregates findings.
- `poetry_guard_plugin/validators/` contains OSV, PyPI metadata, and GuardDog validators.

The highest-risk implementation area is the Poetry adapter layer. Poetry's plugin model may need improvements to
support this kind of install-time guard cleanly. Until then, the adapter code should stay small and covered by
integration tests.

### Poetry Integration Limitations

Poetry Guard currently relies on a few Poetry internals because Poetry does not expose first-class hooks for all of the
places this plugin needs to validate dependency changes. In particular, the plugin wraps Poetry's locker and swaps the
installer executor class at runtime so it can validate lockfile writes and downloaded artifacts before Poetry trusts
them.

Those integration points are intentionally kept narrow, but they are still more sensitive to Poetry implementation
changes than normal public plugin APIs. If a future Poetry release changes locker or executor internals, Poetry Guard may
need adapter updates even when the validator pipeline itself is still correct.

## Development

Install dependencies:

```bash
poetry install
```

Run checks:

```bash
poetry run flake8 .
poetry run black .
poetry run mypy .
poetry run bandit -r . -ll
poetry run pytest
```

## Poetry Plugin Compatibility

When Poetry Guard is installed as a project plugin via `tool.poetry.requires-plugins`, dependency resolution happens
against Poetry's own runtime environment, not just the target project's virtualenv. In practice, that means an older
Poetry installation can block plugin installation if its bundled dependencies are too old for Poetry Guard or one of
its transitive dependencies.

If plugin installation fails with version-solving errors involving packages such as `requests` or `urllib3`, upgrade
or reinstall Poetry itself before assuming the target project is misconfigured.

If Poetry was installed with `pipx`, a full reinstall is often the fastest fix:

```bash
pipx uninstall poetry
pipx install poetry
```

This resets Poetry's own dependency environment, which can otherwise accumulate incompatible package versions across
upgrades.

## Configuration

Configuration is read from `[tool.poetry-guard]` in `pyproject.toml`.

Example:

```toml
[tool.poetry-guard]
enabled = true
offline = false
osv_severity = "moderate"
guarddog_severity = "high"
min_age_days = 3
accept_risk = []
ignore_rules = []
```

Environment overrides currently include:

```bash
POETRY_GUARD_NO_GUARD=1
POETRY_GUARD_ACCEPT_RISK=pkg@1.2.3,other@4.5.6
```

## Security Philosophy

Poetry Guard should be conservative about trust and honest about uncertainty. It should not claim to certify packages as
safe. It should make risky changes visible, block high-confidence danger in enforcing modes, and give developers a clear
path to intentionally accept risk when they have reviewed it.
