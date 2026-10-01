# Releasing

1. **Bump the version** (the docs-consistency test fails if these drift):
   - `pyproject.toml` (`[project] version`)
   - `.mcp/server.json` (`version` and `packages[0].version`)
   - `docs/index.html` footer (`OpenOSINT X.Y.Z`)
   - `README.md` last line (`OpenOSINT vX.Y.Z — Month YYYY`)
2. **CHANGELOG.md**: rename `[Unreleased]` to `[X.Y.Z] — YYYY-MM-DD` and open a fresh `[Unreleased]`.
3. **Refresh the lock**: `uv lock`, commit it. CI runs `uv lock --check`; the Heroku build runs `uv sync --locked`, so a stale lock breaks the demo deploy.
4. **Check locally**: `pytest tests -q` and `ruff check openosint tests --extend-ignore I001`. Merge to `main` once CI is green.
5. **Tag**: `git tag vX.Y.Z && git push origin vX.Y.Z`. The Release workflow checks the tag against `pyproject.toml` and publishes to PyPI.
6. **PyPI check**: `uvx --from openosint==X.Y.Z openosint --version` (and `openosint web` starts) from a clean directory.
7. **Deploy the demo** (manual): `git push heroku-demo main:main`.
8. **Health check**: `curl -fsS https://demo.openosint.tech/api/health` returns `"status":"ok"` and `"version":"X.Y.Z"`. If it fails, `heroku logs --tail -a openosint-demo`.
