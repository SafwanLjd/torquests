## What and why

<!-- Describe the change and the problem it solves. Link any related issue. -->

## Checklist

- [ ] Tests pass: `uv run pytest`
- [ ] Lint and format clean: `uv run ruff check src tests && uv run ruff format --check src tests`
- [ ] Types clean: `uv run mypy src`
- [ ] `pre-commit` hooks pass
- [ ] Docs or `README.md` updated where the change is user-visible
- [ ] Protocol changes verified against `torspec`, and library usage verified
      against the library's own docs, with the source cited where non-obvious
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org)
      (`type: summary`), small and focused
