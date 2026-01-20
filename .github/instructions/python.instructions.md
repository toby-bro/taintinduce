---
applyTo: "**/*.py"
---

## General instructions

- When running code always use `uv run` instead of python / pytest / mypy / ruff directly.
- Type all your code rigourously.
- Once you modify code run these three commands.
  - `uv run mypy .`
  - `uv run ruff check`
  - `uv run pytest`
- Do not use classes when you do not need shared states, use functions instead.
- Never use tuples[, ...] use sets or frozensets instead.
- Do not use Any except when serializing / deserializing / parsing inputs.
- Keep code changes as small as possible.
- Separate intents
  - keep the code as modular as possible
  - make small functions for logic
  - make variable and function names explicit so as not to need comments / docstring

## Writing tests

- When writing unit tests write them with pytest, use pytest mock to mock NEVER unittest.
- Do not make loops to check different variables, use pytest.mark.parametrize
- use `assert` never `self.Assert`
