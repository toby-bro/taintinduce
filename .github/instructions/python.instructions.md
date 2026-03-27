---
applyTo: "**/*.py"
---

## General instructions

- When running code always use `uv run` instead of python / pytest / mypy / ruff directly.
- Type all your code rigourously: we are in python 3.12 so do not use Dict/List/... use dict/list... no need of importing them from typing.
- Once you modify code run these three commands.
  - `uv run mypy .`
  - `uv run ruff check`
    - using `noqa` is nearly always forbidden, and must be avoided at all costs
      - for complexity issues, prefer refactoring the code instead of silencing the error
      - exception for translation functions, where the complexity is often unavoidable, but even then prefer refactoring the code instead of silencing the error
  - `uv run pytest`
- Do not use classes when you do not need shared states, use functions instead.
- Never use tuples[, ...] use sets or frozensets instead.
- Do not use Any except when serializing / deserializing / parsing inputs.
- Keep code changes as small as possible.
- Separate intents
  - keep the code as modular as possible
  - make small functions for logic
  - make variable and function names explicit so as not to need comments / docstring
- Prevent regressions by adding unit tests for each bug you fix, and for each new feature you add.
- Never make fallbacks, or assumptions on default behavious, prefer raising Errors that I will fix instead of silently doing something that may be wrong.

## Writing tests

- When writing unit tests write them with pytest, use pytest mock to mock NEVER unittest.
- Do not make loops to check different variables, use pytest.mark.parametrize
- use `assert` never `self.Assert`
- the test file for "file.py" is "file_test.py" in the same folder.
