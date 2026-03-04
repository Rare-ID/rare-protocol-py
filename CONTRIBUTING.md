# Contributing to Rare Protocol (Python)

## Development setup

```bash
python -m pip install -U pip setuptools wheel
python -m pip install -e .[test]
```

## Quality gates

```bash
pytest -q
python -m build
```

## Pull requests

- Keep changes minimal and focused.
- Include tests for behavioral changes.
- Update RIP docs and vectors for protocol-affecting changes.
