# Rare Protocol (Python)

`rare-protocol` provides the protocol primitives and verifier logic used by Rare identity flows.

## What is included

- `rare_protocol`: signing payload builders, token helpers, crypto helpers, name policy
- `rare_identity_verifier`: verification helpers for identity + delegation chains
- RIP documents and test vectors in `docs/`

## Install

```bash
pip install rare-protocol
```

## Quick verification

```python
from rare_protocol import build_auth_challenge_payload

payload = build_auth_challenge_payload(
    aud="platform.example",
    nonce="nonce123",
    issued_at=1700000000,
    expires_at=1700000120,
)
print(payload)
```

## Local development

```bash
python -m pip install -U pip setuptools wheel
python -m pip install -e .[test]
pytest -q
python -m build
```

## Security and governance

See `SECURITY.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, and `CONTRIBUTING.md`.
