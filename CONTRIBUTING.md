# Contributing to GhostWire

Thanks for helping! GhostWire is small and plain Python, so getting started takes a minute.

## Setup

```bash
git clone https://github.com/Himanshu-Sharma12/ghostwire.git
cd ghostwire
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The TypeScript type-check test needs Node.js (`npx` fetches `tsc` on first run) and is skipped without it.
The live end-to-end test calls https://dummyjson.com and only runs with `GHOSTWIRE_LIVE=1 pytest tests/test_live.py`.

## Reporting a bug

The best bug report is a tiny HAR file that reproduces it. **Remove real tokens, cookies and personal data first.** Replacing values with fakes is fine as long as the shape stays the same.
Tell us what `gw inspect` printed and what you expected instead.

## Making a change

- Add a test. Analysis edge cases usually belong in [`tests/test_engine.py`](tests/test_engine.py); new traffic shapes can go into [`tests/fixtures/edge_cases.har`](tests/fixtures/edge_cases.har).
- If you touch a generator, the tests in [`tests/test_generators.py`](tests/test_generators.py) compile/import/type-check its output for every capture. Keep them green.
- Never make a generator write captured credentials by default. Secrets must stay behind `--embed-secrets`.
- Keep the zero-config experience: new behaviour should work without flags where it safely can.

## Pull requests

1. Fork and create a branch (`git checkout -b fix/clustering-dates`)
2. Commit with a descriptive message (`fix(cluster): keep ISO dates as literal segments`)
3. Open a PR describing the problem, the fix, and how you tested it
