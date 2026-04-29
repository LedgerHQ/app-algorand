# Functional Tests

This directory contains the ** functional test suite** for the Ledger application.  
It is intended to validate the application’s behavior in a **generic context**, when launched directly from the device's dashboard.

These tests are written using:

- [pytest](https://docs.pytest.org/en/stable/) — Python testing framework
- [Ragger](https://github.com/LedgerHQ/ragger) — Ledger's open-source testing library for simulating device interactions

---

## Purpose

The test suite ensures that:

- The application launches correctly from the dashboard
- The main menu and navigation behave as expected
- Core commands (e.g., `GET_VERSION`, `GET_PUBLIC_KEY`, `SIGN_TX`) function properly
- User approval flows work under normal conditions
- Errors are correctly reported and handled

---

## Directory Structure

```text
tests/
├── application_client/      # Python client library for communicating with the app
│   ├── __init__.py
│   ├── algorand_command_sender.py   # APDU command builder
│   ├── algorand_response_unpacker.py # Response parser
│   ├── algorand_types.py            # Type definitions
│   ├── py.typed                     # PEP 561 marker for typed package
│   ├── README.md                    # Client library documentation
│   └── setup.cfg                    # Package configuration
├── __init__.py              # Package marker
├── conftest.py              # Pytest fixtures and device setup
├── data.py                  # Test data and constants
├── requirements.txt         # Python dependencies
├── setup.cfg                # Pytest configuration
├── snapshots/               # Ragger UI snapshots for visual regression
├── snapshots-tmp/           # Temporary snapshot diffs (not tracked in git)
├── test_*.py                # Functional test cases
├── usage.md                 # Usage documentation
└── utils.py                 # Local test helpers
```
