# Application Client for Functional Tests

This minimalist Python client is used in the functional tests of the [algorand Ledger application](https://github.com/LedgerHQ/app-algorand).  
It serves as a communication layer between the test framework (`pytest`) and the device-under-test (Ledger app), sending commands and parsing responses.

## Purpose

This module is not intended to be a full SDK. Instead, it offers just enough abstraction to:

- Send APDUs to the application
- Decode structured responses
- Facilitate clear and maintainable test code

It is intentionally lightweight, focusing on what is strictly necessary to write functional tests.

## When to Use

Use this client as-is when testing the original algorand application.  
If you **fork the algorand app** to implement your own Ledger app, you can **extend or modify this client** to support your custom instruction set, encodings, and behavior.

## Structure

The `application_client` package contains:

- `algorand_command_sender.py` — Low-level command encoding and APDU transmission
- `algorand_response_unpacker.py` — Functions to decode responses from the app
- `algorand_types.py` — Type definitions and data structures for Algorand operations
- `py.typed` — Marker file for type checkers (e.g. `mypy`)

## How to Use

Look at the existing tests for example on how to use this client
