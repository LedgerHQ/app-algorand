"""Type definitions for Algorand arbitrary data signing.

This module contains data structures that match the TypeScript interfaces
from @zondax/ledger-algorand for arbitrary data signing operations.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Union


class ScopeType(IntEnum):
    """Scope type for arbitrary data signing."""

    UNKNOWN = -1
    AUTH = 1


@dataclass
class StdSigData:
    """Standard signature data structure for arbitrary data signing.

    Matches the TypeScript StdSigData interface from @zondax/ledger-algorand.
    Used for ARC-60, CAIP-122, and WebAuthn signing operations.
    """

    data: Union[str, bytes]
    signer: bytes
    domain: str
    authenticationData: bytes
    requestId: Optional[Union[str, bytes]] = None
    hdPath: Optional[str] = None
    signature: Optional[bytes] = None


@dataclass
class StdSignMetadata:
    """Metadata for standard signature operations."""

    scope: ScopeType
    encoding: str
