from pathlib import Path

from typing import List
import re
import json
import hashlib
import base64
import msgpack  # type: ignore[import-not-found]
import ed25519  # type: ignore[import-not-found]
import canonicaljson  # type: ignore[import-not-found]

from .application_client.algorand_types import StdSigData


# Check if a signature of a given message is valid
def check_tx_signature_validity(
    public_key: bytes, signature: bytes, message: bytes
) -> bool:
    """Verify Ed25519 signature for Algorand transaction.

    Algorand transactions are signed with a "TX" prefix as per the Algorand protocol.
    The signature is Ed25519 in raw 64-byte format (not DER encoded).

    Args:
        public_key: 32-byte Ed25519 public key
        signature: 64-byte Ed25519 signature
        message: Transaction bytes (will be prefixed with "TX")

    Returns:
        True if signature is valid, False otherwise
    """
    # Algorand protocol: prepend "TX" to the transaction bytes before signing
    prefixed_message = b"TX" + message
    return check_signature_validity(public_key, signature, prefixed_message)


def check_signature_validity(
    public_key: bytes, signature: bytes, message: bytes
) -> bool:
    """Verify Ed25519 signature for any data.

    Any data signatures are verified directly without any prefix.
    The signature is Ed25519 in raw 64-byte format (not DER encoded).

    Args:
        public_key: 32-byte Ed25519 public key
        signature: 64-byte Ed25519 signature
        message: Message bytes (no prefix added)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Create verifying key from public key bytes
        verifying_key = ed25519.VerifyingKey(public_key)

        # Verify the signature directly without any prefix
        verifying_key.verify(signature, message)
        return True
    except ed25519.BadSignatureError:
        # Signature verification failed
        return False
    except Exception:
        # Other errors (e.g., invalid key format)
        return False



def verify_version(version: str) -> None:
    """Verify the app version, based on defines in app/Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> List[str]:
    """Read lines from the app/Makefile.version"""

    parent = Path(__file__).parent.parent.resolve()
    makefile = f"{parent}/app/Makefile.version"
    with open(makefile, "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines


def pack_account_id(account_id: int) -> bytes:
    """Pack an account ID as a 32-bit big-endian unsigned integer.

    Args:
        account_id (int): The account ID to pack

    Returns:
        bytes: 4-byte big-endian representation of the account ID
    """
    return account_id.to_bytes(4, byteorder="big")


def build_to_sign(auth_request: StdSigData) -> bytes:
    """Build the data to sign for arbitrary data signing.

    This matches the TypeScript buildToSign function. It:
    1. Decodes the data (if base64) to get JSON
    2. Parses and canonifies the JSON
    3. Hashes the canonified JSON with SHA256
    4. Hashes the authenticationData with SHA256
    5. Concatenates both hashes

    Args:
        auth_request: The signature request containing data and authenticationData

    Returns:
        bytes: The concatenated hash to sign
    """
    # Handle data - can be bytes or base64 string
    if isinstance(auth_request.data, bytes):
        # Already bytes, use directly
        decoded_data = auth_request.data
    else:
        # String - decode from base64
        decoded_data = base64.b64decode(auth_request.data)

    # Parse the JSON
    client_data_json = json.loads(decoded_data.decode("utf-8"))

    # Canonify the JSON
    canonified_client_data_json = canonicaljson.encode_canonical_json(client_data_json)

    if not canonified_client_data_json:
        raise ValueError("Wrong JSON")

    # Hash the canonified JSON
    client_data_json_hash = hashlib.sha256(canonified_client_data_json).digest()

    # Hash the authentication data
    authenticator_data_hash = hashlib.sha256(auth_request.authenticationData).digest()

    # Concatenate both hashes
    to_sign = client_data_json_hash + authenticator_data_hash

    return to_sign


def address_to_public_key(address: str) -> bytes:
    """Decode Algorand address to 32-byte public key.

    Args:
        address: Base32-encoded Algorand address

    Returns:
        bytes: 32-byte public key (address without checksum)
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    # Base32 decode
    bits = 0
    value = 0
    output = []

    for char in address:
        index = alphabet.find(char)
        if index == -1:
            continue

        value = (value << 5) | index
        bits += 5

        if bits >= 8:
            output.append((value >> (bits - 8)) & 0xFF)
            bits -= 8

    decoded = bytes(output)
    # Remove the last 4 bytes (checksum) and return first 32 bytes (public key)
    return decoded[:32]


def encode_transaction(transaction: dict) -> bytes:
    """Encode a transaction as a MessagePack blob.

    Args:
        transaction: The transaction to encode

    Returns:
        bytes: The MessagePack blob
    """
    return msgpack.packb(transaction, use_bin_type=True)
