from enum import IntEnum
from typing import Generator, Optional, List
from contextlib import contextmanager
import base64
import struct

from ragger.backend.interface import BackendInterface, RAPDU  # type: ignore  # pylint: disable=import-error

from ..utils import pack_account_id
from .algorand_types import StdSigData, StdSignMetadata

MAX_APDU_LEN: int = 250

CLA: int = 0x80


class AlgorandSigningError(Exception):
    """Exception raised when signing a transaction chunk fails."""


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for first account ID
    P1_FIRST_ACCOUNT_ID = 0x01
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01
    # Parameter 1 indicating account number present in first chunk
    P1_ACCOUNT_PRESENT = 0x01
    # Parameter 1 for more data coming
    P1_MORE = 0x80


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    GET_VERSION = 0x00
    GET_PUBLIC_KEY = 0x03
    GET_ADDRESS = 0x04
    SIGN_MSGPACK = 0x08
    SIGN_ARBITRARY_DATA = 0x10


class Errors(IntEnum):
    # Predefined error codes
    SW_SUCCESS = 0x9000
    SW_CONDITIONS_NOT_SATISFIED = 0x6985
    SW_COMMAND_NOT_ALLOWED_EF = 0x6986
    SW_INCORRECT_P1_P2 = 0x6A86
    SW_WRONG_DATA_LENGTH = 0x6A87
    SW_INVALID_INS = 0x6D00
    SW_INVALID_CLA = 0x6E00
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_DISPLAY_AMOUNT_FAIL = 0xB003
    SW_WRONG_TX_LENGTH = 0xB004
    SW_TX_PARSING_FAIL = 0xB005
    SW_TX_HASH_FAIL = 0xB006
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008
    SW_WRONG_AMOUNT = 0xC000
    SW_WRONG_ADDRESS = 0xC000
    # Arbitrary sign error codes
    SW_DATA_INVALID = 0x6984
    SW_INVALID_SCOPE = 0x6988
    SW_FAILED_DECODING = 0x6989
    SW_INVALID_SIGNER = 0x698A
    SW_MISSING_DOMAIN = 0x698B
    SW_MISSING_AUTH_DATA = 0x698C
    SW_BAD_JSON = 0x698D
    SW_FAILED_DOMAIN_AUTH = 0x698E
    SW_FAILED_HD_PATH = 0x698F


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


def add_account_id_to_message(message: bytes, account_id: int) -> bytes:
    if account_id != 0:
        return pack_account_id(account_id) + message

    return message


def serialize_encoding(encoding: str) -> bytes:
    """Serialize encoding type to bytes.

    Args:
        encoding: The encoding type (e.g., 'base64')

    Returns:
        bytes: Serialized encoding as bytes

    Raises:
        ValueError: If encoding is not supported
    """
    if encoding == "base64":
        return b"\x01"
    if encoding == "wrong_encoding":
        return b"\x99"
    raise ValueError(f"Unsupported encoding: {encoding}")


def serialize_path(path: str) -> bytes:
    """Serialize BIP32 path to bytes.

    Converts a BIP32 path string like "m/44'/283'/0'/0/0" to a 20-byte buffer
    with 5 uint32 values in little-endian format.

    Args:
        path: BIP32 path string (e.g., "m/44'/283'/0'/0/0")

    Returns:
        bytes: 20-byte serialized path

    Raises:
        ValueError: If path is invalid
    """
    HARDENED = 0x80000000

    if not path:
        raise ValueError("Invalid path.")

    if not path.startswith("m"):
        raise ValueError('Path should start with "m" (e.g "m/44\'/1\'/5\'/0/3")')

    path_array = path.split("/")
    if len(path_array) != 6:
        raise ValueError(
            "Invalid path. It should be a BIP44 path (e.g \"m/44'/1'/5'/0/3\")"
        )

    # Allocate 20 bytes for 5 uint32 values
    buf = bytearray(20)

    # Process each component (skip first 'm')
    for i in range(1, len(path_array)):
        value = 0
        hardening = 0

        component = path_array[i]
        if component.endswith("'"):
            hardening = HARDENED
            try:
                value = int(component[:-1])
            except ValueError as exc:
                raise ValueError(
                    f"Invalid path: {component} is not a number. (e.g \"m/44'/1'/5'/0/3\")"
                ) from exc
        else:
            try:
                value = int(component)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid path: {component} is not a number. (e.g \"m/44'/1'/5'/0/3\")"
                ) from exc

        if value >= HARDENED:
            raise ValueError("Incorrect child value (bigger or equal to 0x80000000)")

        value += hardening

        # Write as uint32 little-endian
        offset = 4 * (i - 1)
        struct.pack_into("<I", buf, offset, value)

    return bytes(buf)


class AlgorandCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    # def get_app_and_version(self) -> RAPDU:
    #     return self.backend.exchange(
    #         cla=0xB0,  # specific CLA for BOLOS
    #         ins=0x01,  # specific INS for get_app_and_version
    #         p1=P1.P1_START,
    #         p2=P2.P2_LAST,
    #         data=b"",
    #     )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_LAST, data=b""
        )

    # def get_app_name(self) -> RAPDU:
    #     return self.backend.exchange(
    #         cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_START, p2=P2.P2_LAST, data=b""
    #     )

    @contextmanager
    def get_address_and_public_key_with_confirmation(
        self, account_id: int = 0
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_ADDRESS,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        ) as response:
            yield response

    def get_address_and_public_key(self, account_id: int = 0) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_ADDRESS,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        )

    # Deprecated use get_address_and_public_key instead
    @contextmanager
    def get_public_key_with_confirmation(
        self, account_id: int = 0
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        ) as response:
            yield response

    # Deprecated use get_address_and_public_key instead
    def get_public_key(self, account_id: int = 0) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        )

    @contextmanager
    def sign_tx(
        self, account_id: int, transaction: bytes
    ) -> Generator[None, None, None]:
        # Add the account id to the transaction
        message = add_account_id_to_message(transaction, account_id)
        # Split the transaction into chunks
        chunks = split_message(message, MAX_APDU_LEN)
        # Get the number of chunks
        num_of_chunks = len(chunks)
        # Sπaet the p1 value
        p1 = P1.P1_FIRST_ACCOUNT_ID if account_id != 0 else P1.P1_START

        # Send all chunks except the last one
        if num_of_chunks > 1:
            for i in range(0, num_of_chunks - 1):
                rapdu = self.backend.exchange(
                    cla=CLA,
                    ins=InsType.SIGN_MSGPACK,
                    p1=p1 if i == 0 else P1.P1_MORE,
                    p2=P2.P2_MORE,
                    data=chunks[i],
                )

                if rapdu.status != Errors.SW_SUCCESS:
                    raise AlgorandSigningError(
                        f"Error after sending chunk number {i}: {rapdu.status}"
                    )

        # Send the last chunk
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.SIGN_MSGPACK,
            p1=P1.P1_MORE if len(chunks) > 1 else P1.P1_FIRST_ACCOUNT_ID,
            p2=P2.P2_LAST,
            data=chunks[-1],
        ) as response:
            yield response

    def _prepare_sign_data_buffers(
        self, auth_request: StdSigData, metadata: StdSignMetadata
    ) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
        """Prepare buffers for signing arbitrary data.

        Args:
            auth_request: The signature request data
            metadata: Metadata including scope and encoding

        Returns:
            Tuple of (signer, scope, encoding, data, domain, request_id, auth_data) buffers
        """
        # Handle data - can be base64 string or raw bytes
        if isinstance(auth_request.data, bytes):
            decoded_data = auth_request.data
        else:
            decoded_data = base64.b64decode(auth_request.data)

        # Prepare all buffers
        signer_buffer = auth_request.signer
        scope_buffer = bytes([metadata.scope])
        encoding_buffer = serialize_encoding(metadata.encoding)
        data_buffer = decoded_data
        domain_buffer = auth_request.domain.encode() if auth_request.domain else b""

        # Handle requestId - can be either base64 string or bytes
        if auth_request.requestId:
            if isinstance(auth_request.requestId, str):
                request_id_buffer = base64.b64decode(auth_request.requestId)
            else:
                request_id_buffer = auth_request.requestId
        else:
            request_id_buffer = b""

        auth_data_buffer = (
            auth_request.authenticationData if auth_request.authenticationData else b""
        )

        return (
            signer_buffer,
            scope_buffer,
            encoding_buffer,
            data_buffer,
            domain_buffer,
            request_id_buffer,
            auth_data_buffer,
        )

    def _build_sign_data_message(
        self,
        signer: bytes,
        scope: bytes,
        encoding: bytes,
        data: bytes,
        domain: bytes,
        request_id: bytes,
        auth_data: bytes,
    ) -> bytes:
        """Build the message buffer for signing arbitrary data.

        Args:
            signer: Signer buffer
            scope: Scope buffer
            encoding: Encoding buffer
            data: Data buffer
            domain: Domain buffer
            request_id: Request ID buffer
            auth_data: Authentication data buffer

        Returns:
            bytes: Complete message buffer
        """
        # Calculate message size with variable length fields (2-byte prefixes)
        message_size = (
            len(signer)
            + len(scope)
            + len(encoding)
            + 2
            + len(data)
            + 2
            + len(domain)
            + 2
            + len(request_id)
            + 2
            + len(auth_data)
        )

        # Build the message buffer
        message_buffer = bytearray(message_size)
        offset = 0

        def write_field(buffer: bytes, variable_length: bool = False) -> None:
            nonlocal offset
            if variable_length:
                # Write 2-byte big-endian length prefix
                message_buffer[offset : offset + 2] = len(buffer).to_bytes(
                    2, byteorder="big"
                )
                offset += 2
            # Copy buffer data
            message_buffer[offset : offset + len(buffer)] = buffer
            offset += len(buffer)

        # Write all fields in order
        write_field(signer)
        write_field(scope)
        write_field(encoding)
        write_field(data, True)
        write_field(domain, True)
        write_field(request_id, True)
        write_field(auth_data, True)

        return bytes(message_buffer)

    def _send_sign_data_chunks(self, chunks: List[bytes], p1_add: int, p2: int) -> None:
        """Send all chunks except the last one.

        Args:
            chunks: List of data chunks
            p1_add: P1 value for intermediate chunks
            p1_last: P1 value for last chunk (unused here)
            p2: P2 value

        Raises:
            AlgorandSigningError: If sending chunks fails
        """
        if len(chunks) > 1:
            for i in range(0, len(chunks) - 1):
                rapdu = self.backend.exchange(
                    cla=CLA,
                    ins=InsType.SIGN_ARBITRARY_DATA,
                    p1=p1_add,
                    p2=p2,
                    data=chunks[i],
                )

                if rapdu.status != Errors.SW_SUCCESS:
                    raise AlgorandSigningError(
                        f"Error after sending chunk number {i}: {rapdu.status}"
                    )

    @contextmanager
    def sign_data(
        self, auth_request: StdSigData, metadata: StdSignMetadata
    ) -> Generator[None, None, None]:
        """Sign arbitrary data using the Algorand app.

        Args:
            auth_request: The signature request data
            metadata: Metadata including scope and encoding

        Yields:
            None: Yields control to allow navigation/confirmation

        Raises:
            ValueError: If encoding is not base64
            AlgorandSigningError: If signing fails
        """
        # Validate encoding
        if metadata.encoding != "base64":
            raise ValueError("Failed decoding")

        # Prepare HD path buffer
        hd_path = auth_request.hdPath if auth_request.hdPath else "m/44'/283'/0'/0/0"
        path_buffer = serialize_path(hd_path)

        # Prepare all data buffers
        buffers = self._prepare_sign_data_buffers(auth_request, metadata)

        # Build the message buffer
        message_buffer = self._build_sign_data_message(*buffers)

        # Split message into chunks
        chunks = split_message(message_buffer, MAX_APDU_LEN)

        # P1 values for arbitrary sign
        P1_INIT = 0x00
        P1_ADD = 0x01
        P1_LAST = 0x02

        # P2 is always 0 for arbitrary sign
        p2 = P2.P2_LAST

        # Send first chunk with path buffer (P1_INIT)
        rapdu = self.backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_ARBITRARY_DATA,
            p1=P1_INIT,
            p2=p2,
            data=path_buffer,
        )

        if rapdu.status != Errors.SW_SUCCESS:
            raise AlgorandSigningError(f"Error sending path: {rapdu.status}")

        # Send all chunks except the last one
        self._send_sign_data_chunks(chunks, P1_ADD, p2)

        # Send the last chunk with exchange_async
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.SIGN_ARBITRARY_DATA,
            p1=P1_LAST,
            p2=p2,
            data=chunks[-1],
        ) as response:
            yield response

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response

    # def sign_tx_sync(self, path: str, transaction: bytes) -> Optional[RAPDU]:
    #     with self.sign_tx(path, transaction):
    #         pass
    #     rapdu = self.get_async_response()
    #     assert isinstance(rapdu, RAPDU)
    #     return rapdu
