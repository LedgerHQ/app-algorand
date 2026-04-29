import pytest
import hashlib

import base64
import struct
import cbor2
import canonicaljson
from dataclasses import dataclass
from typing import Optional

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.navigator import NavInsID, Navigator

# from .application_client.algorand_transaction import Transaction
from .application_client.algorand_command_sender import AlgorandCommandSender, Errors
from .application_client.algorand_types import StdSigData, StdSignMetadata, ScopeType
from .application_client.algorand_response_unpacker import (
    unpack_get_public_key_response,
)
from .utils import check_signature_validity, build_to_sign
from .data import (
    ARBITRARY_SIGN_TEST_CASES,
)

DEFAULT_HD_PATH = "m/44'/283'/0'/0/0"


DETERMINISTIC_SEED = "fixed-seed-for-deterministic-tests"
requestIdRandomBytes = hashlib.sha256(DETERMINISTIC_SEED.encode()).digest()[:32]


def sign_arbitrary_and_verify(
    auth_request: StdSigData,
    metadata: StdSignMetadata,
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
    client: AlgorandCommandSender,
    public_key: bytes,
    snap_start_idx: int = 0,
) -> bytes:

    # Set navigate and validate instructions based on the device
    if backend.device.is_nano:
        navigate_instructions = NavInsID.RIGHT_CLICK
        validate_instructions = [NavInsID.BOTH_CLICK]
        text_to_search = "APPROVE"
    else:
        navigate_instructions = NavInsID.SWIPE_CENTER_TO_LEFT
        validate_instructions = [NavInsID.USE_CASE_REVIEW_CONFIRM]
        text_to_search = "Hold"

    with client.sign_data(auth_request, metadata):
        navigator.navigate_until_text_and_compare(
            navigate_instructions,
            validate_instructions,
            text_to_search,
            default_screenshot_path,
            test_name,
            snap_start_idx=snap_start_idx,
        )

    # The device as yielded the result, parse it and ensure that the signature is correct
    signature = client.get_async_response().data

    # Build the data to sign
    to_sign = build_to_sign(auth_request)

    # Verify the signature
    assert check_signature_validity(public_key, signature, to_sign)

    return signature


# In this test we send to the device arbitrary data to sign and verify the signature
# We will ensure that the displayed information is correct by using screenshots comparison
@pytest.mark.parametrize("test_case", ARBITRARY_SIGN_TEST_CASES)
def test_sign_arbitrary(
    test_case: dict,
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # append index to the test name
    test_name = f"{test_name}_{test_case['idx']}"

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_{test_case['idx']})  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = test_case["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
        hdPath=DEFAULT_HD_PATH,
    )

    sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )


# In this test we send to the device arbitrary data to sign and verify the signature for a different account
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_hdpath(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Set account id to 2
    account_id = 2

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key(account_id)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_hdpath)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
        hdPath=f"m/44'/283'/{account_id}'/0/0",
    )

    signatureForAccountId2 = sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )

    signatureForAccountId0 = b"e8ef89c60790bc217a69e0b47fa35119b831e9fd7beb3c4219df2206c5d65d1a59691c7107dd0c0fe03c53a9e2faaf78a47d65d40cdab395bba88395e68f5a049000"
    assert signatureForAccountId0 != signatureForAccountId2


# In this test we send to the device arbitrary data to sign without specifying an HD path
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_no_hdpath(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_no_hdpath)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
    )

    sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )


# In this test we send to the device arbitrary data to sign without specifying a request ID
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_no_request_id(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_no_hdpath)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        hdPath=DEFAULT_HD_PATH,
    )

    sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )


# In this test we send to the device arbitrary data to sign without specifying a request ID or HD path
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_no_request_id_and_no_hdpath(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_no_request_id_and_no_hdpath)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
    )

    sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )


# In this test we send to the device multiple arbitrary data requests to sign and verify the signatures
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_multiple_signatures(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_multiple_signatures)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data1 = ARBITRARY_SIGN_TEST_CASES[0]["data"]
    data2 = ARBITRARY_SIGN_TEST_CASES[1]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request for the first signature
    auth_request1 = StdSigData(
        data=data1,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
        hdPath="m/44'/283'/0'/0/0",
    )
    # Sign and verify the first signature
    sign_arbitrary_and_verify(
        auth_request1,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )

    # Create the Auth Request for the second signature
    auth_request2 = StdSigData(
        data=data2,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
        hdPath="m/44'/283'/0'/0/0",
    )

    snap_start_idx = 0

    # Figure out the number of snapshots based on the device
    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_multiple_signatures)  navigator.device.name: {navigator._device.name}"
    )

    match navigator._device.name:
        case "nanosp":
            snap_start_idx = 13
        case "nanox":
            snap_start_idx = 13
        case "apex_p":
            snap_start_idx = 7
        case "flex":
            snap_start_idx = 7
        case "stax":
            snap_start_idx = 6

    # Sign and verify the second signature
    sign_arbitrary_and_verify(
        auth_request2,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
        snap_start_idx=snap_start_idx,
    )


# In this test we send to the device arbitrary data with authenticator data containing flags
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_authenticator_data_with_flags(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_authenticator_data_with_flags)  public_key: {public_key}"
    )

    # Build the authenticator data structure
    rpIdHash = hashlib.sha256(b"arc60.io").digest()
    flags = 0b11000011

    sign_count = 0
    aaguid = bytes([1] * 16)
    credential_id = bytes([2] * 16)
    credential_id_length = len(credential_id)

    # Create credential public key as CBOR map
    credential_public_key = {
        1: 2,
        3: -7,
        -1: 1,
        -2: bytes([3] * 32),
        -3: bytes([4] * 32),
    }

    credential_public_key_buffer = cbor2.dumps(credential_public_key)

    # Create extensions as CBOR dict
    extensions = {"booleanExt": True, "numericExt": 42, "stringExt": "test-value"}
    extensions_buffer = cbor2.dumps(extensions)

    # Calculate total auth data length
    auth_data_length = (
        len(rpIdHash)
        + 1
        + 4
        + len(aaguid)
        + 2
        + credential_id_length
        + len(credential_public_key_buffer)
        + len(extensions_buffer)
    )

    # Build the auth data buffer
    auth_data = bytearray()
    auth_data.extend(rpIdHash)
    auth_data.extend(struct.pack("B", flags))
    auth_data.extend(struct.pack("<I", sign_count))
    auth_data.extend(aaguid)
    auth_data.extend(struct.pack(">H", credential_id_length))
    auth_data.extend(credential_id)
    auth_data.extend(credential_public_key_buffer)
    auth_data.extend(extensions_buffer)

    # Create the data to sign
    client_data = {
        "type": "arc60.create",
        "challenge": "test",
        "origin": "https://arc60.io",
    }
    canonified_data = canonicaljson.encode_canonical_json(client_data)
    data = base64.b64encode(canonified_data).decode("utf-8")

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=bytes(auth_data),
        hdPath=DEFAULT_HD_PATH,
    )

    sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )


## Tests for failing cases ##


# In this test we send to the device arbitrary data to sign with a long requestId
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_arbitrary_long_requestId(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_long_requestId)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create a long requestId buffer
    long_request_id_buffer = b"0" * 255

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=long_request_id_buffer,
    )

    sign_arbitrary_and_verify(
        auth_request,
        StdSignMetadata(scope=ScopeType.AUTH, encoding="base64"),
        backend,
        navigator,
        test_name,
        default_screenshot_path,
        client,
        public_key,
    )


# In this test we send to the device arbitrary data to sign with an invalid requestId (too long)
# We expect this to fail with an error
def test_sign_arbitrary_invalid_requestId(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_invalid_requestId)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create a long requestId buffer
    invalid_request_id_buffer = b"0" * 400

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=invalid_request_id_buffer,
    )
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_DATA_INVALID
    assert e.value.data == b"Invalid Request ID"


# In this test we send to the device arbitrary data to sign with an invalid scope
# We expect this to fail with an error
def test_sign_arbitrary_invalid_scope(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_invalid_requestId)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
    )
    invalid_scope = 7

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=invalid_scope, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_SCOPE
    assert e.value.data == b"Invalid Scope"


# In this test we send to the device arbitrary data to sign with an invalid signer (public key)
# We expect this to fail with an error
def test_sign_arbitrary_invalid_signer(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    invalid_public_key = b"0" * 32

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_invalid_signer)  invalid_public_key: {invalid_public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=invalid_public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
    )
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_INVALID_SIGNER
    assert e.value.data == b"Invalid Signer"


# In this test we send to the device arbitrary data to sign with an invalid encoding
# We expect this to fail with an error
def test_sign_arbitrary_invalid_encoding(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_invalid_encoding)  public_key: {public_key}"
    )

    # Set invalid encoding
    invalid_encoding = "wrong_encoding"

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
    )
    with pytest.raises(Exception) as e:
        with client.sign_data(
            auth_request,
            StdSignMetadata(scope=ScopeType.AUTH, encoding=invalid_encoding),
        ):
            pass
    # assert e.value.status == Errors.SW_FAILED_DECODING
    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_invalid_encoding)  error: {e.value}"
    )
    assert str(e.value) == "Failed decoding"


# In this test we send to the device arbitrary data to sign with a missing domain
# We expect this to fail with an error
def test_sign_arbitrary_missing_domain(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_invalid_encoding)  public_key: {public_key}"
    )

    # Set invalid encoding
    invalid_encoding = "wrong_encoding"

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
    )
    with pytest.raises(Exception) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_MISSING_DOMAIN
    assert e.value.data == b"Missing Domain"


# In this test we send to the device arbitrary data to sign with missing authentication data
# We expect this to fail with an error
def test_sign_arbitrary_missing_authenticated_data(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_missing_authenticated_data)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=None,
        requestId=requestIdRandomBytes,
        hdPath=DEFAULT_HD_PATH,
    )
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_MISSING_AUTH_DATA
    assert e.value.data == b"Missing Authentication Data"


# In this test we send to the device arbitrary data to sign with invalid JSON
# We expect this to fail with an error
def test_sign_arbitrary_bad_json(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_bad_json)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = base64.b64encode(b"{ this is not valid JSON").decode("utf-8")

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
        hdPath=DEFAULT_HD_PATH,
    )
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_BAD_JSON
    assert e.value.data == b"Bad JSON"


# In this test we send to the device arbitrary data to sign with mismatched domain authentication
# We expect this to fail with an error
def test_sign_arbitrary_failed_domain_auth(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_failed_domain_auth)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    wrong_auth_data = hashlib.sha256(b"wrong-domain.com").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=wrong_auth_data,
        requestId=requestIdRandomBytes,
        hdPath=DEFAULT_HD_PATH,
    )
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_FAILED_DOMAIN_AUTH
    assert e.value.data == b"Failed Domain Auth"


# In this test we send to the device arbitrary data to sign with an invalid HD path
# We expect this to fail with an error
def test_sign_arbitrary_failed_hd_path(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key()
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    print(
        f"km-logs  [test_sign_arbitrary_data.py] (test_sign_arbitrary_failed_domain_auth)  public_key: {public_key}"
    )

    # Create the Data to Sign
    data = ARBITRARY_SIGN_TEST_CASES[0]["data"]

    # Create the Auth Data
    auth_data = hashlib.sha256(b"arc60.io").digest()

    # Create the Auth Request
    auth_request = StdSigData(
        data=data,
        signer=public_key,
        domain="arc60.io",
        authenticationData=auth_data,
        requestId=requestIdRandomBytes,
        hdPath="m/44'/999'/0'/0/0",
    )
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_data(
            auth_request, StdSignMetadata(scope=ScopeType.AUTH, encoding="base64")
        ):
            pass
    assert e.value.status == Errors.SW_FAILED_HD_PATH
