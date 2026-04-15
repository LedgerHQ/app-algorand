import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.navigator import NavInsID, Navigator

from ledgered.devices import DeviceType

from .application_client.algorand_command_sender import AlgorandCommandSender, Errors
from .application_client.algorand_response_unpacker import (
    unpack_get_public_key_response,
)
from .utils import check_tx_signature_validity, encode_transaction
from .data import (
    txAssetFreeze,
    txAssetXfer,
    txAssetConfig,
    txKeyreg,
    txPayment,
    txApplication,
    txApplicationLong,
    txAprv,
    txAlAddress,
    txAlMultipleAddresses,
    txAlAsset,
    txAlApplication,
    txAlHolding,
    txMultipleHoldings,
    txAlLocals,
    txAlBox,
    txAlEmptyBoxRef,
    txAlMixedResources,
    txAlMixedWithBoxAndLocals,
    txAlMaxElements,
    txAlOverMaxElements,
    txAlMultipleAssets,
    txAlMultipleApplications,
    txAlComplexMixHoldingAndLocals,
    txAlHoldingMissingAddressIndex,
    txAlHoldingMissingAssetIndex,
    txAlLocalsMissingAddressIndex,
    txAlLocalsMissingApplicationIndex,
    txAppArgsWithAl,
)


"""
Transaction signing tests for Algorand Ledger application.

These tests verify the device behavior when signing various transaction types,
ensuring correct on-screen display and valid signature generation.
"""

# Account ID used for all tests
ACCOUNT_ID = 123

# Navigation instructions for Nano devices (S+, X)
NANO_NAVIGATE_INSTRUCTIONS = NavInsID.RIGHT_CLICK
NANO_VALIDATE_INSTRUCTIONS = [NavInsID.BOTH_CLICK]

# Navigation instructions for touch screen devices (Stax, Flex, Gen 5/Apex P)
TOUCH_NAVIGATE_INSTRUCTIONS = NavInsID.SWIPE_CENTER_TO_LEFT
TOUCH_VALIDATE_INSTRUCTIONS = [NavInsID.USE_CASE_REVIEW_CONFIRM]
TOUCH_REJECT_INSTRUCTIONS = [
    NavInsID.USE_CASE_CHOICE_REJECT,
    NavInsID.USE_CASE_CHOICE_CONFIRM,
]


def sign_tx_and_verify(
    tx_to_sign,
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Sign a transaction on the device and verify the signature.

    This helper function performs the complete flow of:
    1. Retrieving the public key from the device
    2. Sending a transaction to the device for signing
    3. Navigating through the on-screen approval flow
    4. Verifying the returned signature is valid

    Args:
        tx_to_sign: The transaction to sign (as a list of integers or hex string)
        backend: The backend interface to communicate with the device
        navigator: The navigator to perform on-screen interactions
        test_name: Name of the test for screenshot comparison
        default_screenshot_path: Path where screenshots should be saved

    Raises:
        AssertionError: If the signature verification fails
    """
    # Initialize the Algorand command sender client
    client = AlgorandCommandSender(backend)

    # Retrieve the public key from the device for signature verification
    rapdu = client.get_address_and_public_key(account_id=ACCOUNT_ID)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    # Convert transaction to bytes (handle both hex string and list formats)
    if isinstance(tx_to_sign, str):
        transaction_blob = bytes.fromhex(tx_to_sign)
    else:
        transaction_blob = bytes(tx_to_sign)

    # Configure navigation instructions based on device type
    if backend.device.is_nano:
        navigate_instructions = NANO_NAVIGATE_INSTRUCTIONS
        validate_instructions = NANO_VALIDATE_INSTRUCTIONS
        text_to_search = "APPROVE"
    else:
        navigate_instructions = TOUCH_NAVIGATE_INSTRUCTIONS
        validate_instructions = TOUCH_VALIDATE_INSTRUCTIONS
        text_to_search = "Sign"

    # Send transaction to device for signing (asynchronous operation requiring user confirmation)
    with client.sign_tx(account_id=ACCOUNT_ID, transaction=transaction_blob):
        # Navigate through the approval flow and capture screenshots for comparison
        navigator.navigate_until_text_and_compare(
            navigate_instructions,
            validate_instructions,
            text_to_search,
            default_screenshot_path,
            test_name,
        )

    # Retrieve the signature and verify its validity
    signature = client.get_async_response().data
    assert check_tx_signature_validity(public_key, signature, transaction_blob)


def test_sign_asset_freeze_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing an asset freeze transaction."""
    sign_tx_and_verify(
        txAssetFreeze,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_asset_transfer_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing an asset transfer transaction."""
    sign_tx_and_verify(
        txAssetXfer,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_asset_config_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing an asset configuration transaction."""
    sign_tx_and_verify(
        txAssetConfig,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_keyreg_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a key registration transaction."""
    sign_tx_and_verify(
        txKeyreg,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_payment_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a payment transaction."""
    sign_tx_and_verify(
        txPayment,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_application_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing an application call transaction."""
    sign_tx_and_verify(
        txApplication,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_asset_freeze_and_application_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing two transactions sequentially: asset freeze and application call."""
    sign_tx_and_verify(
        txAssetFreeze,
        backend,
        navigator,
        test_name + "part1",
        default_screenshot_path,
    )

    sign_tx_and_verify(
        txApplication,
        backend,
        navigator,
        test_name + "part2",
        default_screenshot_path,
    )


def test_sign_application_long_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a long application transaction with many fields."""
    sign_tx_and_verify(
        txApplicationLong,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_application_long_shortcut_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a long application transaction using shortcut mode (Nano devices only).
    
    This test enables expert mode and shortcut mode, then signs a long application
    transaction by skipping fields and directly approving.
    """
    # Skip test for touch screen devices (only Nano devices support shortcut mode)
    if not backend.device.is_nano:
        pytest.skip("This test is only for devices with buttons (Nano S, S+, X)")
        return

    # Navigation sequence to enable expert mode and shortcut mode
    enable_shortcut_mode_instructions = [
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # Enable expert mode
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # Enable shortcut mode
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # Confirm shortcut mode
    ]
    # Navigate through settings and capture screenshots
    navigator.navigate_and_compare(
        default_screenshot_path,
        test_name,
        enable_shortcut_mode_instructions,
        screen_change_before_first_instruction=False,
    )

    # Initialize the Algorand command sender client
    client = AlgorandCommandSender(backend)

    # Retrieve the public key from the device for signature verification
    rapdu = client.get_address_and_public_key(account_id=ACCOUNT_ID)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    # Convert transaction to bytes (handle both hex string and list formats)
    if isinstance(txApplicationLong, str):
        transaction_blob = bytes.fromhex(txApplicationLong)
    else:
        transaction_blob = bytes(txApplicationLong)

    # Configure navigation instructions for Nano devices
    navigate_instructions = NANO_NAVIGATE_INSTRUCTIONS
    validate_instructions = NANO_VALIDATE_INSTRUCTIONS
    text_to_search = "APPROVE"

    # Navigation sequence to skip fields and approve
    skip_and_approve_instructions = [
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # Skip fields
        NavInsID.BOTH_CLICK,  # Approve
    ]

    # Send transaction to device for signing (asynchronous operation requiring user confirmation)
    with client.sign_tx(account_id=ACCOUNT_ID, transaction=transaction_blob):
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            skip_and_approve_instructions,
            screen_change_before_first_instruction=False,
            snap_start_idx=11,
        )

    # Retrieve the signature and verify its validity
    signature = client.get_async_response().data
    assert check_tx_signature_validity(public_key, signature, transaction_blob)


def test_sign_aprv_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing an APRV (app reject version) transaction."""
    tx_blob = encode_transaction(txAprv)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_address_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing address resources."""
    tx_blob = encode_transaction(txAlAddress)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_holding_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing holding resources."""
    tx_blob = encode_transaction(txAlHolding)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_multiple_addresses_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing multiple address resources."""
    tx_blob = encode_transaction(txAlMultipleAddresses)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_multiple_holdings_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing multiple holding resources."""
    tx_blob = encode_transaction(txMultipleHoldings)

    # Debug output for encoded transaction
    print("Encoded transaction: 0x", tx_blob.hex())

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_asset_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing asset resources."""
    tx_blob = encode_transaction(txAlAsset)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_application_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing application resources."""
    tx_blob = encode_transaction(txAlApplication)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_locals_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing local resources."""
    tx_blob = encode_transaction(txAlLocals)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_box_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing box resources."""
    tx_blob = encode_transaction(txAlBox)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_empty_box_ref_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing an empty box reference."""
    tx_blob = encode_transaction(txAlEmptyBoxRef)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_mixed_resources_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing mixed resource types (address, asset, application, empty)."""
    tx_blob = encode_transaction(txAlMixedResources)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_mixed_with_box_and_locals_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing both box and local resources."""
    tx_blob = encode_transaction(txAlMixedWithBoxAndLocals)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_max_elements_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list at maximum capacity (16 elements)."""
    tx_blob = encode_transaction(txAlMaxElements)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_multiple_assets_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing multiple asset ressources."""
    tx_blob = encode_transaction(txAlMultipleAssets)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_multiple_applications_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing multiple application ressources."""
    tx_blob = encode_transaction(txAlMultipleApplications)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_complex_mix_holding_and_locals_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with access list containing a complex mix of holding and local resources."""
    tx_blob = encode_transaction(txAlComplexMixHoldingAndLocals)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_over_max_elements_tx(
    backend: BackendInterface,
) -> None:
    """Test that access list with too many elements (17, exceeds maximum of 16) fails with parsing error."""
    client = AlgorandCommandSender(backend)

    tx_blob = encode_transaction(txAlOverMaxElements)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(account_id=ACCOUNT_ID, transaction=tx_blob):
            pass

    # Verify that a data invalid error was returned
    assert e.value.status == Errors.SW_DATA_INVALID


def test_sign_al_holding_missing_address_index_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with holding resource missing the address index (d field)."""
    tx_blob = encode_transaction(txAlHoldingMissingAddressIndex)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_holding_missing_asset_index_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with holding resource missing the asset index (s field)."""
    tx_blob = encode_transaction(txAlHoldingMissingAssetIndex)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_locals_missing_address_index_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with local resource missing the address index (d field)."""
    tx_blob = encode_transaction(txAlLocalsMissingAddressIndex)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


def test_sign_al_locals_missing_application_index_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with local resource missing the application index (p field)."""
    tx_blob = encode_transaction(txAlLocalsMissingApplicationIndex)

    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )

def test_sign_tx_refused(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test that rejecting a transaction signature returns the expected error."""
    # Initialize the Algorand command sender client
    client = AlgorandCommandSender(backend)

    # Create the transaction to sign
    transaction = bytes(txAssetFreeze)

    # Configure navigation instructions based on device type
    if backend.device.is_nano:
        navigate_instructions = NANO_NAVIGATE_INSTRUCTIONS
        validate_instructions = NANO_VALIDATE_INSTRUCTIONS
        text_to_search = "REJECT"
    else:
        navigate_instructions = TOUCH_NAVIGATE_INSTRUCTIONS
        validate_instructions = TOUCH_REJECT_INSTRUCTIONS
        text_to_search = "Reject"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(account_id=ACCOUNT_ID, transaction=transaction):
            navigator.navigate_until_text_and_compare(
                navigate_instructions,
                validate_instructions,
                text_to_search,
                default_screenshot_path,
                test_name,
            )

    # Verify that the rejection error was returned
    assert e.value.status == Errors.SW_COMMAND_NOT_ALLOWED_EF
    assert len(e.value.data) == 0


def test_sign_tx_app_args_with_al(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Test signing a transaction with application arguments and access list."""
    tx_blob = encode_transaction(txAppArgsWithAl)
    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )