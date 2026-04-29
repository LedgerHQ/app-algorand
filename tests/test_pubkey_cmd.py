import pytest

# from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.backend.interface import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.navigator import NavInsID, Navigator
from ledgered.devices import Device

from .application_client.algorand_command_sender import AlgorandCommandSender, Errors
from .application_client.algorand_response_unpacker import (
    unpack_get_public_key_response,
)


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend: BackendInterface) -> None:
    client = AlgorandCommandSender(backend)
    account_id = 123
    expected_public_key = (
        "0dfdbcdb8eebed628cfb4ef70207b86fd0deddca78e90e8c59d6f441e383b377"
    )
    response =  client.get_public_key(account_id=account_id)
    _, public_key, _, address = unpack_get_public_key_response(response.data)

    assert public_key.hex() == expected_public_key

# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm_accepted(
    backend: BackendInterface,
    scenario_navigator: NavigateWithScenario,
    device: Device,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    client = AlgorandCommandSender(backend)
    account_id = 123
    expected_public_key = (
        "0dfdbcdb8eebed628cfb4ef70207b86fd0deddca78e90e8c59d6f441e383b377"
    )
    expected_address = "BX63ZW4O5PWWFDH3J33QEB5YN7IN5XOKPDUQ5DCZ232EDY4DWN3XKUQRCA"

    with client.get_public_key_with_confirmation(account_id=account_id) as response:
        if not device.is_nano:
            scenario_navigator.address_review_approve()
        else:
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "APPROVE",
                default_screenshot_path,
                test_name,
            )

    response = client.get_async_response().data
    _, public_key, _, address = unpack_get_public_key_response(response)


    assert public_key.hex() == expected_public_key
    assert address.decode("ascii") == expected_address


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_key_confirm_refused(
    backend: BackendInterface,
    scenario_navigator: NavigateWithScenario,
    device: Device,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    client = AlgorandCommandSender(backend)
    account_id = 123

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(account_id=account_id) as response:
            if not device.is_nano:
                scenario_navigator.address_review_reject()
            else:
                navigator.navigate_until_text_and_compare(
                    NavInsID.RIGHT_CLICK,
                    [NavInsID.BOTH_CLICK],
                    "REJECT",
                    default_screenshot_path,
                    test_name,
                )

    assert e.value.status == Errors.SW_COMMAND_NOT_ALLOWED_EF
    assert len(e.value.data) == 0


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_address_and_public_key_no_confirm(backend: BackendInterface) -> None:
    client = AlgorandCommandSender(backend)
    account_id = 123
    expected_public_key = (
        "0dfdbcdb8eebed628cfb4ef70207b86fd0deddca78e90e8c59d6f441e383b377"
    )
    response = client.get_address_and_public_key(account_id=account_id).data

    _, public_key, _, _ = unpack_get_public_key_response(response)
    assert public_key.hex() == expected_public_key


# In this test we check that the get_address_and_public_key works in confirmation mode
def test_get_address_and_public_key_confirm_accepted(
    backend: BackendInterface,
    scenario_navigator: NavigateWithScenario,
    device: Device,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    client = AlgorandCommandSender(backend)
    account_id = 123
    expected_public_key = (
        "0dfdbcdb8eebed628cfb4ef70207b86fd0deddca78e90e8c59d6f441e383b377"
    )
    expected_address = "BX63ZW4O5PWWFDH3J33QEB5YN7IN5XOKPDUQ5DCZ232EDY4DWN3XKUQRCA"

    with client.get_address_and_public_key_with_confirmation(account_id=account_id) as response:
        if not device.is_nano:
            scenario_navigator.address_review_approve()
        else:
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "APPROVE",
                default_screenshot_path,
                test_name,
            )

    response = client.get_async_response().data
    _, public_key, _, address = unpack_get_public_key_response(response)

    assert public_key.hex() == expected_public_key
    assert address.decode("ascii") == expected_address


# In this test we check that the get_address_and_public_key in confirmation mode replies an error if the user refuses
def test_get_address_and_public_key_confirm_refused(
    backend: BackendInterface,
    scenario_navigator: NavigateWithScenario,
    device: Device,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    client = AlgorandCommandSender(backend)
    account_id = 123

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_address_and_public_key_with_confirmation(account_id=account_id) as response:
            if not device.is_nano:
                scenario_navigator.address_review_reject()
            else:
                navigator.navigate_until_text_and_compare(
                    NavInsID.RIGHT_CLICK,
                    [NavInsID.BOTH_CLICK],
                    "REJECT",
                    default_screenshot_path,
                    test_name,
                )

    assert e.value.status == Errors.SW_COMMAND_NOT_ALLOWED_EF
    assert len(e.value.data) == 0
