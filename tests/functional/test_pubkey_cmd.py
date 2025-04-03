from ragger.backend import SpeculosBackend
from ragger.backend.interface import RaisePolicy
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.navigator import NavInsID, NavIns
from ragger.error import ExceptionRAPDU

from apps.zilliqa import ZilliqaClient, ErrorType
from utils import ROOT_SCREENSHOT_PATH

ZILLIQA_KEY_INDEX = 1


def check_get_public_key_resp(backend, key_index, public_key):
    if isinstance(backend, SpeculosBackend):
        path = "44'/313'/{}'/0'/0'".format(key_index)
        ref_public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1,
                                                               path,
                                                               compress_public_key=True)
        # Check against nominal Speculos seed expected results
        assert public_key.hex() == ref_public_key


def test_get_public_key_show_addr_accepted(firmware, backend, navigator, test_name, scenario_navigator):
    client = ZilliqaClient(backend)
    with client.send_async_get_public_key(ZILLIQA_KEY_INDEX, True):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Approve",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        else:
            scenario_navigator.address_review_approve(ROOT_SCREENSHOT_PATH, test_name)
    response = client.get_async_response().data
    public_key, _ = client.parse_get_public_key_response(response)
    check_get_public_key_resp(backend, ZILLIQA_KEY_INDEX, public_key)


def test_get_public_key_show_key_accepted(firmware, backend, navigator, test_name, scenario_navigator):
    client = ZilliqaClient(backend)
    with client.send_async_get_public_key(ZILLIQA_KEY_INDEX, False):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Approve",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        else:
            scenario_navigator.address_review_approve(ROOT_SCREENSHOT_PATH, test_name)
    response = client.get_async_response().data
    public_key, _ = client.parse_get_public_key_response(response)
    check_get_public_key_resp(backend, ZILLIQA_KEY_INDEX, public_key)


def test_get_public_key_silent(backend, navigator, test_name):
    client = ZilliqaClient(backend)
    response = client.send_get_public_key_non_confirm(ZILLIQA_KEY_INDEX)
    public_key, _ = client.parse_get_public_key_response(response.data)
    check_get_public_key_resp(backend, ZILLIQA_KEY_INDEX, public_key)


def test_get_public_key_show_addr_refused(firmware, backend, navigator, test_name, scenario_navigator):
    client = ZilliqaClient(backend)
    if firmware.device.startswith("nano"):
        with client.send_async_get_public_key(ZILLIQA_KEY_INDEX, True):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                      [NavInsID.BOTH_CLICK],
                                                      "Reject",
                                                      ROOT_SCREENSHOT_PATH,
                                                      test_name)
        rapdu = client.get_async_response()
        assert rapdu.status == ErrorType.SW_USER_REJECTED
        assert len(rapdu.data) == 0
    else:
        try:
            with client.send_async_get_public_key(ZILLIQA_KEY_INDEX, True):
                scenario_navigator.address_review_reject(ROOT_SCREENSHOT_PATH)
        except ExceptionRAPDU as e:
            assert e.status == ErrorType.SW_USER_REJECTED

