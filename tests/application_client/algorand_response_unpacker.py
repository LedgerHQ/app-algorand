from typing import Tuple
from struct import unpack


# Unpack from response:
# response = test_mode (1)
#            MAJOR (2)
#            MINOR (2)
#            PATCH (2)
#            locked (1)
#            target_id (4)
def unpack_get_version_response(response: bytes) -> Tuple[int, int, int, int, int, int]:
    assert len(response) == 12  # 000002000500070033000004
    # Format: >B = test (1 byte),
    #         HHH = major/minor/patch (3x 2-byte big-endian),
    #         B = locked (1 byte),
    #         I = target_id (4-byte big-endian)
    test_mode, major, minor, patch, locked, target_id = unpack(">BHHHBI", response)
    return (test_mode, major, minor, patch, locked, target_id)


# Unpack from response:
# response = pub_key_len (1)
#            pub_key (var)
#            chain_code_len (1)
#            chain_code (var)
def unpack_get_public_key_response(response: bytes) -> Tuple[int, bytes, int, bytes]:

    PUBKEY_LEN = 32
    ADDRESS_LEN = 58
    pubkey = response[:PUBKEY_LEN]

    address = response[PUBKEY_LEN : PUBKEY_LEN + ADDRESS_LEN]

    return PUBKEY_LEN, pubkey, ADDRESS_LEN, address
