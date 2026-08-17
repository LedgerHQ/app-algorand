## Canonical msgpack encoding used by Algorand

import struct

FIXINT_0 = 0x00
FIXINT_127 = 0x7F
FIXMAP_0 = 0x80
FIXMAP_15 = 0x8F
FIXARR_0 = 0x90
FIXARR_15 = 0x9F
FIXSTR_0 = 0xA0
FIXSTR_31 = 0xBF
BIN8 = 0xC4
UINT8 = 0xCC
UINT16 = 0xCD
UINT32 = 0xCE
UINT64 = 0xCF
STR8 = 0xD9
ARR16 = 0xDC
ARR32 = 0xDD


def encode_str(buf, s):
    n = len(s)
    if n <= FIXSTR_31 - FIXSTR_0:
        buf.append(chr(FIXSTR_0 + n))
        buf.extend(s)
        return

    if n < (1 << 8):
        buf.append(chr(STR8))
        buf.append(chr(n))
        buf.extend(s)
        return

    raise Exception(f"String {s} too long")


def encode_uint(buf, i):
    if i <= FIXINT_127 - FIXINT_0:
        buf.append(chr(FIXINT_0 + i))
        return

    if i < (1 << 8):
        buf.append(chr(UINT8))
        buf.extend(struct.pack(">B", i))
        return

    if i < (1 << 16):
        buf.append(chr(UINT16))
        buf.extend(struct.pack(">H", i))
        return

    if i < (1 << 32):
        buf.append(chr(UINT32))
        buf.extend(struct.pack(">L", i))
        return

    if i < (1 << 64):
        buf.append(chr(UINT64))
        buf.extend(struct.pack(">Q", i))
        return

    raise Exception(f"Integer {i} too big")


def encode_bin(buf, b):
    n = len(b)
    if n < (1 << 8):
        buf.append(chr(BIN8))
        buf.append(chr(n))
        buf.extend(b)
        return

    raise Exception(f"Binary {b} too long")


def is_zero(v):
    if isinstance(v, int):
        return v == 0

    if isinstance(v, str):
        return v == ""

    if isinstance(v, dict):
        return all(is_zero(vv) for k, vv in v.items())

    if isinstance(v, bytearray):
        return all(b == 0 for b in v)

    if isinstance(v, list):
        return len(v) == 0

    raise Exception(f"is_zero: unknown type {type(v)} for {v}")


def encode(buf, x):
    if isinstance(x, int) and x >= 0:
        encode_uint(buf, x)
    elif isinstance(x, bytes):
        encode_bin(buf, x)
    elif isinstance(x, bytearray):
        encode_bin(buf, [chr(b) for b in x])
    elif isinstance(x, str):
        encode_str(buf, x.encode("ascii"))
    elif isinstance(x, dict):
        tmpbuf = []
        count = 0
        for k, v in sorted(x.items()):
            if is_zero(v):
                continue
            count += 1
            encode(tmpbuf, k)
            encode(tmpbuf, v)
        if count <= FIXMAP_15 - FIXMAP_0:
            buf.append(chr(FIXMAP_0 + count))
            buf.extend(tmpbuf)
        else:
            raise Exception(f"Too many map entries ({count}) in {x}")
    elif isinstance(x, list):
        count = len(x)
        if count <= FIXARR_15 - FIXARR_0:
            buf.append(chr(FIXARR_0 + count))
        elif count < 2**16:
            buf.append(chr(ARR16))
            buf.extend(struct.pack(">H", count))
        elif count < 2**32:
            buf.append(chr(ARR32))
            buf.extend(struct.pack(">L", count))
        else:
            raise Exception(f"Too many list entries ({count}) in {x}")
        for v in x:
            encode(buf, v)
    else:
        raise Exception(f"encode: unknown type {type(x)}")


def encoded(x):
    buf = []
    encode(buf, x)
    return "".join(buf)
