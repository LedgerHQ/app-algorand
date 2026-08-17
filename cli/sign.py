#!/usr/bin/env python

import base64
import struct
import sys

import algomsgpack
import ed25519
import msgpack
import sha512_256
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException


def checksummed(pk):
    checksum = sha512_256.new(bytes(pk)).digest()
    return base64.b32encode(bytes(pk) + checksum[28:32]).replace(b"=", b"").decode("ascii")


dongle = getDongle(debug=False)

publicKey = dongle.exchange(bytes.fromhex("8003000000"))
print("Ledger app address:", checksummed(publicKey))

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} infile outfile")
    sys.exit(0)

(_, infile, outfile) = sys.argv

with open(infile) as f:
    buf = f.read()
    instx = msgpack.unpackb(buf, raw=False)
    intx = instx["txn"]

try:
    txbytes = algomsgpack.encoded(intx)

    tosend = txbytes

    p1 = 0
    p2 = 0x80
    while p2 == 0x80:
        thischunk = tosend[:250]
        if len(thischunk) == len(tosend):
            p2 = 0

        # CLA, INS_SIGN_MSGPACK, P1, P2, LC
        apdu = b"\x80\x08"
        apdu += struct.pack("B", p1)
        apdu += struct.pack("B", p2)
        apdu += struct.pack("B", len(thischunk))
        apdu += thischunk.encode() if isinstance(thischunk, str) else thischunk

        signature = dongle.exchange(apdu)

        tosend = tosend[len(thischunk) :]
        p1 = 0x80

    if len(signature) > 64:
        raise Exception(f"Error: {signature[65:]}")

    print("signature " + bytes(signature).hex())

    txbytes_bytes = txbytes.encode() if isinstance(txbytes, str) else txbytes
    ed25519.checkvalid(bytes(signature), b"TX" + txbytes_bytes, bytes(publicKey))
    print("Verified signature")

    foundMsig = False
    msig = instx.get("msig")
    if msig is not None:
        if msig.get("v") != 1:
            print(f"Unknown multisig version {msig['v']}, not filling in multisig")
        for sub in msig["subsig"]:
            if sub["pk"] == publicKey:
                sub["s"] = signature
                foundMsig = True
    if not foundMsig:
        instx["sig"] = signature

    encoded = algomsgpack.encoded(instx)
    with open(outfile, "wb") as f:
        f.write(encoded.encode() if isinstance(encoded, str) else encoded)
        print(f"Wrote signed transaction to {outfile}")

except CommException as comm:
    if comm.sw == 0x6985:
        print("Aborted by user")
    else:
        print(comm)
