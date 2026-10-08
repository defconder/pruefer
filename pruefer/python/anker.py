import hashlib
import re

ZWEI_STUNDEN_MS = 2 * 60 * 60 * 1000


def bitcoin_kopf_pruefen(kopf_hex, mindest_arbeit_bits=64):
    if not isinstance(kopf_hex, str) or not re.fullmatch(r"[0-9a-f]{160}", kopf_hex):
        return {"ok": False}
    kopf = bytes.fromhex(kopf_hex)
    zeit = int.from_bytes(kopf[68:72], "little")
    bits = int.from_bytes(kopf[72:76], "little")
    exponent = bits >> 24
    mantisse = bits & 0x007FFFFF
    if bits & 0x00800000 or mantisse == 0 or exponent < 3 or exponent > 32:
        return {"ok": False}
    ziel = mantisse * 256 ** (exponent - 3)
    if ziel >= 2**256:
        return {"ok": False}
    doppelt = hashlib.sha256(hashlib.sha256(kopf).digest()).digest()
    block_hash = doppelt[::-1].hex()
    if int(block_hash, 16) > ziel:
        return {"ok": False}
    arbeit_bits = (2**256 // (ziel + 1)).bit_length() - 1
    return {"ok": arbeit_bits >= mindest_arbeit_bits, "block_hash": block_hash, "block_zeit": zeit * 1000, "fruehestens": zeit * 1000 - ZWEI_STUNDEN_MS, "arbeit_bits": arbeit_bits}
