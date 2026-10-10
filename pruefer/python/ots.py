import hashlib
import struct

MAGIE = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
AUSSTEHEND_TAG = bytes.fromhex("83dfe30d2ef90c8e")
MAX_NACHRICHT = 4096
MAX_KNOTEN = 20000
MAX_TIEFE = 256
MAX_DATEI = 1000000

R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
MASKE = 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASKE


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & MASKE & z)
    if j < 48:
        return (x | (~y & MASKE)) ^ z
    if j < 64:
        return (x & z) | (y & ~z & MASKE)
    return x ^ (y | (~z & MASKE))


def ripemd160(daten):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    laenge = len(daten)
    rest = laenge % 64
    auffuellung = 64 - rest if rest < 56 else 128 - rest
    voll = daten + b"\x80" + bytes(auffuellung - 9) + struct.pack("<Q", laenge * 8)
    for o in range(0, len(voll), 64):
        x = struct.unpack("<16I", voll[o:o + 64])
        a1, b1, c1, d1, e1 = h
        a2, b2, c2, d2, e2 = h
        for j in range(80):
            runde = j // 16
            t = (_rol((a1 + _f(j, b1, c1, d1) + x[R1[j]] + K1[runde]) & MASKE, S1[j]) + e1) & MASKE
            a1, e1, d1, c1, b1 = e1, d1, _rol(c1, 10), b1, t
            t = (_rol((a2 + _f(79 - j, b2, c2, d2) + x[R2[j]] + K2[runde]) & MASKE, S2[j]) + e2) & MASKE
            a2, e2, d2, c2, b2 = e2, d2, _rol(c2, 10), b2, t
        t = (h[1] + c1 + d2) & MASKE
        h[1] = (h[2] + d1 + e2) & MASKE
        h[2] = (h[3] + e1 + a2) & MASKE
        h[3] = (h[4] + a1 + b2) & MASKE
        h[4] = (h[0] + b1 + c2) & MASKE
        h[0] = t
    return struct.pack("<5I", *h)


class _Leser:
    def __init__(self, daten):
        self.b = daten
        self.pos = 0

    def byte(self):
        if self.pos >= len(self.b):
            raise ValueError("Die Datei endet zu früh.")
        wert = self.b[self.pos]
        self.pos += 1
        return wert

    def bytes(self, n):
        if n < 0 or self.pos + n > len(self.b):
            raise ValueError("Die Datei endet zu früh.")
        out = self.b[self.pos:self.pos + n]
        self.pos += n
        return out

    def varuint(self):
        wert = 0
        for i in range(5):
            x = self.byte()
            wert += (x & 0x7F) << (7 * i)
            if x & 0x80 == 0:
                return wert
        raise ValueError("Eine Längenangabe ist zu groß.")

    def varbytes(self, maximum, minimum=0):
        n = self.varuint()
        if n > maximum or n < minimum:
            raise ValueError("Eine Längenangabe liegt außerhalb des erlaubten Bereichs.")
        return self.bytes(n)

    def ende(self):
        return self.pos == len(self.b)


def _zweig(l, nachricht, tag, tiefe, attest, zaehler):
    zaehler[0] += 1
    if zaehler[0] > MAX_KNOTEN:
        raise ValueError("Der Beweis hat zu viele Knoten.")
    if tag == 0x00:
        art = l.bytes(8)
        nutzlast = l.varbytes(MAX_NACHRICHT)
        if art == BITCOIN_TAG:
            inneres = _Leser(nutzlast)
            hoehe = inneres.varuint()
            if not inneres.ende():
                raise ValueError("Die Bestätigung durch Bitcoin hat überzählige Bytes.")
            attest.append({"art": "bitcoin", "hoehe": hoehe, "nachricht": nachricht})
        elif art == AUSSTEHEND_TAG:
            attest.append({"art": "ausstehend"})
        else:
            attest.append({"art": "unbekannt"})
        return
    if tag == 0x08:
        neu = hashlib.sha256(nachricht).digest()
    elif tag == 0x03:
        neu = ripemd160(nachricht)
    elif tag == 0xF0:
        neu = nachricht + l.varbytes(MAX_NACHRICHT, 1)
    elif tag == 0xF1:
        neu = l.varbytes(MAX_NACHRICHT, 1) + nachricht
    elif tag == 0xF2:
        neu = nachricht[::-1]
    elif tag == 0xF3:
        neu = nachricht.hex().encode("ascii")
    else:
        raise ValueError("Unbekannte oder nicht unterstützte Operation.")
    if len(neu) > MAX_NACHRICHT or len(neu) == 0:
        raise ValueError("Eine Zwischennachricht ist zu lang.")
    _baum(l, neu, tiefe + 1, attest, zaehler)


def _baum(l, nachricht, tiefe, attest, zaehler):
    if tiefe > MAX_TIEFE:
        raise ValueError("Der Beweis ist zu tief verschachtelt.")
    tag = l.byte()
    while tag == 0xFF:
        _zweig(l, nachricht, l.byte(), tiefe, attest, zaehler)
        tag = l.byte()
    _zweig(l, nachricht, tag, tiefe, attest, zaehler)


def ots_auswerten(daten):
    if len(daten) > MAX_DATEI:
        raise ValueError("Der Beweis ist zu groß.")
    l = _Leser(daten)
    if l.bytes(len(MAGIE)) != MAGIE:
        raise ValueError("Das ist keine OpenTimestamps-Datei.")
    if l.varuint() != 1:
        raise ValueError("Unbekannte Hauptversion des Beweises.")
    if l.byte() != 0x08:
        raise ValueError("Der Beweis beginnt nicht mit einer SHA-256-Prüfsumme.")
    digest = l.bytes(32)
    attest = []
    _baum(l, digest, 0, attest, [0])
    if not l.ende():
        raise ValueError("Nach dem Beweis folgen weitere Daten.")
    return {"digest": digest, "attestierungen": attest}


def merkle_wurzel_aus_kopf(kopf_hex):
    return bytes.fromhex(kopf_hex)[36:68]
