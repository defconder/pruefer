import hashlib
import hmac as _hmac

WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4

PARAMETER = {
    "sha2-128s": {"n": 16, "h": 63, "d": 7, "hp": 9, "a": 12, "k": 14, "lg_w": 4},
    "sha2-128f": {"n": 16, "h": 66, "d": 22, "hp": 3, "a": 6, "k": 33, "lg_w": 4},
}

KONTEXT = b"defconder-pruefpunkt-1"


def _sha256(daten):
    return hashlib.sha256(daten).digest()


def _ableiten(p):
    w = 1 << p["lg_w"]
    len1 = -(-8 * p["n"] // p["lg_w"])
    len2 = int.bit_length(len1 * (w - 1)) - 1
    len2 = len2 // p["lg_w"] + 1
    laenge = len1 + len2
    md_bytes = -(-p["k"] * p["a"] // 8)
    baum_bits = p["h"] - p["hp"]
    baum_bytes = -(-baum_bits // 8)
    blatt_bytes = -(-p["hp"] // 8)
    fors_bytes = p["k"] * (p["a"] + 1) * p["n"]
    xmss_bytes = (laenge + p["hp"]) * p["n"]
    g = dict(p)
    g.update(
        w=w, len1=len1, len2=len2, len=laenge, md_bytes=md_bytes, baum_bits=baum_bits, baum_bytes=baum_bytes,
        blatt_bytes=blatt_bytes, m=md_bytes + baum_bytes + blatt_bytes, fors_bytes=fors_bytes, xmss_bytes=xmss_bytes,
        signatur_bytes=p["n"] + fors_bytes + p["d"] * xmss_bytes, oeffentlich_bytes=2 * p["n"],
    )
    return g


def groessen(name):
    g = _ableiten(PARAMETER[name])
    return {"signatur": g["signatur_bytes"], "oeffentlich": g["oeffentlich_bytes"]}


def _mgf1(saat, laenge):
    out = b""
    zaehler = 0
    while len(out) < laenge:
        out += _sha256(saat + zaehler.to_bytes(4, "big"))
        zaehler += 1
    return out[:laenge]


def _base_2b(x, b, ausgabe):
    out = []
    pos = 0
    bits = 0
    summe = 0
    for _ in range(ausgabe):
        while bits < b:
            summe = (summe << 8) | x[pos]
            pos += 1
            bits += 8
        bits -= b
        out.append((summe >> bits) & ((1 << b) - 1))
        summe &= (1 << bits) - 1
    return out


def _set_baum(adrs, t):
    adrs[4:16] = t.to_bytes(12, "big")


def _set_typ(adrs, typ):
    adrs[16:20] = bytes([0, 0, 0, typ])
    adrs[20:32] = bytes(12)


def _wort(adrs, offset, v):
    adrs[offset:offset + 4] = v.to_bytes(4, "big")


def _get_paar(adrs):
    return int.from_bytes(adrs[20:24], "big")


def _komprimiert(adrs):
    return bytes([adrs[3]]) + bytes(adrs[8:16]) + bytes([adrs[19]]) + bytes(adrs[20:32])


class _Kontext:
    def __init__(self, g, pk_seed):
        self.n = g["n"]
        self.praefix = pk_seed + bytes(64 - g["n"])

    def th(self, adrs, m):
        return _sha256(self.praefix + _komprimiert(adrs) + m)[: self.n]


def _kette(c, x, i, s, adrs):
    tmp = x
    for j in range(i, i + s):
        _wort(adrs, 28, j)
        tmp = c.th(adrs, tmp)
    return tmp


def _wots_ziffern(g, m):
    msg = _base_2b(m, g["lg_w"], g["len1"])
    pruef = sum(g["w"] - 1 - z for z in msg)
    pruef <<= (8 - ((g["len2"] * g["lg_w"]) % 8)) % 8
    pruef_bytes = -(-g["len2"] * g["lg_w"] // 8)
    return msg + _base_2b(pruef.to_bytes(pruef_bytes, "big"), g["lg_w"], g["len2"])


def _wots_pk_aus_signatur(g, c, sig, m, adrs):
    ziffern = _wots_ziffern(g, m)
    teile = []
    n = g["n"]
    for i in range(g["len"]):
        _wort(adrs, 24, i)
        teile.append(_kette(c, sig[i * n:(i + 1) * n], ziffern[i], g["w"] - 1 - ziffern[i], adrs))
    wots_pk = bytearray(adrs)
    _set_typ(wots_pk, WOTS_PK)
    _wort(wots_pk, 20, _get_paar(adrs))
    return c.th(wots_pk, b"".join(teile))


def _xmss_pk_aus_signatur(g, c, idx, sig, m, adrs):
    n = g["n"]
    _set_typ(adrs, WOTS_HASH)
    _wort(adrs, 20, idx)
    knoten = _wots_pk_aus_signatur(g, c, sig[: g["len"] * n], m, adrs)
    _set_typ(adrs, TREE)
    baum_index = idx
    _wort(adrs, 28, baum_index)
    for k in range(g["hp"]):
        _wort(adrs, 24, k + 1)
        baum_index >>= 1
        _wort(adrs, 28, baum_index)
        nachbar = sig[(g["len"] + k) * n:(g["len"] + k + 1) * n]
        if ((idx >> k) & 1) == 0:
            knoten = c.th(adrs, knoten + nachbar)
        else:
            knoten = c.th(adrs, nachbar + knoten)
    return knoten


def _fors_pk_aus_signatur(g, c, sig, md, adrs):
    n = g["n"]
    indizes = _base_2b(md, g["a"], g["k"])
    wurzeln = []
    schritt = (g["a"] + 1) * n
    for i in range(g["k"]):
        teil = sig[i * schritt:(i + 1) * schritt]
        _wort(adrs, 24, 0)
        baum_index = i * (1 << g["a"]) + indizes[i]
        _wort(adrs, 28, baum_index)
        knoten = c.th(adrs, teil[:n])
        for j in range(g["a"]):
            _wort(adrs, 24, j + 1)
            baum_index >>= 1
            _wort(adrs, 28, baum_index)
            nachbar = teil[(j + 1) * n:(j + 2) * n]
            if ((indizes[i] >> j) & 1) == 0:
                knoten = c.th(adrs, knoten + nachbar)
            else:
                knoten = c.th(adrs, nachbar + knoten)
        wurzeln.append(knoten)
    fors_pk = bytearray(adrs)
    _set_typ(fors_pk, FORS_ROOTS)
    _wort(fors_pk, 20, _get_paar(adrs))
    return c.th(fors_pk, b"".join(wurzeln))


def pruefen(name, oeffentlich, nachricht, signatur, kontext=KONTEXT):
    try:
        g = _ableiten(PARAMETER[name])
        n = g["n"]
        if len(oeffentlich) != 2 * n or len(signatur) != g["signatur_bytes"] or len(kontext) > 255:
            return False
        pk_seed, pk_wurzel = oeffentlich[:n], oeffentlich[n:]
        c = _Kontext(g, pk_seed)
        m = bytes([0, len(kontext)]) + kontext + nachricht
        r = signatur[:n]
        fors_sig = signatur[n:n + g["fors_bytes"]]
        ht_sig = signatur[n + g["fors_bytes"]:]
        innen = _sha256(r + pk_seed + pk_wurzel + m)
        digest = _mgf1(r + pk_seed + innen, g["m"])
        md = digest[: g["md_bytes"]]
        baum = int.from_bytes(digest[g["md_bytes"]:g["md_bytes"] + g["baum_bytes"]], "big") & ((1 << g["baum_bits"]) - 1)
        blatt = int.from_bytes(digest[g["md_bytes"] + g["baum_bytes"]:g["md_bytes"] + g["baum_bytes"] + g["blatt_bytes"]], "big") % (1 << g["hp"])
        adrs = bytearray(32)
        _set_baum(adrs, baum)
        _set_typ(adrs, FORS_TREE)
        _wort(adrs, 20, blatt)
        fors_pk = _fors_pk_aus_signatur(g, c, fors_sig, md, adrs)
        adrs = bytearray(32)
        _set_baum(adrs, baum)
        knoten = _xmss_pk_aus_signatur(g, c, blatt, ht_sig[: g["xmss_bytes"]], fors_pk, adrs)
        for j in range(1, g["d"]):
            blatt = baum & ((1 << g["hp"]) - 1)
            baum >>= g["hp"]
            adrs[0:4] = bytes([0, 0, 0, j])
            _set_baum(adrs, baum)
            knoten = _xmss_pk_aus_signatur(g, c, blatt, ht_sig[j * g["xmss_bytes"]:(j + 1) * g["xmss_bytes"]], knoten, adrs)
        return _hmac.compare_digest(knoten, pk_wurzel)
    except (KeyError, ValueError, IndexError):
        return False
