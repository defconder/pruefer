import base64
import hashlib
import re
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GEDANKENSTRICH = "\u2014"
TYP_ED25519 = 0x01
TYP_KOSIGNATUR = 0x04
MAX_BAUMGROESSE = 2**31 - 1


def sha256(daten):
    return hashlib.sha256(daten).digest()


def blatt_hash(ereignis_hash):
    return sha256(b"\x00" + ereignis_hash.encode("utf-8"))


def knoten_hash(links, rechts):
    return sha256(b"\x01" + links + rechts)


def groesste_potenz_unter(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def wurzel(blaetter):
    if len(blaetter) == 0:
        return sha256(b"")
    if len(blaetter) == 1:
        return blaetter[0]
    k = groesste_potenz_unter(len(blaetter))
    return knoten_hash(wurzel(blaetter[:k]), wurzel(blaetter[k:]))


def konsistenz_pruefen(alt_groesse, neu_groesse, alt_wurzel, neu_wurzel, beweis):
    if not (isinstance(alt_groesse, int) and isinstance(neu_groesse, int)):
        return False
    if alt_groesse < 0 or neu_groesse < 0 or neu_groesse > MAX_BAUMGROESSE or alt_groesse > neu_groesse:
        return False
    if len(beweis) > 64:
        return False
    if alt_groesse == 0:
        return len(beweis) == 0
    if alt_groesse == neu_groesse:
        return len(beweis) == 0 and alt_wurzel == neu_wurzel
    if len(beweis) == 0:
        return False
    try:
        pfad = [bytes.fromhex(p) for p in beweis]
    except ValueError:
        return False
    if any(len(p) != 32 for p in pfad):
        return False
    if alt_groesse & (alt_groesse - 1) == 0:
        pfad.insert(0, bytes.fromhex(alt_wurzel))
    fn = alt_groesse - 1
    sn = neu_groesse - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = pfad[0]
    for c in pfad[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = knoten_hash(c, fr)
            sr = knoten_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = knoten_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr.hex() == alt_wurzel and sr.hex() == neu_wurzel and sn == 0


def base64_streng(text):
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text) or len(text) % 4 != 0:
        raise ValueError("Ungültiges Base64.")
    roh = base64.b64decode(text, validate=True)
    if base64.b64encode(roh).decode("ascii") != text:
        raise ValueError("Base64 ist nicht kanonisch.")
    return roh


def schluessel_kennung(name, typ, oeffentlich):
    return sha256(name.encode("utf-8") + b"\n" + bytes([typ]) + oeffentlich)[:4]


def schluessel_lesen(text):
    roh = text.strip()
    erstes = roh.find("+")
    zweites = roh.find("+", erstes + 1) if erstes >= 0 else -1
    if erstes < 1 or zweites < 0:
        raise ValueError("Schlüssel hat nicht die Form Name+Kennung+Daten.")
    name, kennung_hex, daten = roh[:erstes], roh[erstes + 1:zweites], roh[zweites + 1:]
    if any(z.isspace() for z in name):
        raise ValueError("Ungültiger Schlüsselname.")
    bytes_ = base64_streng(daten)
    if len(bytes_) != 33 or bytes_[0] not in (TYP_ED25519, TYP_KOSIGNATUR):
        raise ValueError("Nur Ed25519-Schlüssel der Typen 1 und 4 werden unterstützt.")
    typ, oeffentlich = bytes_[0], bytes_[1:]
    if schluessel_kennung(name, typ, oeffentlich).hex() != kennung_hex:
        raise ValueError("Die Kennung passt nicht zum Schlüssel.")
    return {"name": name, "typ": typ, "oeffentlich": oeffentlich, "kennung": kennung_hex}


def notiz_lesen(text):
    trennung = text.rfind("\n\n")
    if trennung < 0:
        raise ValueError("Notiz hat keinen Signaturteil.")
    koerper = text[: trennung + 1]
    rest = text[trennung + 2:]
    if not rest.endswith("\n"):
        raise ValueError("Signaturzeilen müssen mit Zeilenumbruch enden.")
    for zeichen in koerper:
        if ord(zeichen) < 0x20 and zeichen != "\n":
            raise ValueError("Steuerzeichen im Text.")
    zeilen = rest[:-1].split("\n")
    if len(zeilen) == 0 or len(zeilen) > 32:
        raise ValueError("Anzahl der Signaturen ungültig.")
    signaturen = []
    for zeile in zeilen:
        if not zeile.startswith(GEDANKENSTRICH + " "):
            raise ValueError("Signaturzeile beginnt nicht mit dem Gedankenstrich.")
        teile = zeile[2:].split(" ")
        if len(teile) != 2:
            raise ValueError("Signaturzeile ist ungültig.")
        blob = base64_streng(teile[1])
        if len(blob) < 5:
            raise ValueError("Signatur zu kurz.")
        signaturen.append({"name": teile[0], "kennung": blob[:4].hex(), "wert": blob[4:]})
    return {"koerper": koerper, "signaturen": signaturen}


def pruefpunkt_lesen(koerper):
    if not koerper.endswith("\n"):
        raise ValueError("Prüfpunkt endet nicht mit Zeilenumbruch.")
    zeilen = koerper[:-1].split("\n")
    if len(zeilen) < 3 or any(z == "" for z in zeilen):
        raise ValueError("Prüfpunkt hat weniger als drei Zeilen.")
    origin, groesse_text, wurzel_text = zeilen[:3]
    if not re.fullmatch(r"0|[1-9][0-9]*", groesse_text):
        raise ValueError("Baumgröße ist keine Dezimalzahl.")
    wurzel_bytes = base64_streng(wurzel_text)
    if len(wurzel_bytes) != 32:
        raise ValueError("Wurzel hat nicht 32 Byte.")
    return {"origin": origin, "groesse": int(groesse_text), "wurzel": wurzel_bytes.hex(), "erweiterungen": zeilen[3:]}


def _ed25519(oeffentlich, nachricht, signatur):
    try:
        Ed25519PublicKey.from_public_bytes(oeffentlich).verify(signatur, nachricht)
        return True
    except (InvalidSignature, ValueError):
        return False


def signaturen_pruefen(notiz, vertraute):
    bekannt = {(v["name"], v["kennung"]): v for v in vertraute}
    gueltig, fehlerhaft, gesehen = [], [], set()
    for s in notiz["signaturen"]:
        schluessel = bekannt.get((s["name"], s["kennung"]))
        if schluessel is None:
            continue
        schluessel_id = (s["name"], s["kennung"])
        if schluessel_id in gesehen:
            fehlerhaft.append(s["name"])
            continue
        gesehen.add(schluessel_id)
        if schluessel["typ"] == TYP_ED25519:
            ok = len(s["wert"]) == 64 and _ed25519(schluessel["oeffentlich"], notiz["koerper"].encode("utf-8"), s["wert"])
            (gueltig if ok else fehlerhaft).append(s["name"])
        elif schluessel["typ"] == TYP_KOSIGNATUR:
            if len(s["wert"]) != 72:
                fehlerhaft.append(s["name"])
                continue
            zeit = struct.unpack(">Q", s["wert"][:8])[0]
            nachricht = f"cosignature/v1\ntime {zeit}\n{notiz['koerper']}".encode("utf-8")
            ok = _ed25519(schluessel["oeffentlich"], nachricht, s["wert"][8:])
            (gueltig if ok else fehlerhaft).append(s["name"])
    return {"gueltig": gueltig, "fehlerhaft": fehlerhaft}


def pruefpunkt_pruefen(text, log_schluessel, zeugen, schwelle):
    try:
        notiz = notiz_lesen(text)
        punkt = pruefpunkt_lesen(notiz["koerper"])
    except ValueError as fehler:
        return {"lesbar": False, "bestanden": False, "fehler": str(fehler), "punkt": None, "zeugen_gueltig": 0}
    log = schluessel_lesen(log_schluessel)
    log_sig = signaturen_pruefen(notiz, [log])
    log_ok = log["typ"] == TYP_ED25519 and log["name"] == punkt["origin"] and len(log_sig["gueltig"]) == 1 and not log_sig["fehlerhaft"]
    zeugen_schluessel = [z for z in (schluessel_lesen(t) for t in zeugen) if z["typ"] == TYP_KOSIGNATUR]
    zeugen_sig = signaturen_pruefen(notiz, zeugen_schluessel)
    zeugen_ok = len(zeugen_sig["gueltig"]) >= schwelle > 0 and not zeugen_sig["fehlerhaft"]
    return {"lesbar": True, "bestanden": log_ok and zeugen_ok, "log_gueltig": log_ok, "punkt": punkt, "zeugen_gueltig": len(zeugen_sig["gueltig"])}


def einschluss_pruefen(index, groesse, blatt, pfad, wurzel_hex):
    if not (isinstance(index, int) and isinstance(groesse, int)) or index < 0 or index >= groesse or groesse > MAX_BAUMGROESSE:
        return False
    if not isinstance(pfad, list) or len(pfad) > 64:
        return False
    fn = index
    sn = groesse - 1
    r = blatt
    for p in pfad:
        if sn == 0:
            return False
        try:
            geschwister = bytes.fromhex(p)
        except (ValueError, TypeError):
            return False
        if len(geschwister) != 32:
            return False
        if fn & 1 or fn == sn:
            r = knoten_hash(geschwister, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = knoten_hash(r, geschwister)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == wurzel_hex


def blatt_aus_daten(daten):
    return sha256(b"\x00" + daten)
