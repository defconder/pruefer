import hashlib
import json
import re

from pruefpunkt import blatt_aus_daten, wurzel

FELDNAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
SALZ = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
RESERVIERT = {"seq", "type", "at", "hv", "prevHash", "feldWurzel", "hash", "salze"}


def kanonisch(wert):
    if wert is None:
        return "null"
    if isinstance(wert, bool):
        return "true" if wert else "false"
    if isinstance(wert, int):
        return str(wert)
    if isinstance(wert, float):
        raise ValueError("Gleitkommazahlen werden in dieser Umsetzung nicht unterstützt.")
    if isinstance(wert, str):
        return json.dumps(wert, ensure_ascii=False)
    if isinstance(wert, list):
        return "[" + ",".join(kanonisch(w) for w in wert) + "]"
    if isinstance(wert, dict):
        schluessel = sorted(wert.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + kanonisch(wert[k]) for k in schluessel) + "}"
    raise ValueError("Nicht darstellbarer Wert.")


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def inhaltsnamen(ereignis):
    return sorted(k for k in ereignis if k not in RESERVIERT)


def feld_blatt(name, salz, wert):
    return blatt_aus_daten(kanonisch({"n": name, "s": salz, "w": wert}).encode("utf-8"))


def feld_wurzel(ereignis):
    namen = inhaltsnamen(ereignis)
    salze = ereignis.get("salze")
    if not isinstance(salze, dict) or sorted(salze.keys()) != namen:
        raise ValueError("Die Salze passen nicht zu den Feldern.")
    blaetter = []
    for name in namen:
        if not FELDNAME.match(name) or not isinstance(salze[name], str) or not SALZ.match(salze[name]):
            raise ValueError("Ungültiger Feldname oder ungültiges Salz.")
        blaetter.append(feld_blatt(name, salze[name], ereignis[name]))
    return wurzel(blaetter).hex()


def kopf_hash(vorgaenger, kopf):
    return sha256_hex(vorgaenger + kanonisch(kopf))


def ereignis_hash_pruefen(ereignis):
    try:
        basis = {k: v for k, v in ereignis.items() if k != "hash"}
        if "hv" not in basis:
            berechnet = sha256_hex(basis["prevHash"] + json.dumps(basis, separators=(",", ":"), ensure_ascii=False))
        elif basis["hv"] == 2:
            if feld_wurzel(basis) != basis.get("feldWurzel"):
                return False
            kopf = {k: basis[k] for k in ("seq", "type", "at", "hv", "prevHash", "feldWurzel")}
            berechnet = kopf_hash(basis["prevHash"], kopf)
        else:
            return False
        return berechnet == ereignis["hash"]
    except (KeyError, ValueError, TypeError):
        return False


def auszug_pruefen(auszug):
    try:
        if auszug.get("schema") != "defconder-auszug-1":
            return None
        k = auszug["kopf"]
        if k.get("hv") != 2:
            return None
        blaetter = []
        offene = []
        letzter = None
        for b in auszug["blaetter"]:
            if isinstance(b.get("h"), str):
                if not re.fullmatch(r"[0-9a-f]{64}", b["h"]):
                    return None
                blaetter.append(bytes.fromhex(b["h"]))
                continue
            name, salz = b.get("n"), b.get("s")
            if not isinstance(name, str) or not FELDNAME.match(name) or name in RESERVIERT or not isinstance(salz, str) or not SALZ.match(salz) or "w" not in b:
                return None
            if letzter is not None and not name > letzter:
                return None
            letzter = name
            blaetter.append(feld_blatt(name, salz, b["w"]))
            offene.append(name)
        if wurzel(blaetter).hex() != k["feldWurzel"]:
            return None
        kopf = {x: k[x] for x in ("seq", "type", "at", "hv", "prevHash", "feldWurzel")}
        if kopf_hash(k["prevHash"], kopf) != k["hash"]:
            return None
        return {"hash": k["hash"], "offene": offene, "verdeckt": len(blaetter) - len(offene)}
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
