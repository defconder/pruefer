import hashlib
import re

from ereignis import ereignis_hash_pruefen
from pruefpunkt import TYP_ED25519, base64_streng, blatt_aus_daten, blatt_hash, einschluss_pruefen, notiz_lesen, pruefpunkt_lesen, schluessel_lesen, signaturen_pruefen, wurzel

INDEXREGELN = "indexregeln-1"
INDEXZEILE = "defconder-index-1"
SCHLUESSELFELDER = ["id", "recordId", "userId", "actorId", "createdBy", "executedBy", "publishedBy", "deletedBy", "uploadedBy", "approvedBy", "sha256", "assetId", "entityTypeId", "actionTypeId", "objectId", "username", "purposeId", "apiKeyId"]
NULL32 = bytes(32)
EINS32 = bytes([255]) * 32


def schluessel_von(ereignis):
    menge = []
    if isinstance(ereignis.get("type"), str):
        menge.append(f"typ={ereignis['type']}")
    for feld in SCHLUESSELFELDER:
        wert = ereignis.get(feld)
        if isinstance(wert, str) and 1 <= len(wert) <= 200:
            for s in (f"{feld}={wert}", f"{ereignis['type']}|{feld}={wert}"):
                if s not in menge:
                    menge.append(s)
    return menge


def schluessel_hash(schluessel):
    return hashlib.sha256(f"{INDEXREGELN}\n{schluessel}".encode("utf-8")).digest()


def kette_plus(kette, ereignis_hash_hex):
    return hashlib.sha256(kette + bytes.fromhex(ereignis_hash_hex)).digest()


def blatt_daten(key_hash, anzahl, kette):
    return key_hash + anzahl.to_bytes(8, "big") + kette


def index_aufbauen(ereignisse):
    tabelle = {}
    for e in ereignisse:
        for s in schluessel_von(e):
            anzahl, kette = tabelle.get(s, (0, NULL32))
            tabelle[s] = (anzahl + 1, kette_plus(kette, e["hash"]))
    zeilen = [(schluessel_hash(s), a, k) for s, (a, k) in tabelle.items()]
    zeilen.append((NULL32, 0, NULL32))
    zeilen.append((EINS32, 0, NULL32))
    zeilen.sort(key=lambda z: z[0])
    blaetter = [blatt_aus_daten(blatt_daten(*z)) for z in zeilen]
    return {"wurzel": wurzel(blaetter).hex(), "anzahl": len(zeilen)}


def index_zeile_lesen(erweiterungen):
    zeilen = [z for z in erweiterungen if z.startswith(INDEXZEILE + " ")]
    if len(zeilen) != 1:
        raise ValueError("Keine oder mehrere Indexzeilen.")
    teile = zeilen[0].split(" ")
    if len(teile) != 3 or not re.fullmatch(r"0|[1-9][0-9]*", teile[1]):
        raise ValueError("Ungültige Indexzeile.")
    anzahl = int(teile[1])
    wurzel_bytes = base64_streng(teile[2])
    if anzahl < 2 or len(wurzel_bytes) != 32:
        raise ValueError("Ungültige Indexzeile.")
    return {"anzahl": anzahl, "wurzel": wurzel_bytes.hex()}


def _hex64(text):
    return isinstance(text, str) and re.fullmatch(r"[0-9a-f]{64}", text) is not None


def _blatt_pruefen(b, anzahl_blaetter, wurzel_hex):
    try:
        if not (_hex64(b["keyHash"]) and _hex64(b["kette"]) and isinstance(b["anzahl"], int) and not isinstance(b["anzahl"], bool) and b["anzahl"] >= 0 and isinstance(b["index"], int) and isinstance(b["pfad"], list)):
            return False
        blatt = blatt_aus_daten(blatt_daten(bytes.fromhex(b["keyHash"]), b["anzahl"], bytes.fromhex(b["kette"])))
        return einschluss_pruefen(b["index"], anzahl_blaetter, blatt, b["pfad"], wurzel_hex)
    except (KeyError, TypeError, ValueError):
        return False


def aussage_pruefen(doc, log_schluessel, zeugen, schwelle):
    try:
        if doc.get("schema") != "defconder-aussage-1" or doc.get("regeln") != INDEXREGELN:
            return {"ok": False}
        notiz = notiz_lesen(doc["notiz"])
        punkt = pruefpunkt_lesen(notiz["koerper"])
        log = schluessel_lesen(log_schluessel)
        sig = signaturen_pruefen(notiz, [log])
        if not (log["typ"] == TYP_ED25519 and log["name"] == punkt["origin"] and len(sig["gueltig"]) == 1 and not sig["fehlerhaft"]):
            return {"ok": False}
        zeugen_schluessel = [schluessel_lesen(z) for z in zeugen]
        zeugen_sig = signaturen_pruefen(notiz, zeugen_schluessel)
        index = index_zeile_lesen(punkt["erweiterungen"])
        ergebnisse = []
        for a in doc["aussagen"]:
            schluessel = a["schluessel"]
            k = schluessel_hash(schluessel).hex()
            if a["art"] == "vorhanden":
                ok = _blatt_pruefen({"keyHash": k, "anzahl": a["anzahl"], "kette": a["kette"], "index": a["index"], "pfad": a["pfad"]}, index["anzahl"], index["wurzel"]) and a["anzahl"] >= 1
                if ok and "ereignisse" in a:
                    liste = a["ereignisse"]
                    ok = isinstance(liste, list) and len(liste) == a["anzahl"] and all(_hex64(h) for h in liste) and len(set(liste)) == len(liste)
                    if ok:
                        kette = NULL32
                        for h in liste:
                            kette = kette_plus(kette, h)
                        ok = kette.hex() == a["kette"]
                    if ok and "belege" in a:
                        letzte = -1
                        for h, b in zip(liste, a["belege"]):
                            if b["seq"] <= letzte or b["seq"] >= punkt["groesse"] or not einschluss_pruefen(b["seq"], punkt["groesse"], blatt_hash(h), b["pfad"], punkt["wurzel"]):
                                ok = False
                                break
                            letzte = b["seq"]
                ergebnisse.append({"art": "vorhanden", "ok": ok, "anzahl": a["anzahl"]})
            elif a["art"] == "abwesend":
                links, rechts = a["links"], a["rechts"]
                ok = _blatt_pruefen(links, index["anzahl"], index["wurzel"]) and _blatt_pruefen(rechts, index["anzahl"], index["wurzel"]) and rechts["index"] == links["index"] + 1 and links["keyHash"] < k < rechts["keyHash"]
                ergebnisse.append({"art": "abwesend", "ok": ok})
            else:
                ergebnisse.append({"art": "unbekannt", "ok": False})
        alle = all(e["ok"] for e in ergebnisse)
        zeugen_ok = len(zeugen_sig["gueltig"]) >= schwelle > 0 and not zeugen_sig["fehlerhaft"]
        ok = alle and (len(zeugen_schluessel) == 0 or zeugen_ok)
        return {"ok": ok, "stufe": 2 if ok and zeugen_ok else 1 if ok else 0, "aussagen": ergebnisse, "groesse": punkt["groesse"]}
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"ok": False}


def kette_pruefen(ereignisse, genesis):
    vorher = genesis
    for i, e in enumerate(ereignisse):
        if e.get("seq") != i or e.get("prevHash") != vorher or not ereignis_hash_pruefen(e):
            return False
        vorher = e["hash"]
    return True
