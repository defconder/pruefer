import hashlib
import math

SCHEMA = "defconder-stichprobe-1"
MAX_ZIEHUNGEN = 100000


def ziehen(wurzel_hex, groesse, beacon_hex, anzahl):
    if groesse < 1 or anzahl < 1 or anzahl > MAX_ZIEHUNGEN:
        raise ValueError("Ungültige Angaben zur Ziehung.")
    saat = hashlib.sha256(
        (SCHEMA + "\x00").encode("utf-8") + bytes.fromhex(wurzel_hex) + bytes.fromhex(beacon_hex) + groesse.to_bytes(8, "big") + anzahl.to_bytes(8, "big")
    ).digest()
    grenze = (2**64 // groesse) * groesse
    ergebnis = []
    zaehler = 0
    while len(ergebnis) < anzahl:
        roh = hashlib.sha256(saat + zaehler.to_bytes(8, "big")).digest()
        zaehler += 1
        wert = int.from_bytes(roh[:8], "big")
        if wert >= grenze:
            continue
        ergebnis.append(wert % groesse)
    return ergebnis


def obergrenze(anzahl, konfidenz):
    return 1 - math.exp(math.log(1 - konfidenz) / anzahl)
