import hashlib

from ereignis import kanonisch


def regelstand_hash(regel):
    return hashlib.sha256(kanonisch(regel).encode("utf-8")).hexdigest()


def regel_auswerten(regel, eingaben):
    if regel["sprache"] != "regeln-1":
        raise ValueError("Unbekannte Regelsprache.")
    if regel["art"] == "stufen":
        toene = {s["ton"] for s in regel["stufen"]}
        if eingaben["nutzer"] not in toene or eingaben["objekt"] not in toene:
            raise ValueError("Unbekannte Stufe.")
        abstand = max(0, eingaben["nutzer"] - eingaben["objekt"])
        return {"ergebnis": "erlaubt" if abstand == 0 else "verweigert", "abstand": abstand}
    if regel["art"] == "matrix":
        kategorie = eingaben.get("kategorie")
        if kategorie in (None, "") or kategorie in regel.get("immerErlaubt", []):
            return {"ergebnis": "erlaubt"}
        return {"ergebnis": "erlaubt" if kategorie in regel["erlaubt"].get(eingaben["zweck"], []) else "verweigert"}
    raise ValueError("Unbekannte Art der Regel.")


def beleg_pruefen(beleg, regelstaende):
    try:
        regel = regelstaende[beleg["regelstand"]]
        if regelstand_hash(regel) != beleg["regelstand"] or regel["id"] != beleg["regel"]:
            return False
        r = regel_auswerten(regel, beleg["eingaben"])
        if r["ergebnis"] != beleg["ergebnis"]:
            return False
        return regel["art"] != "stufen" or r["abstand"] == beleg.get("abstand")
    except (KeyError, ValueError, TypeError):
        return False
