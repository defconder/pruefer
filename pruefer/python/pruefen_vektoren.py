import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anker import bitcoin_kopf_pruefen
from aussage import aussage_pruefen, index_aufbauen, kette_pruefen
from ereignis import auszug_pruefen, ereignis_hash_pruefen
from pruefpunkt import blatt_hash, konsistenz_pruefen, pruefpunkt_pruefen, wurzel
from regeln import beleg_pruefen

pfad = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testvektoren", "testvektoren.json")
with open(pfad, encoding="utf-8") as datei:
    vektoren = json.load(datei)

fehler = 0


def pruefe(name, bedingung, detail=""):
    global fehler
    if not bedingung:
        fehler += 1
        print(f"FEHLER {name} {detail}")


blaetter = [blatt_hash(h) for h in vektoren["merkle"]["blaetter"]]
for groesse, erwartet in vektoren["merkle"]["wurzeln"].items():
    pruefe(f"Wurzel für Größe {groesse}", wurzel(blaetter[: int(groesse)]).hex() == erwartet)

for v in vektoren["merkle"]["konsistenz"]:
    ok = konsistenz_pruefen(v["alt"], v["neu"], vektoren["merkle"]["wurzeln"][str(v["alt"])], vektoren["merkle"]["wurzeln"][str(v["neu"])], v["pfad"])
    pruefe(f"Konsistenz {v['alt']} nach {v['neu']}", ok)

for f in vektoren["notizen"]["faelle"]:
    r = pruefpunkt_pruefen(f["text"], vektoren["notizen"]["logSchluessel"], vektoren["notizen"]["zeugen"], f["schwelle"])
    if f["erwartet"].get("lesbar") is False:
        pruefe(f"Prüfpunkt \"{f['name']}\" wird als unlesbar abgelehnt", r["lesbar"] is False)
        continue
    pruefe(f"Prüfpunkt \"{f['name']}\": Ergebnis", r["bestanden"] == f["erwartet"]["bestanden"], str(r))
    pruefe(f"Prüfpunkt \"{f['name']}\": Baumgröße", r["punkt"]["groesse"] == f["erwartet"]["groesse"])
    if f["erwartet"]["logGueltig"]:
        pruefe(f"Prüfpunkt \"{f['name']}\": Zahl der gültigen Zeugen", r["zeugen_gueltig"] == f["erwartet"]["zeugenGueltig"], str(r["zeugen_gueltig"]))

zusaetze = 0
if "ereignis" in vektoren:
    for f in vektoren["ereignis"]["faelle"]:
        pruefe(f"Ereignis \"{f['name']}\"", ereignis_hash_pruefen(f["event"]) == f["erwartet"])
        zusaetze += 1
    for f in vektoren["ereignis"]["auszuege"]:
        r = auszug_pruefen(f["auszug"])
        pruefe(f"Auszug \"{f['name']}\": Ergebnis", (r is not None) == f["erwartet"]["ok"])
        if f["erwartet"]["ok"] and r is not None:
            pruefe(f"Auszug \"{f['name']}\": Prüfsumme", r["hash"] == f["erwartet"]["hash"])
            pruefe(f"Auszug \"{f['name']}\": offene Felder", sorted(r["offene"]) == f["erwartet"]["offene"])
            pruefe(f"Auszug \"{f['name']}\": verdeckte Felder", r["verdeckt"] == f["erwartet"]["verdeckt"])
        zusaetze += 1
    pruefe("Kette der Ereignisse", kette_pruefen(vektoren["aussage"]["ereignisse"], "0" * 64))
    index = index_aufbauen(vektoren["aussage"]["ereignisse"])
    pruefe("Indexwurzel über die Ereignisse", index["wurzel"] == vektoren["aussage"]["indexWurzel"], index["wurzel"])
    pruefe("Zahl der Indexeinträge", index["anzahl"] == vektoren["aussage"]["indexAnzahl"])
    for f in vektoren["aussage"]["faelle"]:
        r = aussage_pruefen(f["doc"], vektoren["aussage"]["logSchluessel"], vektoren["aussage"]["zeugen"], f["schwelle"])
        pruefe(f"Aussage \"{f['name']}\": Ergebnis", r["ok"] == f["erwartet"]["ok"], str(r))
        if f["erwartet"]["ok"] and r["ok"]:
            pruefe(f"Aussage \"{f['name']}\": Stufe", r["stufe"] == f["erwartet"]["stufe"], str(r["stufe"]))
            anzahlen = [a["anzahl"] if a["art"] == "vorhanden" else None for a in r["aussagen"]]
            pruefe(f"Aussage \"{f['name']}\": Anzahlen", anzahlen == f["erwartet"]["anzahlen"])
        zusaetze += 1
    for f in vektoren["anker"]:
        r = bitcoin_kopf_pruefen(f["kopf"], f["mindestarbeit"])
        pruefe(f"Zeitanker \"{f['name']}\": Ergebnis", r["ok"] == f["erwartet"]["ok"])
        if f["erwartet"]["ok"]:
            pruefe(f"Zeitanker \"{f['name']}\": Blockprüfsumme", r.get("block_hash") == f["erwartet"]["blockHash"])
            pruefe(f"Zeitanker \"{f['name']}\": Blockzeit", r.get("block_zeit") == f["erwartet"]["blockZeit"])
            pruefe(f"Zeitanker \"{f['name']}\": Arbeit", r.get("arbeit_bits") == f["erwartet"]["arbeitBits"])
        zusaetze += 1
    for f in vektoren["regeln"]["belege"]:
        pruefe(f"Beleg \"{f['name']}\"", beleg_pruefen(f["beleg"], vektoren["regeln"]["regelstaende"]) == f["erwartet"])
        zusaetze += 1

print(f"Alle Testvektoren bestanden ({zusaetze} Vektoren zu Ereignissen, Auszügen, Aussagen, Zeitankern und Belegen)." if fehler == 0 else f"{fehler} Abweichung(en).")
sys.exit(0 if fehler == 0 else 1)
