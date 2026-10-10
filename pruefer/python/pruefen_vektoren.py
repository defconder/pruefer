import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anker import bitcoin_kopf_pruefen
from aussage import INDEXREGELN_2, aussage_pruefen, index_aufbauen, kette_pruefen, schluessel_von
from ereignis import auszug_pruefen, ereignis_hash_pruefen
from pruefpunkt import blatt_hash, konsistenz_pruefen, pruefpunkt_pruefen, wurzel
from regeln import beleg_pruefen
import slhdsa
import ots
import stichprobe

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

hashbasiert = 0
if "hashbasiert" in vektoren:
    for f in vektoren["hashbasiert"]["signaturen"]:
        oeffentlich = base64.b64decode(f["oeffentlich"])
        nachricht = bytes.fromhex(f["nachricht"])
        signatur = base64.b64decode(f["signatur"])
        kontext = f["kontext"].encode("utf-8")
        pruefe(f"Hashbasierte Signatur \"{f['name']}\"", slhdsa.pruefen(f["verfahren"], oeffentlich, nachricht, signatur, kontext) == f["erwartet"])
        if f["erwartet"]:
            for stelle in [0, 15, 16, 100, len(signatur) // 2, len(signatur) - 1]:
                kaputt = bytearray(signatur)
                kaputt[stelle] ^= 1
                pruefe(f"Hashbasierte Signatur \"{f['name']}\": Veränderung an Stelle {stelle} wird erkannt", slhdsa.pruefen(f["verfahren"], oeffentlich, nachricht, bytes(kaputt), kontext) is False)
            pruefe(f"Hashbasierte Signatur \"{f['name']}\": andere Nachricht wird erkannt", slhdsa.pruefen(f["verfahren"], oeffentlich, nachricht + b"\x01", signatur, kontext) is False)
            pruefe(f"Hashbasierte Signatur \"{f['name']}\": abgeschnittene Signatur wird erkannt", slhdsa.pruefen(f["verfahren"], oeffentlich, nachricht, signatur[:-1], kontext) is False)
        hashbasiert += 1
    for f in vektoren["hashbasiert"]["pruefpunkte"]:
        r = pruefpunkt_pruefen(f["text"], f["logSchluessel"], f["zeugen"], f["schwelle"], f["logSchluesselPq"])
        pruefe(f"Hashbasierter Prüfpunkt \"{f['name']}\": Ergebnis", r["bestanden"] == f["erwartet"]["bestanden"], str(r))
        pruefe(f"Hashbasierter Prüfpunkt \"{f['name']}\": Zustand der hashbasierten Signatur", r.get("pq") == f["erwartet"]["pq"], str(r.get("pq")))
        hashbasiert += 1

zeitbeweise = 0
if "zeitbeweis" in vektoren:
    for f in vektoren["zeitbeweis"]["ripemd160"]:
        pruefe("RIPEMD-160", ots.ripemd160(bytes.fromhex(f["eingabe"])).hex() == f["erwartet"])
        zeitbeweise += 1
    for f in vektoren["zeitbeweis"]["faelle"]:
        try:
            r = ots.ots_auswerten(base64.b64decode(f["ots"]))
            ok = True
        except ValueError:
            r = None
            ok = False
        pruefe(f"Zeitbeweis \"{f['name']}\": Ergebnis", ok == f["erwartet"]["ok"])
        if ok and f["erwartet"]["ok"]:
            pruefe(f"Zeitbeweis \"{f['name']}\": Prüfsumme", r["digest"].hex() == f["erwartet"]["digest"])
            ist = [{"art": "bitcoin", "hoehe": a["hoehe"], "nachricht": a["nachricht"].hex()} if a["art"] == "bitcoin" else {"art": a["art"]} for a in r["attestierungen"]]
            pruefe(f"Zeitbeweis \"{f['name']}\": Bestätigungen", ist == f["erwartet"]["attestierungen"])
            if "kopf" in f:
                pruefe(f"Zeitbeweis \"{f['name']}\": Wurzel im Blockkopf", ots.merkle_wurzel_aus_kopf(f["kopf"]["hex"]).hex() == ist[0]["nachricht"])
        zeitbeweise += 1

stichproben = 0
if "stichprobe" in vektoren:
    for f in vektoren["stichprobe"]["ziehungen"]:
        pruefe(f"Ziehung aus {f['groesse']} Ereignissen mit {f['anzahl']} Ziehungen", stichprobe.ziehen(f["wurzelHex"], f["groesse"], f["beaconHex"], f["anzahl"]) == f["ergebnis"])
        stichproben += 1
    for f in vektoren["stichprobe"]["schranken"]:
        pruefe(f"Obergrenze für {f['anzahl']} Ziehungen bei {f['konfidenz']}", abs(stichprobe.obergrenze(f["anzahl"], f["konfidenz"]) - f["obergrenze"]) <= 1e-12 * max(1, abs(f["obergrenze"])))
        stichproben += 1

zaehlvektoren = 0
if "zaehlbeweis" in vektoren:
    z = vektoren["zaehlbeweis"]
    for i, e in enumerate(z["ereignisse"]):
        pruefe(f"Schlüsselmenge des Ereignisses {i} unter den Indexregeln 1", sorted(schluessel_von(e)) == z["schluesselmengen"][i]["regeln1"])
        pruefe(f"Schlüsselmenge des Ereignisses {i} unter den Indexregeln 2", sorted(schluessel_von(e, INDEXREGELN_2)) == z["schluesselmengen"][i]["regeln2"])
        zaehlvektoren += 2
    i1 = index_aufbauen(z["ereignisse"])
    i2 = index_aufbauen(z["ereignisse"], INDEXREGELN_2)
    pruefe("Indexwurzel unter den Indexregeln 1", i1["wurzel"] == z["indexWurzel1"] and i1["anzahl"] == z["indexAnzahl1"])
    pruefe("Indexwurzel unter den Indexregeln 2", i2["wurzel"] == z["indexWurzel2"] and i2["anzahl"] == z["indexAnzahl2"])
    for f in z["faelle"]:
        r = aussage_pruefen(f["doc"], z["logSchluessel"], z["zeugen"], f["schwelle"])
        pruefe(f"Zählprotokoll \"{f['name']}\": Ergebnis", r["ok"] == f["erwartet"]["ok"], str(r))
        if f["erwartet"]["ok"] and r["ok"]:
            pruefe(f"Zählprotokoll \"{f['name']}\": Stufe", r["stufe"] == f["erwartet"]["stufe"])
            pruefe(f"Zählprotokoll \"{f['name']}\": Anzahlen", [a["anzahl"] if a["art"] == "vorhanden" else None for a in r["aussagen"]] == f["erwartet"]["anzahlen"])
        zaehlvektoren += 1
    zaehlvektoren += 2

print(f"Alle Testvektoren bestanden ({zusaetze} Vektoren zu Ereignissen, Auszügen, Aussagen, Zeitankern und Belegen, {hashbasiert} hashbasierte Signaturen und Prüfpunkte, {zeitbeweise} Zeitbeweise, {stichproben} Ziehungen und Schranken, {zaehlvektoren} Vektoren zu den Indexregeln 2)." if fehler == 0 else f"{fehler} Abweichung(en).")
sys.exit(0 if fehler == 0 else 1)
