# Defconder Zeuge

Ein kleiner, eigenständiger Dienst, der Prüfpunkte eines Transparenzprotokolls gegenzeichnet, aber nur, wenn sich der neue Stand lückenlos aus dem letzten ergibt, den er gesehen hat. Protokoll nach [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness), Gegenzeichnungen nach [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature) (`cosignature/v1`, Ed25519). Lizenz Apache-2.0.

## Betrieb

```bash
node zeuge.mjs --name zeuge.example.org --log "defconder.example/log+1a2b3c4d+AQ..." --port 8801 --host 127.0.0.1 --dir ./zeuge-daten
```

Beim ersten Start entsteht ein Schlüssel in `./zeuge-daten/zeuge.key` (Rechte nur für den Dienstbenutzer). Das Programm gibt den öffentlichen Schlüssel des Zeugen aus. Diesen Schlüssel gibt der Zeuge **auf einem Weg weiter, den der Betreiber nicht kontrolliert** (zum Beispiel veröffentlicht auf der eigenen Seite des Zeugen), und der Betreiber trägt ihn mit der Adresse in seine `zeugen.json` ein. Prüfer legen ihn ebenfalls fest.

Der Dienst spricht einfaches HTTP. Betreiben Sie ihn hinter einem Reverse-Proxy mit TLS, wenn er über ein Netz erreichbar sein soll.

## Was der Zeuge prüft

1. Die Anfrage ist wohlgeformt (alte Größe, bis zu 63 Beweiselemente, Prüfpunkt).
2. Das Protokoll ist ihm bekannt (der Schlüssel wurde beim Start festgelegt) und die Signatur des Protokolls stimmt.
3. Die alte Größe der Anfrage ist die Größe, die er zuletzt gegengezeichnet hat. Sonst antwortet er mit 409 und nennt seine Größe.
4. Der Konsistenzbeweis von der alten zur neuen Größe stimmt. Sonst antwortet er mit 422 und zeichnet nicht gegen.
5. Er speichert den neuen Stand und antwortet erst dann mit der Gegenzeichnung. Anfragen werden nacheinander abgearbeitet.

Ein Betreiber, der ein früheres Ereignis ändert oder das Protokoll auf einen früheren Stand zurücksetzt, bekommt keine Gegenzeichnung mehr.

Der Zeuge zeichnet den ganzen Text des Prüfpunkts einschließlich seiner Erweiterungszeilen (Index, Zeitanker) gegen. Er prüft deren Inhalt nicht, die Gegenzeichnung bindet sie nur an diesen Prüfpunkt. Ob ein Index vollständig aus dem Protokoll stammt, prüft der Beobachter (`../beobachter`).

## Grenzen

- Beim ersten Mal vertraut der Zeuge dem Betreiber (Stand 0). Ein Protokoll, das vor der ersten Gegenzeichnung verfälscht wurde, fällt nicht auf.
- Verliert der Zeuge seine Zustandsdatei, kann er einen früheren Stand nicht mehr verweigern. Sichern Sie `zustand.json`.
- Ed25519, kein ML-DSA-44 (siehe README des Prüfers).
