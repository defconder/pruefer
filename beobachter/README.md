# Defconder Beobachter

Ein kleines, eigenständiges Programm, das den Prüfpunkt eines Transparenzprotokolls regelmäßig holt, prüft und gegen alles abgleicht, was es früher gesehen hat. Lizenz Apache-2.0. Keine Abhängigkeiten außer Node ab Version 20 und dem Prüfer im Nachbarordner.

## Was es tut

1. Holt `/transparenz/pruefpunkt` des Betreibers und prüft die Signatur des festgelegten Protokollschlüssels sowie die verlangten Gegenzeichnungen und einen etwaigen Zeitanker.
2. Merkt sich jeden gesehenen Stand (`punkte.jsonl`) und den zuletzt bestätigten (`zustand.json`).
3. Verlangt für jeden größeren Stand einen Konsistenzbeweis (`/transparenz/konsistenz`) und prüft ihn selbst.
4. Schlägt Alarm (`alarme.jsonl`, mit Beweisstücken), wenn
   - der Prüfpunkt keine gültige Signatur trägt,
   - ein früher gesehener Stand größer war (Rücksetzung),
   - der neue Stand sich nicht aus dem alten ableiten lässt (Umschreiben),
   - für dieselbe Größe zwei verschiedene Wurzeln unterschrieben wurden. Das ist ein Beweis, den jeder mit `node ../pruefer/pruefer.mjs widerspruch` nachrechnen kann.
5. Auf Wunsch: `--feed-pruefen` prüft die gesamte veröffentlichte Liste von Prüfpunkten Eintrag für Eintrag. `--nachrechnen event-log.jsonl` rechnet Kette, Baumwurzel und **Index** aus dem vollständigen Protokoll nach und entlarvt einen Index, der nicht aus dem Protokoll stammt.

## Aufruf

```bash
node beobachter.mjs --quelle https://betreiber.example --log "betreiber.example/log+1a2b3c4d+AQ..." --zeuge "zeuge.example+5e6f7a8b+BA..." --schwelle 1 --dir ./beobachter-daten --intervall 300
node beobachter.mjs --quelle https://betreiber.example --log "..." --einmal --feed-pruefen --nachrechnen event-log.jsonl
```

Rückgabewert mit `--einmal`: 0 in Ordnung, 1 Alarm, 2 Fehler beim Abruf. Mit einer Sitzungskennung (`--token`) lässt sich auch ein Betreiber beobachten, der den Endpunkt nicht öffentlich anbietet. `--tls-pruefung-aus` schaltet die Zertifikatsprüfung ab und ist nur für lokale Versuche gedacht.

## Grenzen

- Der Beobachter kann nichts beweisen, was der Betreiber nicht selbst unterschrieben hat.
- Rücksetzung und fehlender Konsistenzbeweis sind Alarme mit Beweisstücken, aber kein kryptografischer Beweis. Bewiesen ist nur der Widerspruch bei gleicher Größe.
- `--nachrechnen` braucht Zugang zum vollständigen Protokoll.
