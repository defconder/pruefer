# Defconder Prüfer

Offener Prüfer für manipulationssichere Beweispakete, Aussagen über das Protokoll, Entscheidungsnachweise und Prüfpunkte eines Transparenzprotokolls. Eine einzelne HTML-Seite, ein Kommandozeilenwerkzeug und zwei weitere Umsetzungen (Python, Rust). Keine Laufzeitabhängigkeiten, nur die Browser-Schnittstelle WebCrypto (Node ab Version 20). Lizenz Apache-2.0.

English version: [README.en.md](README.en.md)

## Was der Prüfer beweist, und was nicht

Der Prüfer rechnet alles selbst nach. Er braucht weder Netz noch Defconder, und die Seite darf technisch keine Verbindung ins Netz aufbauen (Content-Security-Policy). Das Ergebnis trägt eine Vertrauensstufe, damit niemand mehr in das Ergebnis hineinliest, als es hergibt:

| Stufe | Bedeutung | Voraussetzung |
|---|---|---|
| 0 | Das Dokument ist in sich stimmig. | keine |
| 1 | Der Schlüssel des Betreibers ist gebunden. | Sie legen die Kennung des Betreiberschlüssels oder den Protokollschlüssel fest, die Sie auf anderem Weg erhalten haben. |
| 2 | Das Protokoll ist bezeugt. | Sie legen den Protokollschlüssel und die Schlüssel unabhängiger Zeugen fest, und mindestens eine festgelegte Zahl von ihnen hat den Prüfpunkt gegengezeichnet. |

**Stufe 0 beweist nur, dass das Dokument nicht nach seiner Erstellung verändert wurde.** Ein Dokument bringt seinen eigenen Schlüssel mit. Wer eines mit eigenem Schlüssel erzeugt, besteht Stufe 0. Der Prüfer weist darauf in jedem Ergebnis hin.

**Stufe 2 schließt aus, dass der Betreiber das Protokoll rückwirkend umschreibt, ohne dass die Zeugen es merken.** Jeder Zeuge hat sich einen früheren Stand des Protokolls gemerkt und zeichnet einen neuen Stand nur gegen, wenn er sich lückenlos aus dem alten ergibt (Konsistenzbeweis nach RFC 9162). Das gilt nur, wenn die Zeugen tatsächlich unabhängig vom Betreiber sind. Ob sie es sind, beurteilen Sie, nicht der Prüfer.

Zu jedem Ergebnis kann der Prüfer einen **Bericht in Klartext** ausgeben: was bewiesen ist, was nicht, was ein Gegner dafür bräuchte und was Sie als Nächstes tun sollten (`--bericht`, auf der Seite automatisch).

Was der Prüfer nicht beweist:

- Dass ein Ereignis im Protokoll **inhaltlich wahr** ist. Er zeigt, dass es unverändert dort steht.
- Dass **alle** Ereignisse in einem Paket enthalten sind. Eine **Aussage** über das Protokoll kann Vollständigkeit und Abwesenheit relativ zu einem Index beweisen, siehe unten, und der Index lässt sich mit dem vollständigen Protokoll nachrechnen.
- Wie ein Gericht das Ergebnis würdigt. Das ist eine Rechtsfrage und nicht Gegenstand dieses Werkzeugs.

## Dokumentarten

| Dokument | Zweck |
|---|---|
| Beweispaket | Eine Datei samt ihren Ereignissen, Analysen und Beweisen. Ereignisse können als **Auszug** mit verdeckten Feldern beiliegen, ihre Prüfsumme bleibt nachrechenbar. |
| Aussage über das Protokoll | Beweist "zu diesem Schlüssel gibt es genau diese Ereignisse" oder "es gibt keine". |
| Entscheidungsnachweis | Beweist, dass eine Zugriffsentscheidung der im Protokoll veröffentlichten Regel entsprach. |
| Widerspruchsbeweis | Beweist, dass das Protokoll für dieselbe Größe zwei verschiedene Wurzeln unterschrieben hat. |
| Prüfpunkt | Der signierte und gegengezeichnete Stand des Protokolls, gegebenenfalls mit Index und Zeitanker. |

## Schnellstart

```bash
node pruefer.mjs beweispaket.json
node pruefer.mjs beweispaket.json original.pdf --bericht
node pruefer.mjs beweispaket.json --vertraue-schluessel a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
node pruefer.mjs beweispaket.json --log-schluessel "defconder.example/log+1a2b3c4d+AQ..." --zeugen-datei zeugen.txt --schwelle 2
node pruefer.mjs aussage aussage.json --log-schluessel "..." --zeugen-datei zeugen.txt --mindeststufe 2
node pruefer.mjs entscheidung nachweis.json --log-schluessel "..." --bericht
node pruefer.mjs widerspruch beweis.json --log-schluessel "..."
node pruefer.mjs pruefpunkt pruefpunkt.txt --log-schluessel "..." --zeugen-datei zeugen.txt
node pruefer.mjs konsistenz alt.txt neu.txt beweis.json --log-schluessel "..."
```

Die Dokumentart wird am Feld `schema` erkannt, der Befehl kann weggelassen werden. Oder `pruefer.html` im Browser öffnen. Alles läuft lokal, es werden keine Daten verschickt.

Mit `--mindeststufe N` gilt ein Dokument nur als bestanden, wenn mindestens Stufe N erreicht ist. Sind Zeugen festgelegt, verlangt der Prüfer bei einem Beweispaket auch deren Gegenzeichnungen.

Rückgabewert 0: alle Prüfungen bestanden. 1: mindestens eine Prüfung fehlgeschlagen. 2: Aufruf oder Eingabe fehlerhaft.

## Bestandteile

- `pruefer-kern.js`: Prüfung eines Beweispakets, eines Prüfpunkts und von Schlüsselwechseln.
- `ereignis.js`: Prüfsumme der Ereignisse (altes Format und Version 2), Auszüge.
- `aussage.js`: Index, Aussagen über das Protokoll. `entscheidung.js`, `regeln.js`: Entscheidungsnachweise und Regelsprache. `widerspruch.js`: Widerspruchsbeweise. `zeitanker.js`: Bitcoin-Zeitanker. `bericht.js`: Bericht in Klartext.
- `merkle.js`: Merkle-Baum nach RFC 6962 und RFC 9162, Einschluss- und Konsistenzbeweise.
- `note.js`: signierte Notizen, Prüfpunkte und Gegenzeichnungen nach den Formaten von [C2SP](https://c2sp.org) (signed-note, tlog-checkpoint, tlog-cosignature).
- `pruefer.mjs`: Kommandozeile. `pruefer.html`: eigenständige Seite, erzeugt mit `node bauen-html.mjs`.
- `python/` und `rust/`: zweite und dritte Umsetzung (Prüfpunkte, Konsistenz, Ereignisse, Auszüge, Aussagen, Zeitanker, Belege).
- `testvektoren/`: deterministisch erzeugte Testvektoren, gegen die alle drei Umsetzungen laufen.
- `release.mjs`: reproduzierbarer Bau, Prüfsummen, Liste der Bestandteile (CycloneDX) und signiertes Manifest.
- `schluesselwechsel-erzeugen.mjs`: erzeugt eine vom alten Schlüssel unterschriebene Wechselaussage.
- `SPEZIFIKATION.md` und `BEDROHUNGSMODELL.md`: genaue Formate, Prüfschritte und was abgewehrt wird (englisch: `SPECIFICATION.en.md`, `THREAT_MODEL.en.md`).

## Prüfen, ob die Seite unverändert ist

`node release.mjs` baut `pruefer.html` aus den Quelldateien und schreibt `release/SHA256SUMS`, `release/sbom.cdx.json` und ein signiertes `release/MANIFEST.json`. Zweimal gebaut ergibt sich dieselbe Prüfsumme. Vergleichen Sie die Prüfsumme der Seite, die Sie benutzen, mit der in der Ankündigung der Fassung.

## Zeugen und Beobachter

Ein **Zeuge** ist ein kleiner, eigenständiger Dienst (Ordner `zeuge`). Er merkt sich je Protokoll den letzten Stand, den er gegengezeichnet hat, und verlangt für jeden neuen Stand einen Konsistenzbeweis. Ein **Beobachter** (Ordner `beobachter`) holt den Prüfpunkt regelmäßig, prüft ihn, verlangt Konsistenzbeweise, rechnet auf Wunsch den Index mit dem vollständigen Protokoll nach und erzeugt bei Widerspruch einen Beweis, den jeder nachprüfen kann. Jeder kann beides betreiben. Je mehr voneinander unabhängige Zeugen und Beobachter ein Betreiber hat, desto weniger muss man dem Betreiber vertrauen.

## Tests

```bash
node testvektoren/pruefen.mjs
python python/pruefen_vektoren.py
cargo run --release --manifest-path rust/Cargo.toml -- testvektoren/testvektoren.json
```

Die Testvektoren umfassen die Wurzeln der Baumgrößen 1 bis 33 und einiger größerer, mehr als dreihundert Konsistenzbeweise, Prüfpunkte mit gültigen, fehlenden und gefälschten Signaturen, Ereignisse beider Formate mit Veränderungen, Auszüge, Aussagen, Zeitanker und Belege. Alle drei Umsetzungen bestehen sie.

## Grenzen und was fehlt

- Die Gegenzeichnungen verwenden Ed25519. Die Spezifikation empfiehlt für neue Einsätze ML-DSA-44. Die Web-Schnittstelle der Browser und die eingesetzte Node-Fassung bieten das heute nicht an.
- Ein qualifizierter Zeitstempel nach eIDAS ist nicht eingebaut. Der Bitcoin-Zeitanker belegt "nicht früher als", und die Gegenzeichnungen der Zeugen tragen eine eigene, signierte Zeit. Beides ist kein qualifizierter Zeitstempel.
- Der Prüfer hat kein unabhängiges Sicherheitsaudit durchlaufen. Er ist klein, hat keine Abhängigkeiten und ist gegen drei Umsetzungen getestet. Das ersetzt kein Audit.
- Eine Aussage über das Protokoll gilt für den Index, den der Betreiber festgelegt hat. Ob er vollständig ist, lässt sich nur mit dem vollständigen Protokoll nachrechnen.
- Ein Entscheidungsnachweis zeigt, dass nach der veröffentlichten Regel entschieden wurde, nicht dass die Eingaben oder die Regel fachlich richtig sind.

## Sicherheitslücken melden

Bitte vertraulich an justautomatemore@jamoneai.de. Nennen Sie Fassung, Eingabe und erwartetes Verhalten.
