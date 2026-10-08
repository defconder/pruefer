# Bedrohungsmodell

Fassung 0.3. Was der Prüfer abwehrt, was er nicht abwehrt, und was dafür vorausgesetzt wird. Englische Fassung: [THREAT_MODEL.en.md](THREAT_MODEL.en.md).

## Was geschützt wird

Die Aussage: Ein Ereignis oder eine Datei stand zu einem Zeitpunkt in einem Protokoll, und das Protokoll wurde seither nur ergänzt, nie verändert. Dazu kommen Aussagen über das Protokoll (es gibt zu einem Schlüssel genau diese Ereignisse, es gibt keine) und Nachweise, dass eine Entscheidung der veröffentlichten Regel entsprach.

## Angreifer und Wirkung

| Angreifer | Ziel | Stufe 0 | Stufe 1 | Stufe 2 |
|---|---|---|---|---|
| Wer ein Dokument auf dem Transportweg ändert | Inhalt, Datei oder Befund verändern | abgewehrt | abgewehrt | abgewehrt |
| Wer ein eigenes Dokument mit eigenem Schlüssel erfindet | Fälschung als Dokument des Betreibers ausgeben | **nicht abgewehrt** | abgewehrt, wenn die Kennung des Betreibers stimmt | abgewehrt |
| Betreiber oder Administrator, der das Protokoll vor der Unterschrift neu schreibt | Ereignisse rückwirkend ändern oder entfernen | **nicht abgewehrt** | **nicht abgewehrt** | abgewehrt, solange nicht genug Zeugen zusammenwirken |
| Betreiber, der verschiedenen Beobachtern verschiedene Wahrheiten zeigt | zwei Wahrheiten erzählen | nicht abgewehrt | nicht abgewehrt | abgewehrt, sobald ein Beobachter beide Stände vergleicht, und beweisbar bei gleicher Größe |
| Betreiber, der den Baum auf einen früheren Stand zurücksetzt | Ereignisse verschwinden lassen | nicht abgewehrt | nicht abgewehrt | abgewehrt, die Zeugen lehnen kleinere Größen ab |
| Gestohlener Signaturschlüssel des Betreibers | Dokumente im Namen des Betreibers erzeugen | nicht abgewehrt | nicht abgewehrt | wirkungslos für das Umschreiben, nicht für neue, gültig aussehende Ereignisse |
| Betreiber, der in einer Aussage Ereignisse weglässt | "es gab keine Zugriffe" behaupten | nicht abgewehrt | nicht abgewehrt | nur durch Nachrechnen des Index mit dem vollständigen Protokoll abgewehrt |
| Betreiber, der eine Entscheidung nach anderen Regeln trifft als veröffentlicht | Regeln heimlich ändern | nicht abgewehrt | nicht abgewehrt | abgewehrt für Entscheidungen mit Beleg, jede Regeländerung steht im Protokoll |
| Wer ein Auszug-Dokument fälscht | verdeckte Felder austauschen | abgewehrt, die Prüfsumme des Ereignisses bindet sie | abgewehrt | abgewehrt |
| Wer einen Zeitanker fälscht | ein Dokument älter aussehen lassen | teilweise, der Block muss die geforderte Rechenarbeit tragen | teilweise | teilweise, der Anker belegt "nicht früher als", nicht "nicht später als" |

## Annahmen, auf denen Stufe 2 ruht

1. Der Prüfer kennt den Protokollschlüssel und die Zeugenschlüssel auf einem Weg, den der Betreiber nicht kontrolliert (zum Beispiel auf Papier, über den Zeugen selbst, aus einer unabhängigen Veröffentlichung).
2. Mindestens die geforderte Zahl von Zeugen ist **nicht** mit dem Betreiber im Bunde und wurde nicht kompromittiert. Verlangt der Prüfer zwei von drei, brauchen Betreiber und Angreifer zwei Zeugen.
3. Der erste Stand, den ein Zeuge sieht, ist nicht schon verfälscht. Zeugen vertrauen beim ersten Mal dem Betreiber. Ein vor der ersten Gegenzeichnung umgeschriebenes Protokoll fällt nicht auf. Deshalb sollte der Betreiber Zeugen ab Inbetriebnahme verwenden.
4. SHA-256 und Ed25519 bleiben sicher. Gegen Rechner mit Quantenvorteil schützt Ed25519 nicht.

## Beobachter

Ein Beobachter holt den Prüfpunkt, prüft die Signatur, verlangt für jeden neuen Stand einen Konsistenzbeweis und merkt sich alle gesehenen Stände. Er erkennt Rücksetzung, Umschreiben und, anders als ein einzelner Zeuge, zwei Wahrheiten. Zwei unterschriebene Prüfpunkte gleicher Größe mit verschiedenen Wurzeln sind ein Beweis, den jeder nachrechnen kann. Je mehr unabhängige Beobachter es gibt (Zeugen, Behörden, die Bürger-App), desto schwerer lässt sich ein Betrug verbergen. Ein Beobachter kann dem Betreiber nichts beweisen, was der Betreiber nicht selbst unterschrieben hat.

## Weitere Risiken

| Risiko | Gegenmaßnahme | Rest |
|---|---|---|
| Eine veränderte `pruefer.html` täuscht gute Ergebnisse vor | reproduzierbarer Bau, Prüfsumme, signiertes Manifest, Richtlinie gegen Netzverbindungen | Wer die Prüfsumme nicht vergleicht, trägt das Risiko. |
| Die Kennung des Betreibers kommt über denselben Kanal wie das Dokument | Kennung über einen zweiten Weg beschaffen | Das liegt beim Anwender. |
| Zwei Umsetzungen berechnen die Prüfsumme der Ereignisse verschieden | Version 2 mit kanonischem JSON und Feldbaum, Testvektoren, drei Umsetzungen | Das alte Format hängt an `JSON.stringify` und wird nur noch geprüft. |
| Absichtlich riesige oder verschachtelte Eingaben | Grenzen für Ereigniszahl, Beweislänge, Feldzahl und Baumgröße | Sehr große Pakete brauchen Speicher. |
| Fehler in der Umsetzung | drei Umsetzungen in drei Sprachen gegen dieselben Testvektoren (von derselben Hand, eine Umsetzung durch Dritte steht aus), Zufallsprüfung, Aufzählung aller Baumgrößen bis 70 | Kein unabhängiges Audit. |
| Zeitangaben | Gegenzeichnungen tragen die Zeit des Zeugen, Zeitanker die Blockzeit | Sie belegen "nicht früher als", nicht "nicht später als". Ein qualifizierter Zeitstempel ist nicht eingebaut. |
| Der Index lässt Ereignisse aus | Nachrechnen mit dem vollständigen Protokoll | Wer das Protokoll nicht sieht, kann es nicht nachrechnen. |
| Der Prüfer erkennt ein Schlüsselfeld nicht | Schlüsselfelder stehen fest in den Indexregeln | Ein Ereignis, das seine Kennung in einem anderen Feld trägt, taucht unter diesem Schlüssel nicht auf. |
| Die Eingaben einer Entscheidung waren falsch erfasst | keine, der Nachweis zeigt nur die Übereinstimmung mit der Regel | Der Nachweis sagt nichts über die fachliche Richtigkeit der Regel oder der Eingaben. |

## Was die Stufen für Entscheidungen bedeuten

Stufe 0 ist ein Integritätsnachweis des Dokuments. Stufe 1 bindet das Dokument an einen bekannten Betreiber. Stufe 2 bindet es an einen Protokollstand, den unabhängige Dritte bestätigt haben, und macht das heimliche Umschreiben für den Betreiber nachweisbar. Keine Stufe sagt etwas über die Rechtswirkung.
