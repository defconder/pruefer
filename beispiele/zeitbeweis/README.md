# Beispiel: ein echter Zeitbeweis / A real time proof

## Deutsch

Ein Beispielprotokoll mit acht erfundenen Ereignissen, dessen Prüfpunkt am 11. Oktober 2026 mit OpenTimestamps in die Bitcoin-Blockkette eingetragen wurde. Es zeigt den ganzen Weg mit echten Daten. Das Protokoll gehört niemandem und sagt nichts über ein echtes System.

| Datei | Inhalt |
| --- | --- |
| `pruefpunkt.txt` | Der signierte Prüfpunkt mit Ed25519, hashbasierter Signatur (SLH-DSA-SHA2-128f) und dem Kopf eines Bitcoin-Blocks (Untergrenze der Zeit) |
| `log-schluessel.txt` | Öffentlicher Schlüssel des Beispielprotokolls (Ed25519) |
| `log-schluessel-pq.txt` | Öffentlicher hashbasierter Schlüssel des Beispielprotokolls |
| `koerper.txt` | Der signierte Text des Prüfpunkts, also das, was gestempelt wurde |
| `koerper.txt.ots` | Der Zeitbeweis, wie ihn das Werkzeug `ots` von OpenTimestamps erzeugt hat |
| `zeitbeweis.json` | Prüfpunkt, Beweis und die Blockköpfe in einem Dokument, das der Prüfer versteht |

Nachprüfen mit dem Prüfer (aus dem Ordner `pruefer`, Node.js ab Version 20, keine Pakete nötig):

```
node pruefer.mjs zeitbeweis ../beispiele/zeitbeweis/zeitbeweis.json --log-schluessel "$(cat ../beispiele/zeitbeweis/log-schluessel.txt)" --bericht
```

Oder das Dokument `zeitbeweis.json` auf die Seite `pruefer.html` ziehen und den Schlüssel aus `log-schluessel.txt` eintragen.

Erwartetes Ergebnis: Der Prüfpunkt steckt im Bitcoin-Block der Höhe 970912 (Blockzeit 2026-10-11 10:33:25 UTC). Er entstand frühestens am 2026-10-11 05:58:41 UTC und bestand spätestens am 2026-10-11 12:33:25 UTC. Der Prüfer rechnet mit der Blockzeit plus zwei Stunden, weil Blockzeiten nur auf etwa zwei Stunden genau sind.

Der Beweis in `koerper.txt.ots` ist unabhängig vom Prüfer mit dem Werkzeug `ots` lesbar (`ots info koerper.txt.ots`).

Grenzen: Der Zeitbeweis zeigt, dass der Text zu diesem Zeitpunkt schon bestand, nicht dass sein Inhalt wahr ist. Für den Bitcoin-Block gilt: Vergleichen Sie die Blockprüfsumme mit einer Blockübersicht Ihrer Wahl, der Prüfer prüft die Rechenarbeit des Blockkopfs, kennt aber die Kette nicht.

## English

A sample log with eight made-up events whose checkpoint was entered into the Bitcoin blockchain with OpenTimestamps on 11 October 2026. It shows the whole path with real data. The log belongs to nobody and says nothing about a real system.

| File | Content |
| --- | --- |
| `pruefpunkt.txt` | The signed checkpoint with Ed25519, a hash-based signature (SLH-DSA-SHA2-128f) and the header of a Bitcoin block (lower bound of time) |
| `log-schluessel.txt` | Public key of the sample log (Ed25519) |
| `log-schluessel-pq.txt` | Public hash-based key of the sample log |
| `koerper.txt` | The signed text of the checkpoint, which is what was stamped |
| `koerper.txt.ots` | The time proof as produced by the OpenTimestamps tool `ots` |
| `zeitbeweis.json` | Checkpoint, proof and block headers in one document the verifier understands |

Check it with the verifier (from the folder `pruefer`, Node.js 20 or later, no packages needed):

```
node pruefer.mjs zeitbeweis ../beispiele/zeitbeweis/zeitbeweis.json --log-schluessel "$(cat ../beispiele/zeitbeweis/log-schluessel.txt)" --bericht
```

Or drag `zeitbeweis.json` onto the page `pruefer.html` and enter the key from `log-schluessel.txt`.

Expected result: the checkpoint is in the Bitcoin block at height 970912 (block time 2026-10-11 10:33:25 UTC). It was created no earlier than 2026-10-11 05:58:41 UTC and existed at the latest at 2026-10-11 12:33:25 UTC. The verifier uses the block time plus two hours because block times are only accurate to about two hours.

The proof in `koerper.txt.ots` can be read independently of the verifier with the tool `ots` (`ots info koerper.txt.ots`).

Limits: a time proof shows that the text already existed at that time, not that its content is true. For the Bitcoin block: compare the block hash with a block explorer of your choice. The verifier checks the proof of work of the block header but does not know the chain.
