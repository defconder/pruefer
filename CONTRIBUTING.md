# Mitmachen

Willkommen sind Fehlerberichte, Korrekturen an der Spezifikation, zusätzliche Testvektoren und Umsetzungen in weiteren Sprachen. Eine unabhängige Umsetzung, die dieselben Testvektoren besteht, ist das Wertvollste, was dieses Projekt bekommen kann.

## Grundregeln

- **Die Spezifikation ist maßgeblich.** Ändert sich ein Format oder ein Prüfschritt, ändern sich zuerst `pruefer/SPEZIFIKATION.md` und die Testvektoren, danach alle drei Umsetzungen. Eine Änderung nur in einer Sprache wird nicht angenommen.
- **Keine Laufzeitabhängigkeiten** im Prüfer, in der Seite und in der Kommandozeile. Die Python- und Rust-Umsetzung dürfen Bibliotheken für Ed25519 und SHA-256 nutzen.
- **Jeder Prüfschritt hat einen Test**, der zeigt, dass er ein verändertes Dokument ablehnt, nicht nur, dass er ein gültiges annimmt.
- **Ehrliche Aussagen.** Texte, die der Prüfer ausgibt, und die Dokumentation nennen Grenzen genauso deutlich wie Fähigkeiten.

## Tests ausführen

```bash
node pruefer/testvektoren/pruefen.mjs
python pruefer/python/pruefen_vektoren.py
cargo run --release --manifest-path pruefer/rust/Cargo.toml -- pruefer/testvektoren/testvektoren.json
```

Nach Änderungen an `pruefer/*.js` die Seite neu bauen (`node pruefer/bauen-html.mjs`). Der Bau ist reproduzierbar, die Prüfung der Pipeline vergleicht das Ergebnis mit der eingecheckten Datei.

## Pull Requests

Bitte klein halten und den Zweck in einem Satz nennen. Sicherheitsrelevantes bitte nicht öffentlich, siehe [SECURITY.md](SECURITY.md).

---

# Contributing

Bug reports, corrections to the specification, additional test vectors and implementations in further languages are welcome. An independent implementation that passes the same test vectors is the most valuable thing this project can get.

- **The specification is authoritative.** A change to a format or verification step changes `pruefer/SPEZIFIKATION.md` and the test vectors first, then all three implementations.
- **No runtime dependencies** in the verifier, the page and the command line. The Python and Rust implementations may use libraries for Ed25519 and SHA-256.
- **Every verification step has a test** showing it rejects a modified document, not only that it accepts a valid one.
- **Honest statements.** Texts the verifier prints and the documentation state limits as clearly as capabilities.

Run the tests with the three commands above. After changing `pruefer/*.js`, rebuild the page with `node pruefer/bauen-html.mjs`. The build is reproducible and the pipeline compares the result with the committed file.
