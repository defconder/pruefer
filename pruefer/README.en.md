# Defconder Verifier

An open verifier for tamper-evident evidence packages, statements about a transparency log, decision proofs and checkpoints. One standalone HTML page, a command line tool and two further implementations (Python, Rust). No runtime dependencies, only the WebCrypto API of the browser (Node 20 or later). Licence Apache-2.0.

German version: [README.md](README.md). Identifiers in the code and the interface texts are German.

## What it proves, and what it does not

The verifier recomputes everything itself. It needs neither a network nor Defconder, and the page is technically forbidden from opening any connection (Content-Security-Policy). Every result carries a trust level so that nobody reads more into it than it gives:

| Level | Meaning | Requirement |
|---|---|---|
| 0 | The document is internally consistent. | none |
| 1 | The operator key is pinned. | You supply the key id of the operator, or the log key, that you obtained through another channel. |
| 2 | The log is witnessed. | You supply the log key and the keys of independent witnesses, and at least a set number of them have cosigned the checkpoint. |

**Level 0 only proves that the document has not been altered since it was made.** A document brings its own key. Anyone who builds one with their own key passes level 0. The verifier says so in every result.

**Level 2 rules out that the operator silently rewrites the log after the fact.** Each witness remembers an earlier state of the log and cosigns a new state only if it follows from the old one without gaps (consistency proof, RFC 9162). This holds only if the witnesses are independent of the operator. You judge that, not the verifier.

For every result the verifier can print a **plain language report**: what is proven, what is not, what an adversary would need, and what to do next (`--bericht`, automatic on the page).

It does not prove that an event in the log is true (only that it is there unaltered), that a package holds all events (a **statement** about the log can prove completeness and absence relative to an index, see below), or how a court will treat the result.

## Document types

| Document | Purpose |
|---|---|
| Evidence package | A file with its events, analyses and proofs. Events may be included as an **extract** with hidden fields, their hash stays verifiable. |
| Statement about the log | Proves "there are exactly these events for this key" or "there are none". |
| Decision proof | Proves that an access decision matched the rule that was published in the log. |
| Contradiction proof | Proves that the log signed two different roots for the same size. |
| Checkpoint | The signed and cosigned state of the log, possibly with index and time anchor. |

## Quick start

```bash
node pruefer.mjs package.json
node pruefer.mjs package.json original.pdf --bericht
node pruefer.mjs package.json --log-schluessel "example.org/log+1a2b3c4d+AQ..." --zeugen-datei witnesses.txt --schwelle 2
node pruefer.mjs aussage statement.json --log-schluessel "..." --zeugen-datei witnesses.txt --mindeststufe 2
node pruefer.mjs entscheidung proof.json --log-schluessel "..." --bericht
node pruefer.mjs widerspruch proof.json --log-schluessel "..."
node pruefer.mjs pruefpunkt checkpoint.txt --log-schluessel "..." --zeugen-datei witnesses.txt
node pruefer.mjs konsistenz old.txt new.txt proof.json --log-schluessel "..."
```

The document type is recognised by its `schema` field, the command can be left out. Or open `pruefer.html` in a browser. Everything runs locally. With `--mindeststufe N` a document only passes if at least level N is reached. If witnesses are pinned, the verifier also requires their cosignatures in an evidence package. Exit code 0: all checks passed, 1: at least one check failed, 2: bad usage or input.

## Formats

Checkpoints, signed notes and cosignatures follow the formats of [C2SP](https://c2sp.org) (signed-note, tlog-checkpoint, tlog-cosignature, tlog-witness). Merkle trees, inclusion proofs and consistency proofs follow RFC 6962 and RFC 9162. Event hashes of version 2 are built over a salted field tree with canonical JSON (RFC 8785 for the value types used), which is what makes extracts possible. See `SPECIFICATION.en.md` and `THREAT_MODEL.en.md`.

## Witnesses and observers

A **witness** (folder `zeuge`) remembers the last state it cosigned for each log and demands a consistency proof for every new state. An **observer** (folder `beobachter`) fetches the checkpoint regularly, verifies it, demands consistency proofs, can recompute the index from the full log and produces a proof anyone can check when the log contradicts itself. Anyone can run either.

## Tests

```bash
node testvektoren/pruefen.mjs
python python/pruefen_vektoren.py
cargo run --release --manifest-path rust/Cargo.toml -- testvektoren/testvektoren.json
```

The vectors cover tree roots, more than three hundred consistency proofs, checkpoints with valid, missing and forged signatures, events of both formats with modifications, extracts, statements, time anchors and decision receipts. All three implementations pass them.

## Limits

Cosignatures use Ed25519, not the recommended ML-DSA-44, which browsers and the Node version used here do not offer yet. There is no eIDAS qualified timestamp. The Bitcoin time anchor proves "not earlier than", the witness cosignatures carry their own signed time. The verifier has had no independent security audit. A statement about the log holds for the index the operator fixed, whether it is complete can only be checked by recomputing it from the full log. A decision proof shows that the published rule was applied, not that the inputs or the rule are right.

Report vulnerabilities confidentially to justautomatemore@jamoneai.de.
