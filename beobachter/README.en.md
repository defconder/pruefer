# Defconder Observer

A small, standalone program that regularly fetches the checkpoint of a transparency log, verifies it and compares it with everything it has seen before. Licence Apache-2.0. No dependencies apart from Node 20 or later and the verifier in the neighbouring folder. German version: [README.md](README.md), which is authoritative.

## What it does

1. Fetches `/transparenz/pruefpunkt` of the operator and verifies the signature of the pinned log key, the demanded cosignatures, an optional hash-based signature of the log (`--log-pq`) and any time anchor.
2. Remembers every state it has seen (`punkte.jsonl`) and the last confirmed one (`zustand.json`).
3. Demands a consistency proof for every larger state (`/transparenz/konsistenz`) and verifies it itself.
4. Raises an alarm (`alarme.jsonl`, with evidence) if
   - the checkpoint carries no valid signature,
   - an earlier state was larger (rollback),
   - the new state cannot be derived from the old one (rewriting),
   - two different roots were signed for the same size. That is a proof anyone can recompute with `node ../pruefer/pruefer.mjs widerspruch`.
5. On request: `--feed-pruefen` verifies the whole published list of checkpoints entry by entry. `--nachrechnen event-log.jsonl` recomputes chain, tree root and **index** (under index rules 1 or 2) from the full log and exposes an index that does not stem from the log.

## Usage

```bash
node beobachter.mjs --quelle https://operator.example --log "operator.example/log+1a2b3c4d+AQ..." --zeuge "witness.example+5e6f7a8b+BA..." --schwelle 1 --dir ./beobachter-daten --intervall 300
node beobachter.mjs --quelle https://operator.example --log "..." --einmal --feed-pruefen --nachrechnen event-log.jsonl
```

Return value with `--einmal`: 0 fine, 1 alarm, 2 error while fetching. With a session token (`--token`) an operator that does not offer the endpoint publicly can also be observed. `--tls-pruefung-aus` turns off certificate checking and is only meant for local experiments.

## Limits

- The observer cannot prove anything the operator did not sign itself.
- Rollback and a missing consistency proof are alarms with evidence, but no cryptographic proof. Only the contradiction at the same size is proven.
- `--nachrechnen` needs access to the full log.
