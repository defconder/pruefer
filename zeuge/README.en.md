# Defconder Witness

A small, standalone service that cosigns checkpoints of a transparency log, but only if the new state follows without gaps from the last one it has seen. Protocol per [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness), cosignatures per [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature) (`cosignature/v1`, Ed25519). Licence Apache-2.0. German version: [README.md](README.md), which is authoritative.

## Operation

```bash
node zeuge.mjs --name witness.example.org --log "defconder.example/log+1a2b3c4d+AQ..." --port 8801 --host 127.0.0.1 --dir ./zeuge-daten
```

On first start a key is created in `./zeuge-daten/zeuge.key` (permissions for the service user only). The program prints the public key of the witness. The witness passes this key on **through a channel the operator does not control** (for example published on the witness's own site), and the operator enters it with the address into its `zeugen.json`. Verifiers pin it as well.

The service speaks plain HTTP. Run it behind a reverse proxy with TLS if it is to be reachable over a network.

## What the witness checks

1. The request is well formed (old size, up to 63 proof elements, checkpoint).
2. It knows the log (the key was pinned at start) and the signature of the log is valid.
3. The old size in the request is the size it last cosigned. Otherwise it answers 409 and names its size.
4. The consistency proof from the old to the new size is valid. Otherwise it answers 422 and does not cosign.
5. It stores the new state and only then answers with the cosignature. Requests are handled one after the other.

An operator who changes an earlier event or rolls the log back to an earlier state no longer gets a cosignature.

The witness cosigns the whole text of the checkpoint including its extension lines (index, time anchor). It does not check their content, the cosignature only binds them to this checkpoint. Whether an index stems completely from the log is checked by the observer (`../beobachter`). A hash-based signature line of the log (SLH-DSA) comes after the cosignatures and is never seen by the witness.

## Limits

- The first time, the witness trusts the operator (state 0). A log falsified before the first cosignature does not stand out.
- If the witness loses its state file it can no longer refuse an earlier state. Back up `zustand.json`.
- Ed25519, no ML-DSA-44 (see the README of the verifier).
