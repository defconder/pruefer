# Defconder Custodian

A small reference service for **release only against a log entry**. Data lies encrypted, the key is shared by Shamir among `n` custodians, `k` suffice. A custodian only hands out its share if the request appears in the log of a checkpoint that the pinned witnesses have confirmed. For that it issues a signed receipt. Licence Apache-2.0. German version: [README.md](README.md), which is authoritative.

This is a model for understanding, checking and rebuilding, not a hardened service.

## Flow

1. The application enters an event `ZugriffAngefragt` with `objectId` and `empfaengerSchluessel` (X25519, Base64) into the log and waits for the next confirmed checkpoint.
2. The requester sends the custodian the event, its inclusion proof and the checkpoint (`POST /freigabe`).
3. The custodian checks the checkpoint (log key, witnesses, threshold), the inclusion and the type. Then it answers with a receipt and its share, encrypted to the recipient.
4. The requester collects `k` shares, reassembles the key and decrypts. The receipts form the release proof (`defconder-freigabe-1`), which the verifier recomputes.
5. On request each custodian signs a statement about its receipts for an object (`GET /auskunft?objekt=...`). From `n - k + 1` statements without a receipt it follows that no key could have been released for the object (`defconder-freigabebericht-1`).

## Operation

```bash
node hueter.mjs --name custodian-1.example.org --log "defconder.example/log+1a2b3c4d+AQ..." \
  --zeuge "witness-a.example+5e6f7a8b+BA..." --zeuge "witness-b.example+9c0d1e2f+BA..." --zeugen-schwelle 2 \
  --anteil object-1=<share in Base64> --port 8811 --dir ./hueter-daten
```

On first start a key is created in `hueter.key`. The custodian passes on its public key through a channel the operator does not control. Receipts are stored in `quittungen.jsonl`. The files `shamir.mjs` and `umschlag.mjs` share the key and encrypt data and shares.

## Limits

- Whoever brings `k` custodians to their side decrypts without an entry. The custodians must be run independently of each other.
- Whoever has the plaintext can copy it. The log shows the access, it does not prevent passing it on.
- The entry only appears in the next confirmed checkpoint. That time passes between request and release.
- The statements of the custodians are promises. A custodian that signs a false statement is exposed as soon as someone holds a receipt of the same custodian against it.
- The service speaks plain HTTP and does not authenticate requesters. Run it behind a reverse proxy with TLS. Who may collect shares is decided only by the entry in the log, not by the person.
- Shares leave the service encrypted to the recipient key from the event. The custodian itself keeps them in the clear in the call, protect the device.
