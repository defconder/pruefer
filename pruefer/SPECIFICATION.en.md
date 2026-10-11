# Specification of formats and verification steps

Version 0.4. English translation of [SPEZIFIKATION.md](SPEZIFIKATION.md), which is authoritative. This page describes exactly what the verifier computes so that someone can rebuild it in another language. Three implementations (JavaScript, Python, Rust) pass the same test vectors in `testvektoren/`.

Terms: a hex value is lower case without a prefix. `||` is concatenation. `SHA-256` hashes bytes. Strings are UTF-8. Field and type names in the formats are German identifiers and are kept as they are.

## 1. Events

An event is a JSON object. There are two formats, told apart by the field `hv`.

### 1.1 Old format (no `hv`)

Required fields `seq` (integer, starts at 0), `type`, `prevHash`, `hash`.

```
hash = hex( SHA-256( prevHash || JSON.stringify( event without the field hash ) ) )
```

`JSON.stringify` serialises the fields in the order they have in the event, without whitespace. Implementations in other languages must reproduce field order, number formatting and string escaping of ECMAScript exactly. This format is only verified now, no longer written, except when a field name excludes the new format.

### 1.2 New format (`hv` equals 2)

A version 2 event has the head fields `seq`, `type`, `at`, `hv`, `prevHash`, `feldWurzel`, plus `hash` and `salze`. All other fields are content fields. Their names match `[A-Za-z0-9_]{1,64}`. A salt is a string from `[A-Za-z0-9_-]{16,64}` that belongs to exactly one content field. `salze` contains exactly the names of the content fields.

```
leaf(name)  = SHA-256( 0x00 || canonical({ "n": name, "s": salt, "w": value }) )
feldWurzel  = Merkle root (section 2) over the leaves, fields ascending by UTF-16 code units of the name
head        = { seq, type, at, hv: 2, prevHash, feldWurzel }
hash        = hex( SHA-256( prevHash || canonical(head) ) )
```

`canonical` is JSON without whitespace, keys ascending by UTF-16 code units, strings and numbers as in `JSON.stringify`. For values made of strings, integers, booleans, lists and objects that is RFC 8785. Floating point numbers are excluded from the test vectors because their representation differs between languages.

Because the hash only depends on the head and the field root, content fields can be hidden without changing the hash (section 4).

The first event has `prevHash` of 64 zeros. For two events with consecutive `seq` the verifier requires the later one to name the `hash` of the earlier one as `prevHash`.

## 2. Merkle tree

RFC 6962 and RFC 9162 with SHA-256.

- Leaf `i` of the log is `SHA-256( 0x00 || UTF-8( hash_i ) )` where `hash_i` is the hex string of the hash of the event with `seq = i`.
- An inner node is `SHA-256( 0x01 || left || right )`.
- With `n` leaves, `k` is the largest power of two smaller than `n`.
- The empty tree has the root `SHA-256( "" )`.

Inclusion proofs follow RFC 9162 section 2.1.3, consistency proofs section 2.1.4. The verifier limits tree sizes to 2^31 - 1 and proof paths to 64 elements. Other trees (field tree, index) use the same splitting, their leaves are `SHA-256( 0x00 || data )` with the data described there.

## 3. Tree head of a package

```
treeHead: { treeSize, rootHash (hex), headHash (hex), at (ms since 1970),
            signature: { keyId, algorithm: "Ed25519", signature (hex) }, publicKeyPem }
```

`keyId` is the hex string of the first 16 bytes of `SHA-256( SPKI DER of the public key )`. The signed message is the UTF-8 form of `canonical({ treeSize, rootHash, headHash, at, keyId })`.

## 4. Evidence package `defconder-beweispaket-1`

```
{ schema, createdAt, exporter, purpose, asset, treeHead, events: [ entry ], analyses, original, transparenz?, hinweise }
entry = { event, proof } | { auszug, proof }
```

`proof` is the inclusion proof of the event in the tree of the tree head. `asset.sha256` is the hash of the original file. `analyses[i].result.outputDigest` is the SHA-256 of `canonical({ findings (without the field id), artifacts })`. Recordings carry a segment chain: `SHA-256( previousChain || "|" || sha256 || "|" || index || "|" || size || "|" || startMs || "|" || endMs )`.

### 4.1 Extract `defconder-auszug-1`

```
{ schema, kopf: { seq, type, at, hv: 2, prevHash, feldWurzel, hash }, blaetter: [ leaf ] }
leaf = { h: hex }                        hidden field, only the leaf
     | { n: name, s: salt, w: value }    open field
```

The leaves are in the order of the field tree. The verifier computes the leaves of open fields from `n`, `s`, `w`, takes the hidden leaves as given, builds the root, compares it to `feldWurzel` and derives `hash` from it. Open names must be ascending and unique. Hidden field names and values appear nowhere in the extract.

## 5. Checkpoint (transparency log)

A checkpoint is a signed note per [c2sp.org/signed-note](https://c2sp.org/signed-note) with the text per [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint):

```
<origin>\n
<treeSize decimal>\n
<rootHash Base64>\n
<extension line>\n           (zero or more)
\n
U+2014 U+0020 <name> U+0020 <Base64( key id(4 bytes) || signature )>\n
```

- Every signature line starts with the dash U+2014 and a space.
- Key id `= SHA-256( name || 0x0A || type || key )[:4]`. Type `0x01` is an Ed25519 signature of the log over the text. Type `0x04` is the cosignature of a witness.
- Cosignature (cosignature/v1): the signature is `time (8 bytes, big endian) || Ed25519( "cosignature/v1\ntime <time decimal>\n" || text )`.
- A key is exchanged as `name+id(hex)+Base64(type || 32 bytes)`.
- Base64 must be canonical. Signatures of unknown keys are ignored. If the signature of a known key fails, the verifier rejects the whole checkpoint.

Extension lines are part of the signed text and are cosigned by the witnesses. Defined:

```
defconder-index-1 <number of index entries decimal> <index root Base64>
defconder-index-2 <number of index entries decimal> <index root Base64>
defconder-zeitanker-1 bitcoin <block header, 160 hex characters>
```

## 6. Block `transparenz` in a package

```
transparenz: { logSchluessel, notiz, konsistenz: { von, bis, pfad: [hex] } | null }
```

`notiz` is the checkpoint as text. If its tree size equals `treeHead.treeSize` the roots must be equal. Otherwise the verifier requires `konsistenz` between the smaller and the larger size. The events with `seq` below the smaller size are covered.

## 7. Verification steps and trust levels of a package

1. Shape of the package and input limits (at most 200000 events, proof paths at most 64 elements).
2. Key id and signature of the tree head.
3. If pinned key ids are given: does the key belong to them, possibly after the key rotations (section 11)?
4. Hash and inclusion proof of every event or extract, chaining of consecutive events.
5. Original file, result digests, segment chain.
6. If `transparenz` is present: log signature, cosignatures of pinned witnesses (at least `schwelle`), binding of the tree head to the checkpoint, time anchor.

Level 0: steps 1 to 5 passed. Level 1: additionally step 3 with a pinned key. Level 2: steps 4 and 6 passed with a pinned log key and the demanded number of pinned witnesses. If witnesses are pinned but too few cosignatures are valid, the checkpoint fails. If the block `transparenz` is missing altogether although witnesses are pinned, the package fails. With the option `mindestStufe` a document only passes if at least that level is reached.

## 8. Statement about the log `defconder-aussage-1`

Proves completeness and absence relative to an index whose root is in the checkpoint.

### 8.1 Index

Key fields: `id, recordId, userId, actorId, createdBy, executedBy, publishedBy, deletedBy, uploadedBy, approvedBy, sha256, assetId, entityTypeId, actionTypeId, objectId, username, purposeId, apiKeyId`.

For every event `e` these keys arise (without repetition): `typ=<type>`, and for every key field `F` with string `V` of length 1 to 200: `F=V` and `<type>|F=V`.

Each key owns the list of event hashes in order of `seq` and

```
chain_0 = 32 zero bytes,  chain_i = SHA-256( chain_(i-1) || raw bytes(hash_i) )
leafdata = SHA-256( "indexregeln-1\n" || key ) || count (8 bytes, big endian) || chain_n
```

The leaves of the index are `SHA-256( 0x00 || leafdata )`, ascending by the first component (key hash, bytewise). Two boundary leaves are always present: key hash of 32 zero bytes and of 32 bytes 0xFF, each with count 0 and chain of zero bytes. The root of this tree is in the extension line `defconder-index-1`. The index covers the events with `seq` below the tree size of the checkpoint.

### 8.2 Statements

```
{ schema, regeln: "indexregeln-1", notiz, logSchluessel, aussagen: [ ... ] }
vorhanden: { art, schluessel, anzahl, kette, index, pfad, ereignisse?: [hex], belege?: [{ seq, pfad }] }
abwesend:  { art, schluessel, links: leaf, rechts: leaf }        leaf = { keyHash, anzahl, kette, index, pfad }
```

`vorhanden` (present) is valid if the leaf of key hash, `anzahl`, `kette` lies in the index at `index` and `anzahl` is at least 1. If `ereignisse` is given there must be `anzahl` distinct hashes whose chain yields `kette`. If `belege` is given every event lies in the tree of the checkpoint, in ascending `seq`. `abwesend` (absent) is valid if both leaves lie in the index, their indexes are adjacent and `links.keyHash < key hash < rechts.keyHash`.

Limit: the verifier cannot check whether the index was derived completely from the log. That is done by recomputing it from the full log (observer).

## 9. Decision proof `defconder-entscheidung-1`

```
{ schema, notiz, logSchluessel, seq, ereignisse: [ { event | auszug, pfad } ] }
```

The event with `seq` carries a field `belege` (receipts). Each receipt:

```
{ regel, regelstand, eingaben, ergebnis, abstand?, anzahl?, endgueltig?, grund? }
```

`regelstand` is `hex( SHA-256( canonical(rule) ) )` of a rule that stands in an event `RegelstandVeroeffentlicht` (fields `regelId`, `regelstand`, `regel`) with a smaller sequence number. The events must lie in the checkpoint (inclusion proof against its root).

### 9.1 Rule language `regeln-1`

`{ sprache: "regeln-1", id, art, ... }`.

- `art: "stufen"` with `stufen: [{ id, ton }]`. Inputs `{ nutzer, objekt }` (tones from the levels). `abstand = max(0, nutzer - objekt)`. Result `erlaubt` (allowed) if the distance is 0, else `verweigert` (denied).
- `art: "matrix"` with `erlaubt: { purpose: [category] }` and `immerErlaubt: [category]`. Inputs `{ zweck, kategorie }`. Result `erlaubt` if the category is empty, in `immerErlaubt` or in `erlaubt[zweck]`, else `verweigert`.

The verifier computes every rule itself: for levels all combinations (the same level is allowed, a higher clearance never allows less, a less secret object is never treated more strictly), for matrices all listed pairs. It relies on no external prover. The rules are so small that the enumeration is the proof.

If a receipt carries `endgueltig: "verweigert"` with `grund: "freigabestufe"` the rule must yield `verweigert`. With `grund: "formale-pruefung"` the rule must yield `erlaubt`, the final denial then comes from a further check of the application that the verifier does not recompute.

## 10. Time anchor

`defconder-zeitanker-1 bitcoin <header>`: 80 bytes of block header in hex. The verifier computes `SHA-256( SHA-256( header ) )`, reverses the bytes (block hash), checks it against the target from `nBits` (mantissa without sign bit, exponent 3 to 32) and computes the work as `floor( log2( 2^256 / (target + 1) ) )` bits. It demands a minimum work (default 64 bits). The checkpoint came into being at the earliest two hours before the block time. This proves "not earlier than", not "not later than".

## 11. Key rotation `defconder-schluesselwechsel-1`

```
{ schema, von, nach, at, entzieht, vonPem, nachPem, signatur }
```

The old key signs `canonical({ schema, von, nach, at, entzieht })`. The verifier follows a chain of rotations starting from the pinned ids. `entzieht: true` removes the old key from the set of accepted keys.

## 12. Contradiction proof `defconder-widerspruch-1`

```
{ schema, logSchluessel, a, b }
```

`a` and `b` are checkpoints. A contradiction is proven if both carry the valid log signature, have the same tree size and different roots. Anyone can recompute that. A rollback or a missing consistency proof is not a cryptographic proof, the observer reports it as an alarm with evidence.


## 13. Hash-based signature (SLH-DSA)

A log may sign its checkpoint additionally with a hash-based scheme per FIPS 205. The scheme only computes with SHA-256 and stays secure against a quantum computer as long as SHA-256 holds. SLH-DSA-SHA2-128s (signature 7856 bytes) and SLH-DSA-SHA2-128f (17088 bytes) are supported. The external form with a context string (`slh_sign`, `slh_verify`) is used, not the pre-hashed one.

Key: `name+id+Base64( 0xFF || scheme identifier || 0x00 || public key )`. The scheme identifier is the ASCII string `defconder-slh-dsa-sha2-128s-1` or `defconder-slh-dsa-sha2-128f-1`, the public key has 32 bytes (PK.seed || PK.root). Per c2sp.org/signed-note the type byte `0xFF` stands for types without a type byte of their own. The key id is `SHA-256( name || 0x0A || 0xFF || scheme identifier || 0x00 || key )[:4]`.

Signature line: as in section 5, with the signature as value. What is signed is the text of the checkpoint (all bytes up to and including the line break before the blank line) with the context string `defconder-pruefpunkt-1`. The line carries the name of the log and sits after the cosignatures of the witnesses, who never see it. There are no cosignatures by witnesses with a hash-based scheme. For cosignatures C2SP knows the type `0x06` with ML-DSA-44, which the verifier does not check.

Whoever pins a hash-based log key demands exactly one valid signature of that key. If it is missing or invalid, the checkpoint fails. Without a pinned key the line is ignored like any signature of an unknown key.

## 14. Time proof `defconder-zeitbeweis-1`

Proves that a checkpoint existed at the latest at a Bitcoin block time. It adds an upper bound to the lower bound of the time anchor (section 10).

```
{ schema, notiz, logSchluessel?, ots: Base64(file in the OpenTimestamps format), koepfe: { "<height>": <block header, 160 hex characters> } }
```

What is stamped is `SHA-256` over the text of the checkpoint as in section 13. The file `ots` starts with the 31 bytes `00 "OpenTimestamps" 00 00 "Proof" 00 BF 89 E2 E8 84 E8 92 94`, then major version 1 (length number in LEB128), the byte `08` (SHA-256), 32 bytes of digest and the tree of steps. A node reads one byte. `FF` announces another branch and the next byte names its kind. `00` is an attestation: 8 bytes of kind, then a payload preceded by its length. All other bytes are operations on the running message:

| Byte | Operation |
|---|---|
| `08` | SHA-256 |
| `03` | RIPEMD-160 |
| `F0` | append (argument with length number, at least 1 byte) |
| `F1` | prepend (likewise) |
| `F2` | reverse the bytes |
| `F3` | write out as lower-case hex characters |

The verifier rejects SHA-1 (`02`) and Keccak-256 (`67`). After the operation comes the subtree for the result. Attestation kinds: `05 88 96 0D 73 D7 19 01` is Bitcoin (payload the block height as a length number, nothing else), `83 DF E3 0D 2E F9 0C 8E` is pending, other kinds are ignored. Limits: file at most 1000000 bytes, message at most 4096 bytes, depth at most 256, nodes at most 20000, length numbers at most 5 bytes, no bytes after the tree.

For a Bitcoin attestation the message at the end of the path must equal bytes 36 to 67 of the block header at that height. The header must meet its target and carry the minimum work (section 10). The verifier cautiously uses the block time plus two hours as the latest moment. If the checkpoint names a time anchor, lower and upper bound must fit together.

## 15. Audit sample `defconder-stichprobe-1`

Draws events from the log using randomness the operator did not know when committing, and states a bound on the share of violating events from error-free draws.

```
{ schema, notiz, logSchluessel?, regel: { anzahl, abstand, konfidenz, pruefungen: [ "kette", "index", "entscheidung" ] },
  zeitbeweis: { ots, koepfe }, zufall: { koepfe: [ block header ] }, proben: [ Probe ] }
```

`zeitbeweis` confirms the checkpoint (section 14) in a block of height `h`. `zufall.koepfe` are exactly `abstand` block headers of heights `h+1` to `h+abstand`, each with valid work and its predecessor in the `prev` field of the header. The randomness is the block hash of the last header in the usual notation (with leading zeros) as 32 bytes.

```
seed = SHA-256( "defconder-stichprobe-1" || 0x00 || root of the checkpoint (32) || randomness (32) || tree size (8, big-endian) || anzahl (8, big-endian) )
draw z = 0, 1, 2, ...: w = first 8 bytes of SHA-256( seed || z (8, big-endian) ) as an unsigned number
                       limit = floor( 2^64 / tree size ) * tree size
                       if w >= limit, z is skipped, otherwise w mod tree size is the next draw
```

There are `anzahl` draws with replacement. `proben` holds exactly one entry per drawn sequence number, ascending:

```
Probe = { seq, event | auszug, pfad, vorgaenger?: { hash, pfad }, indexBelege?: [ { schluessel, keyHash, anzahl, kette, index, pfad } ], entscheidung?: { ereignisse } }
```

Depending on `pruefungen` the verifier checks: chain (hash of the event, inclusion at `seq`, for `seq` above 0 the hash of the predecessor equal to `prevHash` with inclusion, for `seq` 0 `prevHash` of 64 zeros), index (for every key of the event a leaf with count at least 1, only for an open event) and decision (every event of the types `AccessDenied` and `FederatedQueryExecuted` carries receipts that a decision proof per section 9 confirms). A single violation makes the sample fail, and it names no bound. Otherwise: with certainty `konfidenz` the share of violating events is below `1 - (1 - konfidenz)^(1/anzahl)`.

The bound says nothing about single rare violations. It only holds if the checkpoint is confirmed by witnesses, otherwise the operator could have prepared several and presented the favourable one later.

## 16. Index rules 2 (count statements)

`indexregeln-2` extends the keys of section 8.1. If an event has a field `at` holding an integer from 0 to 253402300799999 (milliseconds since 1970), let `M` be the calendar month in UTC in the form `YYYY-MM`. To the existing keys come `monat=M` and, for every existing key `K`, the key `K|monat=M`. The key hash starts with `indexregeln-2\n`, the extension line is called `defconder-index-2`. A checkpoint carries exactly one index line, a statement names the same rules as the checkpoint.

A statement without `ereignisse` thus proves the number of events of a type in a month without showing the events. Whoever adds the proven numbers gets the sum over several months.

## 17. Release only against a log entry

Data lies encrypted. The key is shared among `n` key custodians, `k` of them suffice. A custodian only hands out its share if the request appears in the log of a checkpoint confirmed by witnesses. Whoever decrypted has therefore left an entry.

Sharing: Shamir over GF(2^8) with the polynomial `x^8 + x^4 + x^3 + x + 1`. A share is `x (1 to 255) || y bytes`. Request: an event of type `ZugriffAngefragt` with the fields `objectId` and `empfaengerSchluessel` (public X25519 key, 32 bytes, Base64). The custodian checks the checkpoint against its pinned keys (log, witnesses, threshold), the inclusion and the type of the event. It answers with the receipt and the share, encrypted to the recipient: X25519 with an ephemeral key, `HKDF-SHA-256( secret, salt = raw bytes of the request hash, info = "defconder-freigabe-1", 32 bytes )`, AES-256-GCM with the raw bytes of the request hash as additional data.

```
Quittung = { schema: "defconder-freigabequittung-1", hueter, anfrageHash, seq, objektId, nutzerId | null, groesse, wurzel, at, anteil, signatur }
```

`signatur` is the Ed25519 signature of the custodian (type `0x01`) over `canonical( receipt without signatur )`, hex. `groesse` and `wurzel` name the checkpoint the custodian saw.

### 17.1 Release proof `defconder-freigabe-1`

```
{ schema, notiz, logSchluessel?, anfrage: { event | auszug, pfad }, objektId, nutzerId?, hueter?, schwelle?, quittungen: [ Quittung ], konsistenz?: { "<from>-<to>": { pfad } } }
```

The verifier demands: a valid checkpoint, the request lies at `seq` in the checkpoint and names `objectId` equal to `objektId`, at least `schwelle` receipts of different pinned custodians with a valid signature that name exactly this request (hash, `seq`, object, user) and a state `groesse` above `seq` and at most the size of the checkpoint. If `groesse` is smaller it demands the consistency proof from `groesse` to the size of the checkpoint with the root of the receipt as the old root.

### 17.2 Release report `defconder-freigabebericht-1`

On request a custodian signs a statement `{ schema: "defconder-freigabeauskunft-1", hueter, objektId, quittungen: [ { anfrageHash, at } ], bis, anzahlGesamt, signatur }` with the same rules for `signatur`.

```
{ schema, objektId, schwelle, auskuenfte: [ statement ], weitereQuittungen?: [ Quittung ], aussage?: statement about the log }
```

With `n` pinned custodians and threshold `k` the verifier demands at least `n - k + 1` valid statements. If none lists a receipt, at most `k - 1` custodians can have issued one, and a key could not have been released. A receipt in `weitereQuittungen` that a statement of the same custodian omits makes the report invalid. If `aussage` is attached (section 8), every named request must be among the log's events for `objectId`.

Limits: The custodians must work independently of each other. Whoever brings `k` custodians to their side decrypts without an entry. An entry only appears in the next confirmed checkpoint, which costs time. Whoever has the plaintext can copy it.

### 17.3 Delivery `defconder-lieferung-1` and share checksum

A custodian signs for every envelope it hands out: `{ schema: "defconder-lieferung-1", hueter, anfrageHash, objektId, huelle, signatur }`. `huelle` is SHA-256 over the canonical JSON form of the envelope (`fluechtig`, `nonce`, `text`, `tag`). The checksum of a share is SHA-256 over `defconder-anteil-1`, 0x00, the object id, 0x00 and the bytes of the share (the first byte is its number). Whoever splits the secret fixes the checksums and stores them with the object.

Evidence against a custodian consists of the delivery, the envelope, the envelope key of that one delivery, request, object, number and the fixed checksum. It holds if the signature is valid, the envelope belongs to the delivery, the envelope opens with the key (so the authentication tag of the encryption is valid) and the share inside does not match the fixed checksum. An envelope that does not open proves nothing against the custodian, because the recipient could name a wrong key. The checksums themselves must be obtained by the verifier from the party that split the secret. The implementation is in `hueter/empfang.mjs`; there is no verifier for deliveries in the browser yet.

## 18. Proof renewal `defconder-erneuerung-1`

Keeps the evidential value of a checkpoint beyond the break of a scheme. Whoever forges a signature after Ed25519 is broken cannot date it before the quantum age if the checkpoint stood in a time proof under another scheme before.

```
{ schema, notiz, logSchluessel?, glieder: [ Glied ] }
Glied = { schema: "defconder-erneuerungsglied-1", vorher, zeit, verfahren, schluessel, signatur, zeitbeweis?: { ots, koepfe } }
```

`vorher` is `hex( SHA-256( text of the checkpoint ) )` for the first link and otherwise `hex( SHA-256( canonical( previous link without zeitbeweis ) ) )`. `signatur` is the signature of the key (hash-based with the context string `defconder-erneuerung-1`, or Ed25519) over `canonical( link without signatur and zeitbeweis )`, hex. The time proof stamps `SHA-256( canonical( link without zeitbeweis ) )`, that is, the file with exactly that text. The times rise, and every stated time is not after the confirmed moment.

With the assumption `scheme = date` the verifier demands for every scheme assumed broken a link of another kind whose confirmed moment lies before the date and which, by the assumption, was itself not yet broken at that moment.

## 19. Release of the verifier `defconder-pruefer-release-1`

```
{ manifest: { schema, version, htmlSha256, summenSha256, dateien }, signaturen: [ { verfahren, schluessel, signatur } ] }
```

`htmlSha256` is the SHA-256 of the file `pruefer.html`, `summenSha256` that of the list `SHA256SUMS` (hash and path of all files of the verifier). The page is built reproducibly, the build yields the same bytes for the same source. What is signed is `canonical( manifest )`, once with Ed25519 and once hash-based (context string `defconder-release-1`). Whoever pins keys demands a valid signature from every pinned key.
