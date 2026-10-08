# Specification of formats and verification steps

Version 0.3. English translation of [SPEZIFIKATION.md](SPEZIFIKATION.md), which is authoritative. This page describes exactly what the verifier computes so that someone can rebuild it in another language. Three implementations (JavaScript, Python, Rust) pass the same test vectors in `testvektoren/`.

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
