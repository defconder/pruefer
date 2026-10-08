# Threat model

Version 0.3. English translation of [BEDROHUNGSMODELL.md](BEDROHUNGSMODELL.md), which is authoritative. What the verifier defends against, what it does not, and what that depends on.

## What is protected

The claim: an event or file stood in a log at a point in time, and the log has since only been appended to, never changed. In addition, statements about the log (for a key there are exactly these events, there are none) and proofs that a decision matched the published rule.

## Attackers and effect

| Attacker | Goal | Level 0 | Level 1 | Level 2 |
|---|---|---|---|---|
| Someone changing a document in transit | change content, file or finding | defended | defended | defended |
| Someone inventing a document with their own key | pass a forgery off as the operator's | **not defended** | defended if the operator key id is right | defended |
| Operator or administrator rewriting the log before signing | change or remove events after the fact | **not defended** | **not defended** | defended unless enough witnesses collude |
| Operator showing different observers different truths | tell two stories | not defended | not defended | defended once an observer compares both states, provable for the same size |
| Operator rolling the tree back | make events disappear | not defended | not defended | defended, witnesses refuse smaller sizes |
| Stolen operator signing key | create documents in the operator's name | not defended | not defended | useless for rewriting, not for new, valid-looking events |
| Operator omitting events in a statement | claim "there were no accesses" | not defended | not defended | defended only by recomputing the index from the full log |
| Operator deciding by other rules than published | change rules secretly | not defended | not defended | defended for decisions with a receipt, every rule change is in the log |
| Someone forging an extract | swap hidden fields | defended, the event hash binds them | defended | defended |
| Someone forging a time anchor | make a document look older | partly, the block must carry the demanded work | partly | partly, the anchor proves "not earlier than", not "not later than" |

## Assumptions behind level 2

1. The verifier knows the log key and the witness keys through a channel the operator does not control.
2. At least the demanded number of witnesses is **not** in league with the operator and was not compromised.
3. The first state a witness sees is not already falsified. Witnesses trust the operator the first time. A log rewritten before the first cosignature does not stand out. The operator should use witnesses from the first day.
4. SHA-256 and Ed25519 stay secure. Ed25519 does not protect against quantum computers.

## Observer

An observer fetches the checkpoint, verifies the signature, demands a consistency proof for every new state and remembers all states it has seen. It detects rollback, rewriting and, unlike a single witness, two truths. Two signed checkpoints of the same size with different roots are a proof anyone can recompute. The more independent observers there are (witnesses, authorities, the citizen app), the harder it is to hide fraud. An observer cannot prove anything the operator did not sign itself.

## Further risks

| Risk | Countermeasure | Remainder |
|---|---|---|
| A modified `pruefer.html` fakes good results | reproducible build, hash, signed manifest, policy against network connections | whoever does not compare the hash carries the risk |
| The operator key id arrives through the same channel as the document | obtain the id through a second channel | up to the user |
| Two implementations compute the event hash differently | version 2 with canonical JSON and field tree, test vectors, three implementations | the old format depends on `JSON.stringify` and is only verified now |
| Deliberately huge or nested input | limits on event count, proof length, field count and tree size | very large packages need memory |
| Implementation bugs | three implementations in three languages against the same test vectors (by the same author, an implementation by third parties is still missing), random mutation tests, enumeration of all tree sizes up to 70 | no independent audit |
| Time | cosignatures carry the witness time, time anchors the block time | they prove "not earlier than", not "not later than"; no qualified timestamp |
| The index leaves events out | recompute with the full log | whoever cannot see the log cannot recompute it |
| A key field is not recognised | key fields are fixed in the index rules | an event carrying its identifier in another field does not appear under that key |
| The inputs of a decision were recorded wrongly | none, the proof only shows agreement with the rule | the proof says nothing about the correctness of the rule or the inputs |
