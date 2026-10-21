# CircuitBreaker evidence bundle format, version 1 (spec revision 1.1)

This document specifies an evidence bundle well enough to verify one without CircuitBreaker's code. It covers what the verifier must check; it does not describe how the gateway produces the files.

Conventions: "hex" is lowercase hexadecimal. `SHA256(x)` is SHA-256 of the byte string `x`. `||` is concatenation. Domain strings are ASCII and include the trailing NUL byte written as `\0`. Every file is UTF-8 text with one JSON object per line, each line ending in `\n` (no blank lines, no trailing data). Journals, checkpoints, key files, and receipts are ASCII. Rekor anchor lines are UTF-8: the signed note in each contains `—` (U+2014).

## 1. Files

A bundle is a directory:

| File | Required | Contents |
| --- | --- | --- |
| `decision.jsonl` | yes | Decision journal: what the gateway allowed and denied (§2) |
| `control.jsonl` | yes | Control journal: what the gateway did about it (§3) |
| `checkpoints.jsonl` | yes in v1 | Signed checkpoints of both journals' heads (§4) |
| `gateway-keys.pub.json` | yes in v1 | The gateway's public keys, as the bundle claims them (§4.1) |
| `rekor-anchors.jsonl` | optional | Checkpoints anchored in a Rekor v1 transparency log (§6) |
| `rekor-log.pub.pem` | with anchors | The log's public key, as the bundle claims it (§6) |
| `report.json` | optional | A summary derived from the files above. Not evidence; a verifier may ignore it |

Every structural rule in this document (key order, exact bytes, field sets) is a requirement, whether or not it has a number. Statement and record objects have exactly the fields listed: an extra or missing field, or a value of the wrong JSON type (for example a number written as a string), makes the bundle invalid.

A verifier is also given, separately from the bundle:
- **trusted gateway keys**: a `gateway-keys.pub.json` obtained another way. Its `gateway_key_id` must be correct for its keys (§4.1) and equal the bundle copy's. Because the ID is a hash of both keys, equal IDs mean equal keys.
- **trusted log key** (if anchors are checked): the Rekor log's public key obtained another way.
- **receipts** (optional): checkpoints that left the gateway's machine when they were made (§5).

## 2. Decision journal (`decision.jsonl`)

**Header** (line 1): `{"format":"circuitbreaker-m2.1","journal_id":"<uuid>"}`, keys in that order. `journal_id` is a lowercase hyphenated UUID.

**Genesis head** `H0 = hex(SHA256("circuitbreaker.m2.genesis\0" || header_line_bytes))`, where `header_line_bytes` is line 1 without its `\n`.

**Records** (lines 2..): `{"body":<BODY>,"sha256":"<hex64>"}`. Each line starts with the 8 bytes `{"body":` and ends with `,"sha256":"` + 64 hex digits + `"}`. `BODY_BYTES` is exactly the bytes between those two parts. For record `n` (1-based):

- `body.format == "circuitbreaker-m2.1"`, `body.sequence == n`, `body.payload.sequence == n`;
- `body.decision_id == "<journal_id>:" + 16 lowercase hex digits of n` (zero-padded);
- `body.previous_sha256 == H(n-1)`;
- `sha256 == hex(SHA256("circuitbreaker.m2.record\0" || BODY_BYTES))`, and `H(n) = sha256`.

`body.payload` holds the decision. Fields a verifier may use: `event` (`LeaseDecision`, `BrokerUse`, `RiskApplied`, `Recovery`, `SimulatedUse`), `outcome` (`ALLOW`, `DENY`, `RESTRICTED`), `epoch`, `state` (`Active`, `Restricted`, `Quarantined`, `Terminated`), `reason`. A trip is recorded here as a `RiskApplied` record that moves `state` to `Quarantined` at `epoch + 1`. The reference verifier also checks the state machine (no permission while quarantined, a recovery only from the recorded quarantine, and so on); those checks are not needed for the challenge.

## 3. Control journal (`control.jsonl`)

**Header**: `{"format":"circuitbreaker-control.1","journal_id":"<uuid>"}`.

**Genesis head** `C0 = hex(SHA256("circuitbreaker-control/genesis\0" || header_line_bytes))`.

**Records**: `{"body":<BODY>,"sha256":"<hex64>"}` with the same line shape as §2. For record `n`:

- `body.format == "circuitbreaker-control.1"`, `body.sequence == n`, `body.previous_sha256 == C(n-1)`;
- `sha256 == hex(SHA256("circuitbreaker-control/entry\0" || BODY_BYTES))`, and `C(n) = sha256`.

`body.entry.kind` is one of: `tripped` (with `trigger`), `kill` (`outcome`: `confirmed`, `failed`, `unknown`, `not_applicable`), `alarm` (`event`, `outcome`: `delivered`, `failed`, `timed_out`, `dropped`), `checkpoint` (`sequence`, `reason`, `statement_sha256`), `anchor` (`checkpoint_sequence`, `outcome`, `log_index`, `detail`), `reset`, `model_use`, `model_uses_suppressed`, `peer_rejected`, `peers_suppressed`, `scope_lost`, `daemon_lost`.

**Checkpoint bookkeeping** entries are: `checkpoint`; `alarm` with `event == "checkpoint"`; and `anchor`. A checkpoint can't cover these records about itself.

## 4. Checkpoints (`checkpoints.jsonl`)

### 4.1 Gateway keys (`gateway-keys.pub.json`)

```json
{"schema_version":"circuitbreaker.gateway-keys.v1","gateway_key_id":"<hex64>","slh_dsa_sha2_128f":"<hex, 32 bytes>","ecdsa_p256":"<hex, 65 bytes, uncompressed point 04||X||Y>"}
```

(Pretty-printed in the file; parse it as JSON.) `gateway_key_id` must equal

`hex(SHA256("circuitbreaker-gateway-keys-v1\0" || u32_be(32) || slh_pk || ecdsa_point))`.

### 4.2 Lines

Each line is a signed checkpoint, keys in this order:

```
{"statement":<STATEMENT>,"statement_sha256":"<hex64>","slh_dsa_sha2_128f":"<hex>","ecdsa_p256_sha256":"<hex>"}
```

### 4.3 Canonical statement bytes

`STATEMENT_BYTES` is the statement encoded as compact JSON (no whitespace) with keys in exactly this order:

```
{"schema_version":"circuitbreaker.checkpoint.v1",
 "gateway_key_id":<hex64>,
 "sequence":<int>,
 "reason":"start"|"tripped"|"reset"|"periodic"|"shutdown",
 "decision":{"journal_id":<uuid>,"sequence":<int>,"head_sha256":<hex64>,"epoch":<int>,"state":<string>},
 "control":{"journal_id":<uuid>,"sequence":<int>,"head_sha256":<hex64>},
 "previous_checkpoint_sha256":<hex64>,
 "wall_time_unix_ms":<int>}
```

Integers are plain decimal. In `checkpoints.jsonl` these are exactly the bytes of the `statement` value in the line. In receipts (§5) the statement may appear with keys in a different order, so re-encode it in this order before hashing or verifying.

### 4.4 Checks for each checkpoint

1. `statement.schema_version == "circuitbreaker.checkpoint.v1"` and `statement.gateway_key_id` equals the trusted keys' `gateway_key_id`.
2. `statement_sha256 == hex(SHA256(STATEMENT_BYTES))` (plain SHA-256, no domain).
3. **ECDSA:** `ecdsa_p256_sha256` is an ASN.1 DER ECDSA signature, P-256 with SHA-256, over `STATEMENT_BYTES`, verifying under the `ecdsa_p256` key.
4. **SLH-DSA:** `slh_dsa_sha2_128f` (17,088 bytes) is a FIPS 205 SLH-DSA-SHA2-128f signature, *pure* (not pre-hash) with context string `ctx = "circuitbreaker-checkpoint-v1"` (28 bytes). Per FIPS 205 Algorithm 23, the internal message is `0x00 || 0x1c || ctx || STATEMENT_BYTES`. It must verify under the `slh_dsa_sha2_128f` public key.
5. **Both signatures must verify.** A checkpoint with one valid signature is invalid.

An empty `checkpoints.jsonl` is allowed and verifies, but it proves nothing about authorship, the bundle is not sealed, and every receipt (§5) then fails as missing.

### 4.5 Chain

For checkpoints in file order `k = 1..N`:

- `statement.sequence == k`;
- `statement.previous_checkpoint_sha256` is 64 zeros for `k = 1`, else checkpoint `k-1`'s `statement_sha256`;
- `decision.journal_id` and `control.journal_id` are the same in every checkpoint, and equal the journals' header `journal_id`s;
- `decision.sequence` and `control.sequence` never decrease.

### 4.6 Heads in the journals

For every checkpoint: `decision.head_sha256 == H(decision.sequence)` from §2 (`H0` when the sequence is 0), and `control.head_sha256 == C(control.sequence)` from §3. Both sequences must be no larger than the journal's record count.

### 4.7 Sealed (informational)

A bundle is *sealed* when the last checkpoint's `decision.sequence` equals the decision journal's record count and every control record after `control.sequence` is checkpoint bookkeeping (§3). An unsealed bundle is not invalid; it means records exist that no checkpoint covers.

## 5. Receipts

Receipts are checkpoints held outside the gateway's machine, for example the alarm log of a separate receiver. A receipts file has one JSON object per line, of one of these kinds:

- an **alarm**: `schema_version == "circuitbreaker.alarm.v1"`. If `event == "checkpoint"`, its `checkpoint` field is a signed checkpoint (same fields as §4.2, keys possibly reordered). Alarms with any other `event` (for example `tripped`) carry no checkpoint and are skipped. Other alarm fields (`scope_unit`, `alarm_sequence`, `unix_time`) are informational;
- a bare **signed checkpoint** (§4.2);
- a **Rekor anchor line** (§6).

For every receipt that carries a checkpoint:

1. it must pass §4.4 (both signatures, under the trusted keys);
2. the bundle must contain a checkpoint with the same `statement.sequence`;
3. that bundle checkpoint must have the same `statement_sha256`.

If the receipt is an anchor line naming a checkpoint the bundle doesn't have, it fails check 2 (missing), before any §6 check. A missing checkpoint (2) means the bundle was cut after that checkpoint left the machine. A different digest (3) means the history was rewritten. Either makes the bundle invalid. Records written after the last receipt are not protected by receipts.

## 6. Rekor anchors (`rekor-anchors.jsonl`)

Each line records one checkpoint logged in a Rekor v1 transparency log:

```
{"schema_version":"circuitbreaker.rekor-anchor.v1","checkpoint_sequence":<int>,"statement_sha256":<hex64>,"log_url":<url>,"uuid":<hex>,"entry":{"body":<base64>,"integratedTime":<int>,"logID":<hex64>,"logIndex":<int>,"verification":{"inclusionProof":{"checkpoint":<signed note>,"hashes":[<hex64>...],"logIndex":<int>,"rootHash":<hex64>,"treeSize":<int>},"signedEntryTimestamp":<base64>}}}
```

`rekor-log.pub.pem` is a PEM `PUBLIC KEY` (ECDSA P-256 SubjectPublicKeyInfo). For each anchor, with the trusted log key:

1. `entry.logID == hex(SHA256(log key SPKI DER))`.
2. **Signed entry timestamp:** `signedEntryTimestamp` (base64 DER ECDSA P-256/SHA-256) verifies under the log key over the bytes `{"body":"<body>","integratedTime":<n>,"logID":"<hex>","logIndex":<n>}` (keys sorted, no whitespace, the four values copied from `entry`; this is the RFC 8785 form for these values).
3. **Leaf:** `leaf = SHA256(0x00 || base64decode(body))`; `uuid` (64 or 80 hex) ends with `hex(leaf)`.
4. **Inclusion:** the RFC 6962 / RFC 9162 §2.1.3.2 inclusion proof with `index = inclusionProof.logIndex`, `size = treeSize`, `hashes` leaf-to-root, interior node `SHA256(0x01 || left || right)`, reaches `rootHash`. (`inclusionProof.logIndex` is within the log's current shard and may be smaller than `entry.logIndex`.)
5. **Signed tree head:** `checkpoint` is a signed note `"<origin>\n<treeSize>\n<base64 root>\n[other lines]\n\n— <name> <base64(keyhint4 || sig)>\n"`. The signed text is everything before the blank line, including its final `\n`. A signature line is one that starts with `—` (U+2014) and a space, then a name, a space, and base64. Some signature line must have `keyhint4 ==` the first 4 bytes of `logID` and an ECDSA P-256/SHA-256 DER signature over that text under the log key. The note's size and root must equal `treeSize` and `rootHash`.
6. **Binding:** `base64decode(body)` is JSON with `apiVersion == "0.0.1"`, `kind == "hashedrekord"`, `spec.data.hash.algorithm == "sha256"`, `spec.data.hash.value ==` the checkpoint's `statement_sha256`; `base64decode(spec.signature.content)` equals the checkpoint's ECDSA signature bytes; and `base64decode(spec.signature.publicKey.content)` is a PEM `PUBLIC KEY` whose SPKI is the gateway's `ecdsa_p256` point (SPKI DER prefix `3059301306072a8648ce3d020106082a8648ce3d030107034200` then the 65-byte point).
7. The bundle's checkpoint `checkpoint_sequence` exists and has the same `statement_sha256`. Anchors appear in strictly increasing `checkpoint_sequence`, all with one `log_url`.
8. Every control-journal `anchor` record with `outcome == "anchored"` has a matching line (same `checkpoint_sequence` and `log_index == entry.logIndex`). If the control journal has any `anchored` record and the bundle has no anchors file, the bundle is invalid.

Anchor lines may also be used as receipts (§5): apply 1–7 against the bundle's checkpoint at that sequence. Anyone can also fetch each entry from the log (`GET <log_url>/api/v1/log/entries/<uuid>`) and compare `body`, `integratedTime`, `logID`, and `logIndex` with the stored ones. This is optional. The inclusion proof and tree head legitimately differ as the log grows.

## 7. Verdict

A bundle is **valid** when every check in §2–§4, §5 for every supplied receipt, and §6 (when anchors are present) passes, with the trusted gateway keys equal to the bundle's copy. Otherwise it is **invalid**. The verdict doesn't depend on the order of checks, but to make reports comparable, run them in this order and name the first that fails: trusted keys (§1, §4.1); decision journal (§2); control journal (§3); each checkpoint in file order (§4.2–§4.4), then the chain and heads (§4.5–§4.6); anchors (§6); receipts in file order (§5).

## 8. What a valid bundle shows, and doesn't

It shows that the holder of the gateway's keys wrote these records in this order, and, with receipts or anchors, that nothing at or before a received or anchored checkpoint was removed or rewritten. It does not show that the gateway recorded everything that happened, protect records after the last checkpoint someone else holds, or stop someone with the gateway's keys from signing new, false checkpoints going forward.

## Changes

- **1.1 (2026-10-21).** Clarifications only; no change to any file format or to which bundles are valid. From the first independent implementation (evidence challenge 1): UTF-8 in anchor lines; key equality by verified key ID; structural rules and exact field sets are requirements; an empty checkpoint file; an anchor receipt naming a missing checkpoint; signature-line syntax in signed notes; strictly increasing anchors; anchored records without an anchors file; the optional live comparison; a fixed order for reporting the first failure.
- **1.0 (2026-10-21).** Published with evidence challenge 1.
