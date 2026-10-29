# Protocol profile 0.7

The original wire4 manifest/policy/receipts and wire5 nonce-bound inspections retain their meaning. This is a separately versioned custody sidecar and transport adapter. Old clients/providers fail explicit profile negotiation; no old armed Capsule is silently upgraded.

## Encryption and immutable commitment

The trusted creator obtains a random AES-128 content key DEK, chooses independent uniform 128-bit A and sets B=A XOR DEK. A and B are separately wrapped with independent 2/3 threshold-DH keys from the 0.6 reference construction (P-256, HKDF-SHA256 and AES-GCM). Both components are required. Content is encrypted once with AES-GCM and the preserved Capsule/policy AAD. A random 16-byte salt precedes synthetic plaintext inside the ciphertext; the sidecar commits SHA256(`otherwise07-plaintext\0` || salt || plaintext). The recipient verifies this commitment after authenticated decryption. No public plaintext salt is supplied.

The owner-signed sidecar contains exactly `v=7`, `suite`, `epoch`, immutable signed `manifest`, recipient public key, `domains`, `wraps`, and `plaintext_commitment`. Each domain commits its generation epoch, public threshold key/verifying shares, and three distinct Ed25519 member identities. All six identities and the two generation public points must be distinct. This is useful substitution checking, **not proof of independently unknown private secrets or separate administrators** (U demonstrates the distinction).

Wrap contexts bind protocol/suite, Capsule/manifest/ciphertext digest, recipient, policy version, Capsule epoch, domain/key epoch, both committee descriptions and plaintext commitment. Partial contexts additionally bind sidecar digest, release-attempt ID, authorisation hash, a named finality-certificate head and participant set. Exact canonical ASCII JSON, integer bounds and domain-separated hashes/signatures follow the retained protocol rules.

`evidence_head = SHA256(canonical({finality_certificate: certificate}))` names one immutable complete certificate, rather than the variable union of every record returned by different snapshot samples. This is a **versioned new context rule**, not a reinterpretation of a v6 head. Each holder still independently obtains a fresh signed 3/4 snapshot quorum, preserves known prefixes and checks vetoes. Agreement on the named certificate does not assert a globally atomic read or total order of all messages.

## Individual and collective verification

1. Each `/enroll07` verifies the owner signature, member identity, local private/public share consistency, domain/epoch and immutable sidecar. An enrolled Capsule cannot change its commitment.
2. Each `/partial07` verifies requirements and supplied context, fetches witnesses concurrently, excludes malformed/rolled-back sources and requires three authenticated fresh snapshots. It checks ARM quorum, disarm/presence vetoes and the complete release certificate. Python and the preserved independent Node policy evaluator must agree.
3. The holder computes D_i=x_i*R with the retained context-tagged Chaum–Pedersen proof. It encrypts the proof/point to the committed X25519 recipient and signs the exact outer context/index/box. SQLite FULL commits the response before reply; retries return the same response for the same operation digest.
4. The recipient authenticates the pinned source, exact context, inner/outer index and DLEQ equations against the committed verification share. A valid signature does not substitute for valid arithmetic. A valid proof does not substitute for valid policy.
5. Collection excludes bad replies independently, deduplicates source identities, sorts compatible valid responses and requires two in **each** domain. Surplus custody replies cannot replace an authorisation reply. The recipient combines points, unwraps A and B, XORs DEK, checks AEAD and the salted plaintext commitment.
6. The separate `Missing.recipient` client has an independently installed expected sidecar/ciphertext and recipient secret, no owner seed. It queries fresh pinned witnesses itself and verifies the complete package; it does not accept a SaaS success Boolean or a self-authenticating replacement commitment chosen by a combiner.

The primitive encoding/proof transcript retains its v6 format/domain label inside an explicitly v7-scoped context. It is not RFC 9497 wire conformance or a newly invented primitive. The independent Node P-256/DLEQ implementation and Python evaluate 23 fixed signed proof objects and three strict-parser negatives. Full wire4 policy conformance is separately retained; the new helper alone does not establish lifecycle validity.

## Independently retained operation evidence

After verifying responses, the client distributes each selected encrypted response plus signed sidecar and certificate to witnesses via `/retain07`, obtaining at least three distinct signed storage acknowledgements before reporting the durable simulated workflow complete. Witnesses authenticate the holder and context; they **do not** attest mathematical validity of encrypted inner content. `/inspect07` returns fresh nonce-bound signed operation journals.

Three-of-four write/read quorums intersect in at least two holders, at least one honest under f<=1. Retention therefore does not depend on SaaS or the latest creator device. A restored old encrypted vault can retrieve later contributions, verify them individually and recover the release. `recover_journal` filters invalid/cross-operation records and deduplicates valid sources before combination. Changed replies for a restored custody DB can be compared with independently retained signed replies. If every anchor/key is rolled back or lost, no universal detection/recovery claim holds.

Existing wire4 repair checkpoints deliberately do not silently acquire v7 fields. Restart repair preserves lifecycle records; it does not transfer a missing v7 operation journal. The surviving three witness holders can serve retained journals under one loss; repairing/replacing journal replicas and membership is unfinished work. Already available partials are not made unavailable by a failed retention acknowledgement.

## Finality, disarm, expiry and replay

Each honest witness durably commits its first local FINAL or DISARM for the relevant lifecycle. A complete release finality certificate needs three distinct witnesses; so does disarm. Under f<=1 their intersection includes an honest node that cannot sign both. Test H exercises one FINAL followed by three DISARMs, and separately complete FINAL closure followed by refused late disarm. This establishes outcomes from signed protocol records, not observed wall time.

Release permission becomes irreversible at a valid complete witness closure certificate, **not when the SaaS worker runs or the last cryptographic partial arrives**. However, the inherited wire4 disarm gate rejects **any own FINAL**, even a PRESENT final for an earlier window. Consequently disarm can already be unavailable while the overall policy remains unsatisfied and a later window is still open. Test V retains this successful cancellation-denial counterexample. Early accepted disarm still prevents honest-domain capability release. This generation documents the gap; changing it requires versioned lifecycle/finality rules, not a hidden owner/admin bypass. A split can prevent both quorums; even an individually authentic retained DISARM conservatively vetoes a holder, so cancellation failure must be reported as uncertain. A fully colluding two-domain coalition can ignore every gate; no clawback claim applies.

Identical authorised retries are idempotent, not “replay attacks”. Cross-Capsule/domain/recipient/policy/epoch/certificate contexts fail binding or proof/AEAD checks. Contract and proof expiry remain evaluated at the committed finalisation snapshot under wire4; expiry does not revoke a previously irreversible valid release or emitted capabilities. New head/key/policy rules require a new immutable Capsule, not an amendment to an armed one.

## Transport and replacement

HTTPS is the reference transport; byte transport does not determine policy truth. Laravel, account systems and PorterNet are absent from the protocol image. `CAPABILITIES` explicitly advertises two indispensable domains, unreviewed trusted-dealer setup and **no cryptographic policy enforcement against a combined quorum**. A requester demanding that last guarantee is rejected. Migration to another implementation requires matching the suite, versioned commitment, thresholds, provenance, recovery and evidence semantics; changing wire4 witness policy meaning is not permitted.
