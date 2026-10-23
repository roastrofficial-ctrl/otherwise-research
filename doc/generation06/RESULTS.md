# The boundary found in 0.6

The new implementation is a limited, unreviewed reference harness. Honest release combines verified partial **points** to recover one Capsule's wrapping key and AES key, rather than reconstructing the reusable custody scalar. That is a stronger honest execution path. A malicious threshold still decrypts early, using the same partial-point arithmetic with all policy checks removed. Both outcomes are executable tests.

## Actor-by-actor guarantees

| Actor / condition | Demonstrated result | Classification / qualification |
|---|---|---|
| One extracted custodian | Gets its own signing key, scalar share, DB, public ciphertext and own partial; cannot complete the tested decrypt | Prevented below threshold, assuming discrete-log/DH hardness, independent secrets and trusted provisioning; finite tests are not a cryptographic proof |
| Two malicious custodians | Recover synthetic plaintext before any valid release decision, without reconstructing the private scalar | **Successful**; software gates and recipient encryption cannot stop raw-share owners |
| SaaS operator alone | Cannot forge owner/witness signatures, replace the owner commitment or supply sufficient partials | Prevented for tested capability boundary; can censor, lie, deny service or distribute a malicious client; executing that client with secrets remains a successful attack |
| Honest available quorum | Validates independent witness evidence, commits recipient-encrypted partials, and completes simulated disclosure after authorisation | Recoverable stable-state execution; two custody members suffice, fresh witness quorum required; no unconditional Byzantine liveness claim |
| Wrong recipient / substituted Capsule or ciphertext | Genuine partials fail signature, context, recipient or AES authentication checks | Prevented by verifying participants; a threshold already holding secrets can bypass verification privately |
| Rolled-back/stale evidence | Old nonce responses, changed heads, surviving-anchor omissions and same-sequence signed forks rejected | Detected; concurrent writes may require retry; erased global anchors cannot be recreated from nothing |
| Custody process crash | Pre-commit operation absent; post-commit exact signed/encrypted response survives restart | Recoverable; serial SQLite FULL commit before reply, real process termination tested |
| Whole custody DB rollback | New response differs from independently retained response; mathematical partial remains identical | Detected **only if a surviving external receipt is compared**; no universal rollback claim |
| Compromised creator/dealer | Copies plaintext/AES key or sufficient setup shares before provisioning completes | **Successful**, potentially undetectable; no secure-erasure or malicious-client resistance claim |
| Owner after release fence | Late disarm is refused; enough emitted partials remain usable | **Successful late disclosure**, not a cancellation guarantee |
| Entire Docker host / all independent anchors lost | Host can inspect every state volume and rewrite software | Outside the threat model; containers are not independent organisations |

## Evidence and conformance

Raw records are in [results06](../results06/). `attacks.json` includes capabilities, attempted action, observed result, evidence and classification for every scenario. A detected leak is never counted as prevented. `tests.txt` covers 16 new test methods, including actual TLS services, extraction, threshold bypass, honest recipient recovery, forged decisions, stale heads, substitutions, disarm ordering, service availability, process death before/after commit, DB rollback, creation compromise, encrypted replacement-client recovery, six competing release workers, independent OpenSSL group arithmetic, forked witness snapshots and an actual child-process CLI lifecycle.

The public fixed algebra fixture `reference-vector.json` uses x=5, a=7, r=11 and tests every ordered pair of three shares against `cryptography`/OpenSSL scalar multiplication. It is public test material, not a security parameter choice. Chaum–Pedersen proofs also have mutation/encoding/context negatives. This is an arithmetic cross-check, not an independent full threshold protocol implementation or cryptographic audit. The existing independent Python/Node policy verifier continues to check the unchanged wire4 certificate semantics.

The regression runner re-executes every earlier generation: 20 methods in 0.1, 21 in 0.2, 13 in 0.3, 23 in 0.4 and 16 in 0.5. Together with 16 new methods that is **109 tests**. It also preserves the 194 0.2 proof snapshots, 48 0.3 proof objects, 66 0.4 receipt/release objects and 14 0.5 fresh-envelope vectors, with zero Python/Node disagreements. See `regression/generation02`, `regression/generation03`, and `regression/generation05` (the latter also contains the 0.4 rerun). Old raw artifacts remain unchanged.

The 0.5 SaaS-offline experiment is rerun, not inferred: Laravel, hostile courier and product database are stopped; a replacement client restores an older encrypted backup, recovers later accepted presence, checks in, disarms, rotates, repairs a restarted witness and performs independent missed-window release. Its static-share collusion and compromised-client attacks must remain successful. New 0.6 containers never start Laravel at all. A new standalone CLI also completes the lifecycle using the alternate custody adapter.

## What this does not establish

This does not cryptographically enforce a Boolean release policy against a controlling custody threshold. The exact impossibility argument, timing/snapshot model, disarm race boundary and rollback qualifications are in [SECURITY.md](SECURITY.md). This does not establish DKG, robust share refresh, production recipient key distribution, multi-host independence, external secure time, constant-time Python orchestration, secure memory deletion, an audited hybrid encryption scheme or decades-long operational survivability. The reference composition needs review before even considering real data.
