# Reproducible hostile laboratory

Only synthetic messages and simulated local disclosure are used. The machine ledger `doc/results07/attacks.json` contains attacker capabilities, action, exact public inputs and selected deliberately synthetic secret fixtures, observed outputs, classification and test identifiers. Never reuse those fixture keys/material for real content. Complete test, policy/proof conformance, process-recovery and resource outputs are beside it. Each run has separate custodian/authority identities, persistent own volumes and TLS credentials.

| Experiment | Attack and actual result | Classification |
|---|---|---|
| A | Extract every custody member's scalar, signing identity, TLS key and DB; raw arithmetic opens A, but wrong-domain unwrap/AES attempts fail without B | Prevented under secure-independent-setup and primitive assumptions; not merely honest API refusal |
| B | Extract every authorisation member's secrets; recover B, but cannot open custody wrap/AES without A | Prevented under symmetric assumptions |
| C | Extract enough members in both domains; compute raw partial points, unwrap A and B, XOR DEK and decrypt before authorisation | **Successful**; no reusable scalar reconstruction required |
| D | Honest 2+2 contributions with valid independently witnessed finality; recipient verifies all arithmetic and final commitment; encrypted replies durably retained | Recoverable legitimate release |
| E | Forged SaaS release certificate with self-computed hash but no valid witness finals | Prevented at all six honest holders |
| F | Combined attackers produce correctly signed, mathematically valid contributions scoped to an unauthorised statement | Detected/rejected by honest recipient's policy check; C shows the coalition can bypass that verifier privately |
| G | Swap ciphertext/Capsule/recipient/policy version/evidence head/membership/key epoch/attempt/suite; duplicate a source or reuse another Capsule's partials | Prevented by authentic context, proof, threshold and AEAD checks |
| H | One local FINAL then three DISARMs; separate valid release closure then late disarm | Recoverable expected ordering: early completed disarm blocks honest release; late cancellation unavailable. V qualifies the earlier-fence gap |
| I | Malicious creation process retains DEK before distribution; also tries an explicitly aliased member set | **Successful** early decrypt; visibly identical members rejected, but creator secrecy/erasure is not proved |
| J | Retire old Capsule and create fresh domain generations/epoch; try old secrets on new wraps | Old secrets fail against new ciphertext, but **successful** historical decrypt remains. No in-place resharing claim |
| K | One shared Docker/backup administrator extracts both domains | **Successful**; nominal committee count does not equal compromise-domain count |
| L | Dishonest combiner gives mixed-domain bundle, wrong recipient or forged success | Prevented by independent recipient verification rather than server status |
| M | One holder per domain returns malformed data, signed invalid proof or six-second delay | Recoverable: select the remaining verified 2/domain; retain invalid response evidence; no downgrade |
| N | Reorder results, duplicate another source's payload, miss a declared deadline | Valid sources retained in deterministic order; invalid/deadline outcomes excluded; test transcript in `tests.txt` |
| O | Delete/latest creator state by restoring old encrypted vault; roll back custodian DB after operation | Recoverable via fresh independently retained witness journals; differing retry detectable against surviving signed original |
| P | Lose one custodian and one authorisation holder; then lose threshold in custody | Recoverable with surviving2/domain; missing threshold fails closed, confidentiality distinct from availability |
| Q | Actual process exits before/after durable partial commit, automatic restart with same volume | Recoverable; precommit no record, postcommit same stored response; fresh witness gate remains |
| R | Assume global compromise/loss of all secrets or every anchor | Outside claimed prevention/recovery model; K concretely models the shared-admin subset |
| S | Actual encrypted-vault creator CLI without SaaS | Recoverable complete create/provision/arm/checkin/status/disarm |
| T | Separate encrypted-vault recipient CLI, no owner seed; independently obtains fresh evidence and verifies package | Recoverable legitimate decryption; forged certificate rejected |
| U | Malicious dealer chooses distinct public keys with known relation B-scalar=2*A-scalar | **Successful** custody-only decrypt under compromised setup. Shows why distinct keys do not prove independent unknown capabilities |
| V | Public worker finalises earlier accepted presence slot; later window still open and policy unsatisfied; owner tries disarm | **Successful** inherited cancellation denial. Any own FINAL blocks wire4 disarm; no secret bypass introduced |

A/B finite attack attempts do not prove exhaustive computational security. Their supporting argument is the established threshold-DH/AEAD assumption plus the independently hidden uniform XOR component. The new integrated composition remains unreviewed. C, I, K and U explain when the assumptions fail; V explains a lifecycle availability weakness rather than a broken cipher. A detected response/rollback is never called a prevented plaintext leak.

## Reproduction

```sh
./scripts/experiment07.sh
python3 scripts/regression07.py
./scripts/performance07.sh
```

Docker Desktop/Compose is required; host Python only orchestrates containers. Bootstrap secrets and TLS roots are generated locally in ignored `.env05` / `.tls07` files. Default internal subnets are 10.207.7.0/24 (new profile) and 10.207.8.0/24 (fresh 0.6 performance comparison); inspect local routing on another host. `OTHERWISE_07_SUBNET` overrides the new profile. Unique project names and cleanup traps remove only that run's containers/networks/volumes. Existing demos, old code, raw historical results and old source fingerprints remain intact. No ports, external disclosure, email, SMS or PorterNet integration is added.

The full lab starts ten protocol services and a temporary client. It runs the attack methods and both independent conformance checks, then stops an actual witness process for the old-vault recovery/new checkin/disarm/release scenario and repairs it after restart. In this controlled-clock experiment, explicit private test-clock advancement is instrumentation; timeout does not create evidence of absence. Original real-clock/TLS experiments remain available in prior generations.

`Missing.cli` supports local `create`, `arm`, `checkin --challenge 1`, `status`, `disarm`, `evaluate` and `disclose`, with `--vault` and `--trust` pointing to independently retained local files. Passphrases are local prompts or the CLI environment. The synthetic recipient config is encrypted separately; `python -m Missing.recipient --vault RECIPIENT --bundle PROOF` independently validates a supplied proof package using its locally pinned expected sidecar/ciphertext and direct witness reads. Do not obtain the expected commitment from the untrusted combiner being checked.

## Historical regression and migration

The 0.1–0.6 methods and successful counterexamples are rerun under `results07/regression` and `results07/regression06`, not overwritten in their original directories. They include static-share early reconstruction, 0.6 premature point-decryption, hostile client and operator attacks, unsafe three-witness quorum intersection, stale state, malformed witness handling, clock/grace, actual restarts/rollback, encrypted recovery and real SaaS/database disappearance. The old 0.5 install/source check continues to verify its original inventory; the new Node verifier is isolated in `Missing/`, not added to that legacy directory.

Migration is explicit: wire4 evidence stays wire4; the v7 sidecar, endpoint names, finality-head definition, two-domain requirements, recipient salt format and journal are new. An old armed Capsule is not rewritten, nor made safe against already copied old secrets. New independent generation and retirement are required; new profile tests do not erase old successful attacks.
