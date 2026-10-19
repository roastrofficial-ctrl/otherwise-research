# Otherwise Protocol 0.1

## Meaning and authority

A Capsule is a unique identifier, encrypted payload reference and immutable policy commitment. An obligation is a versioned contract scoped to that Capsule and commitment. Independent contract results feed an expression. A positive result means the contract's defined predicate was satisfied by authoritative facts at a snapshot. It does not mean the world agrees with an attester.

Generation 0.1 trusts one durable acceptance authority and its controlled integer-seconds clock. Application receipt, notification timestamps, sender timestamps and signatures alone do not establish timely acceptance. The authority serialises submissions, clock changes, revocations, disarming and release decisions into one committed order. An acceptance transaction that rolls back is not a fact. A lost acknowledgement after commit is recovered by retry.

The decision consumes one validated snapshot: policy commitment, complete ordered history, its head, authoritative time and clock-health status. Authorisation records that exact pre-decision head, commitment, results, grace candidate and payload reference. A later evaluator can replay the prefix at the decision time; subsequent delivery does not rewrite it.

## Wire profile

Messages use JSON with ASCII string keys/values, booleans, null, arrays and integers with absolute value at most `2^53-1`. No floats. Canonical encoding uses lexicographically sorted object keys, compact separators and ASCII JSON escapes, UTF-8 bytes. This deliberately restricted profile is **not a claim of full RFC 8785 conformance**. Payload bytes can contain arbitrary text or files; only protocol strings are restricted.

SHA-256 of canonical policy bytes is the commitment. Ed25519 signatures cover the entire canonical message, not a subset. Wire identifiers are case-sensitive opaque strings. Public keys and signatures are hexadecimal encodings. JSON parsers receiving bytes must reject duplicate object keys before construction; this engine accepts Python objects and does not implement a network JSON parser.

The only policy format version and contract semantic version supported here are `1`. Unknown fields and operators fail validation. An event envelope is:

```json
{"v":1,"capsule":"example","seq":1,"time":0,"kind":"CREATED","data":{},"prev":"previous-event-sha256"}
```

`seq` is capsule-local, strictly increasing. A trusted head/count anchor detects removed tails as well as gaps, reordered and changed entries. Head/count reside with the database; they are not an independent cryptographic witness. Hashes detect accidental corruption and simple unauthorised edits, not an operator who rewrites all anchors.

## Policy and contract schema

A policy has exactly `version`, `owner` (Ed25519 public key), `contracts`, `expression`, `grace` (positive integer seconds), `max_step` (positive clock-jump bound) and `destination`. Destination must equal `{"kind":"simulated","verified":true,"consented":true}`; no real-world verification is implemented.

A contract has exactly `id`, `version`, `kind`, `authority` (public key), `start`, `end`, `challenges`. Its half-open active period is `[start,end)`. Every contract ID is unique in the Capsule. Every expression leaf occurs exactly once, and all contracts must be referenced. This prevents repeated leaves inflating a threshold.

Two contract kinds are specified:

| Kind | Evidence schema extension | Satisfaction |
| --- | --- | --- |
| `attestation` | `claim`: boolean | At least one currently valid accepted true claim and no currently valid accepted false claim |
| `absence` | `challenge`: challenge ID | At least one issued challenge has passed its deadline with no timely accepted presence |

An attestation has no challenges. An absence contract contains at least one immutable challenge `{"id":...,"open":...,"deadline":...}` with `start <= open <= deadline < end`. Challenge IDs are unique within a contract. Arming durably issues all predefined challenges, including future challenges; this generation has a finite explicit schedule, not calendar recurrence.

Inactive, expired or revoked contracts cannot satisfy the expression. Missing or contradictory evidence does not supply a positive result. A contradictory attestation leaf therefore does not veto an unrelated 2-of-3 result. Other contracts may still establish enough positive leaves.

For absence, accepted presence is a historical witness for its challenge even after the proof's validity window expires. The validity window constrained acceptance, not retention of the fact that presence was timely witnessed. Revocation disables the entire contract, including absence inference; it does not make old witnessed challenges unwitnessed.

## Composition

A leaf is a contract ID. Nodes have exactly `op`, `args`, and additionally `k` for `THRESHOLD`:

```json
{"op":"THRESHOLD","k":2,"args":["A","B","C"]}
```

`AND` requires every child; `OR` requires at least one; `THRESHOLD` requires at least `k` true children, with `1 <= k <= len(args)`. Children may themselves be expressions. Empty nodes, unknown leaves, repeated leaves and depth greater than 32 are rejected. `n` is derived from the number of immediate children.

Thresholds count obligations, not unique people. The same public key may participate in several contracts, but each requires separately scoped evidence. A policy claiming independent entities must select distinct keys and establish organisational independence outside the protocol; three keys alone do not prove independence.

## Evidence

Evidence has these base fields, plus the kind's extension:

```json
{"v":1,"id":"submission-1","capsule":"example","commitment":"policy-sha256","contract":"A","contract_version":1,"authority":"public-key-hex","valid_from":0,"valid_until":100,"claim":true}
```

The authority rejects unarmed/terminal Capsule submissions, unknown contracts, incorrect fields, wrong Capsule/commitment/version/authority, invalid signatures, revoked authorities and invalid validity windows. Require `contract.start <= valid_from <= authority.now < valid_until <= contract.end`. Absence additionally requires an issued matching challenge and `open <= authority.now <= deadline`.

Submission is an attempt (`SUBMITTED`); acceptance is an authenticated, scoped, durable fact (`ACCEPTED`); satisfaction is a snapshot interpretation; authorisation is a committed Capsule decision. None is interchangeable.

Only accepted submission IDs reserve the idempotency key in this minimal profile. An identical accepted message/signature retry returns the original receipt even after expiry or terminal transition. Same ID with different accepted bytes raises a collision error. Rejected submissions can be retried after correction and do not satisfy anything. New submission IDs for the same claim do not increase the number of satisfied contracts. An accepted new proof conservatively restarts grace; duplicates recovering the same receipt do not.

Revocations are signed by the owner and scoped to Capsule and commitment. They disable all contracts using that authority in that Capsule from the revocation's committed position onwards, including already accepted evidence. There is no unrevocation or retroactive reversal of an already committed release. Contradictory active proofs make an attestation unsatisfied; after a false proof expires, a still-valid true proof may satisfy it. A stale proof cannot be newly accepted.

## Lifecycle and grace

`CREATED -> ARMED -> AUTHORISED -> RELEASED`, with `DISARMED` terminal for authorisation from either created or armed. Arm/disarm commands include `v`, `capsule`, `commitment`, `action` and an owner signature. Retries are idempotent. Disarming after authorisation is rejected; disclosure permission is already committed. Disarming first makes all subsequent authorisation attempts return no decision. Delivery and human receipt remain different facts.

When an armed, healthy Capsule's expression first becomes true, the engine records a `CANDIDATE`, including an escalation/grace audit fact. This starts a positive, configurable grace period; observation starts grace, not the historical challenge deadline. Notification successes/failures are transport facts only. Generation 0.1 does not send real reminders or implement custom escalation channels.

Authorisation requires continued expression satisfaction throughout grace and at the release snapshot. Evidence, revocation and recovery reset the candidate. At evaluation, all intervening contract/proof boundaries and challenge deadline transitions are checked, so a worker pause cannot bridge a false interval. Time is discrete seconds; absence begins at `deadline+1`. Grace permits authorisation at `candidate_time+grace`, including equality. The laboratory uses five seconds; deployments must choose a substantial grace appropriate to human response and availability. A candidate is not permission to disclose.

One atomic authoritative decision exists per Capsule. Competing workers either create it or recover the same committed event. Authorisation stores references, never plaintext. `RELEASED` means the simulated adapter durably inserted the content, not that a human read it. A crash between recipient insertion and audit acknowledgement can be retried with the same decision key. Non-idempotent real providers would require a separate delivery design and cannot inherit exactly-once guarantees.

## Deadline race and clocks

At authoritative time `deadline`, presence is eligible and absence is false. Release cannot pass a valid check-in in the same serialised clock instant. A front-end receipt before the deadline that reaches the authority after it is too late. In the example, Server A's receipt at 11:59:59 protects the Capsule only if it became an authoritative acceptance before the deadline boundary. Server B's independent wall-clock impression at 12:00:01 has no authority.

In this laboratory, the clock is a durable controlled variable; clock advancement shares the transaction lock. Time eligibility is sampled after acquiring the authority lock and is unchanged until that transaction commits. A successful commit is the durable acceptance threshold. If real wall time passes during this transaction, this engine does not observe it. A future real-time adapter must define sampling, lock duration, drift budgets and crash uncertainty; copying this laboratory's clock into a production service would not establish real-time guarantees.

Clock rollback is rejected. Excessive positive jumps or explicitly declared downtime latch the authority unhealthy. No new authorisation is allowed until an owner-signed recovery command resets that Capsule's grace. Each affected Capsule retains a local uncertainty latch until its own owner signs recovery; another owner cannot clear it. Its committed history is checked before recovery. Hidden outages, gradual drift, clock freezes and dishonest test-clock advances are not detected. A stopped worker cannot retroactively skip grace because a fresh candidate starts when observed; a candidate established before undetected downtime may mature normally. The outage adapter must report uncertainty; production outage detection remains future work.

## Amendments and future custody

No policy update API exists, even before arming. To amend: create a new Capsule ID and commitment, obtain fresh evidence scoped to it, disarm the predecessor before arming the successor, and retain both histories. This is a two-step workflow, not an atomic cross-Capsule migration. If the predecessor has already been authorised, amendment cannot retract it. Contract revisions are likewise new commitments; unknown revisions are rejected. Independent custodians could later consume the same committed decisions and evidence snapshots, but authenticated commitments alone do not force an operator to obey them.

---

# Generation 0.2: bounded custody profile

This section specifies an **additional, opt-in feasibility profile**, not a retrospective change to 0.1 custody. Contract/policy semantic version `1` remains unchanged. Event envelope version remains `1`. New custody manifests, receipts and head-bound owner commands use message version `2`. A Capsule created with a server-held development key remains a 0.1 Capsule; there is no silent upgrade or downgrade.

## Three authorities

| Authority | Responsibility | Reference component |
| --- | --- | --- |
| Acceptance | Retain the definitive accepted history, its order and observation time | Independent witness service retaining full immutable prefixes |
| Decision | Verify signatures, lifecycle, contract truth and continuous grace | Python replay verifier plus independently written JavaScript state machine; repeated by custodians |
| Custody | Hold the capability to recover plaintext | Three separately stored Shamir shares; two required for recovery |

The application database is a local preparation/projection store in this profile. A local `ACCEPTED` or `AUTHORISED` event is **not yet an externally authoritative 0.2 fact**. The exact threshold is the witness's durable SQLite commit of the corresponding validated prefix. The receipt may be lost after this threshold; retry retrieves it. Failed publication does not grant permission. The creator must retain/verify the witness receipt, not rely on an application success boolean.

## Owner commitment and provisioning

A trusted creator client generates a random 128-bit AES key, encrypts with AES-GCM and a random 96-bit nonce, then invokes PyCryptodome's established 2-of-3 Shamir implementation for its supported 16-byte secret size. No new sharing primitive is defined. This is share-and-reconstruct custody, **not threshold decryption without key reconstruction**.

The owner signs a manifest with exactly these fields:

```text
v=2, capsule, epoch=1, policy, commitment, payload,
algorithm="AES-128-GCM",
custody={scheme:"shamir-pycryptodome-128",k:2,n:3,keys:{"1":pub1,"2":pub2,"3":pub3}},
witness=public_key,
clock={profile:"witness-observed-v2",outage:"withhold-and-restart-grace"}
```

`payload` is SHA-256 of `nonce || encrypted-bytes-with-GCM-tag`. GCM associated data is canonical `{v:2,capsule,commitment,epoch}`. Policy commitment is still SHA-256 of the canonical version-1 policy. Manifest commitment is SHA-256 of the complete canonical manifest. Custodian keys must be distinct. Policy authorities and custodian keys need not be the same people or threshold. Solo uses one absence contract and automatic 2-of-3 custody; Council uses three contract authorities and an independent 2-of-3 custody group.

The creator pins authentic service identities through trusted provisioning. Each custodian immutably enrolls its own share/manifest under a separate bootstrap capability and returns a signed `ENROLLED` receipt binding manifest hash, index and its public key. The witness requires all three enrollment receipts before history can be committed. A partially provisioned Capsule cannot arm. Replaying an identical enrollment resumes provisioning; replacing its manifest or share is rejected. Once provisioned, any two honest available custodians suffice for authorised recovery.

`Engine.import_encrypted` accepts only ciphertext and the committed policy, writes/fsyncs the ciphertext and commits its reference. It never receives the plaintext or key. A crash before the Capsule database commit may leave an unreferenced encrypted object; no armed Capsule exists. After a local commit but before witness publication, the projection is prepared only. Orphan removal, secure erasure and fully automatic recovery from creator loss during provisioning are not implemented. Destroy/reprovision abandoned synthetic fixtures rather than silently assuming complete custody.

## Head-bound owner commands

0.2 owner commands use:

```text
{v:2,capsule,commitment,action,head:current_pre_command_history_head}
```

The signature covers every field. The engine rejects a command for an obsolete head, and both verifiers require the command's head to equal its event's `prev`. In particular, the witness rejects newly submitted legacy version-1 `RECOVERED` commands. A reusable action-only recovery signature cannot acknowledge a subsequent outage. Version-1 histories remain replayable for legacy conformance; they are not sufficient to recover a 0.2 observation authority.

## Witness commitments and freshness

The witness checks the owner manifest, policy, hash chain, lifecycle signatures, evidence schema/scope/signatures/windows, committed challenges, candidate support, continuous grace and every authorisation. It retains the **full prefix**, not just a replaceable local head. Every subsequent publication must extend that exact prefix. Deleting even correctly signed earlier presence or restoring an entire old application database is observable. A locally self-consistent alternative history is insufficient.

A checkpoint receipt is the witness signature over:

```text
{v:2,manifest,capsule,commitment,head,count,now,healthy}
```

A custodian never accepts caller-provided history or an operator's signed “approved” claim. It fetches the current bundle directly from its configured witness. Each fetch includes a fresh random nonce; the witness signs `{v:2,nonce,manifest,head,count,clock,blocked,candidate_upper}`. The custodian verifies both signatures, pinned identities and scope, then independently replays the snapshot using Python **and JavaScript**. It persists a local prefix high-water mark even if the valid history does not yet authorise release. A later contradictory/shorter prefix is refused. Freshness depends on authenticated/pinned responses from the configured witness; this is not an independently established global latest-history oracle.

If the witness is unavailable, inconsistent, uncertain, or offers a conflicting prefix, no new share is issued. Witness history is independently stored relative to the application. Restoring **all** independent retained state, compromising its signing authority, or concealing evidence before any external receipt remains outside rollback detection.

## Observation clock and outages

The real adapter samples `time.time_ns()` and `time.monotonic_ns()`. Default configuration uses a 1,000 ms radius, a 1,000 ms wall/monotonic divergence budget and a 30,000 ms observation-gap ceiling. The output is conservative integer seconds `[lower,upper]`. It detects backwards jumps, cumulative wall/monotonic disagreement, negative monotonic movement, excessive sampling gaps and lost process continuity. Persisted state on restart is unhealthy until explicit recovery. Monotonic values are not assumed portable across sessions.

The application must also provide witnessed heartbeats. Its allowed silence is at most the smaller of 30 seconds and half the shortest committed challenge window (inclusive integer seconds). This derives a stricter observation requirement from the committed challenges; it does not move challenge deadlines. A missing heartbeat spanning entire short windows is therefore uncertainty, not reliable absence. The deterministic Docker service profile uses a separately capability-controlled test clock for accelerated integration; real adapter sources are fault-injected in automated tests, with actual host-clock sampling separately exercised. No host clock is changed by the suite.

New facts must fall inside the witness's current observation interval; retrospective candidates and fabricated future clock advances are rejected. Presence/proof acceptance must be valid across the entire interval (`valid_from <= lower`, `upper < valid_until`; for presence, `open <= lower` and `upper <= deadline`). A boundary-straddling proof latches uncertainty rather than being converted into confident absence. The candidate must be independently observable by `lower`, and `lower` must have passed the first witnessed candidate observation's **upper** bound plus the entire grace before authorisation. The signed fresh status includes that retained `candidate_upper`; custodians check it against the decision time. Local time alone cannot mature a candidate.

Deadline eligibility is established by the witness's bounded sample while processing a serialised publication. Durable commit confirms that sampled acceptance; it does not prove that physical disk commit preceded a UTC instant. A commit delayed by storage can complete after its sampling deadline; its ordering still precedes subsequent witness decisions. No hard bound on sampling-to-fsync latency or globally correct UTC is claimed. This unresolved physical-time boundary is distinct from application request arrival and from durable authoritative order.

Clock uncertainty latches every live registered Capsule. An owner's fresh head-bound `RECOVERED` command can clear its own latch and restart grace; it cannot clear another Capsule's latch. Recovery acknowledges an observation gap, not evidence of incapacity. Withholding/restarting grace is part of the owner-signed manifest's committed outage semantics and can extend effective release time indefinitely without amending the policy. It does not extend proof validity or erase missed obligations. Automatic terminal-state recovery after witness restart and a complete real-time acceptance service remain unfinished.

A functioning heartbeat cannot prove the creator can reach the service. A partition affecting only that creator can still result in absence-based release. Common-mode corruption of wall and monotonic sources, a dishonest independent witness, and externally wrong UTC are not solved by comparing clocks.

## Custody participation and irreversible thresholds

A release request contains Capsule ID, manifest hash and the requested decision hash. A custodian verifies the current witnessed history, then signs a response containing:

```text
{v:2,capsule,epoch,manifest,commitment,payload,decision,history,index,share}
```

The recipient checks every signature/domain, distinct indices and identical snapshot binding before combining at least two shares and authenticating GCM. A different Capsule, policy/epoch, payload, unsigned altered response or mixed release snapshot is rejected by the honest recipient implementation.

There are two irreversible thresholds. Witness-committed authorisation is the protocol permission boundary: a subsequent disarm cannot recall it. A merely local prepared authorisation can be discarded by restoring the witnessed projection, permitting disarm before an external decision. Reconstruction capability escapes once a party possesses two shares; the holder can retain and reuse it forever. Already issued shares are not revocable by later availability, disarm or clock changes.

Signed context binds **honest participation and receipt validation**, not the underlying mathematical share to a snapshot. Shares are static. Two malicious custodians can ignore the checks and reconstruct early; issued shares can be combined outside the honest recipient code. No cryptographic proof forces the share holders to obey policy. This is the central feasibility boundary, not a hidden security guarantee.

A synthetic recipient acknowledgment may create `RELEASED` after valid `AUTHORISED`. It establishes neither a real external disclosure nor human receipt. The app never needs the complete key before permission; this experiment reconstructs at a trusted synthetic recipient after permission.

---

# Generation 0.3: retained-witness profile

This is an opt-in version-3 proof/custody profile. Generations 0.1 and 0.2 remain executable, with their original policy semantics and recorded attacks. Version-1 policy/contract definitions and AND/OR/THRESHOLD composition are reused. The new owner-signed manifest explicitly adds static witness membership, receipt thresholds and finite acceptance slots. It does not reinterpret old Capsule commitments or upgrade their guarantees.

## Submission, observation, acceptance

**Submission** is a request; it establishes no durable fact. **Observation** is one witness's valid, signed receipt committed in its own SQLite transaction. **Acceptance** is a quorum of at least two distinct witness receipts for the exact same scoped signed proof. An aggregate certificate may be assembled or recovered later, even after its window closes. It is the qualifying durable receipts that matter, not the time of the application's acknowledgment.

`CheckInClient(root, witness_urls).check_in(signed_manifest, signed_proof)` is the thin client-facing boundary. It independently validates receipt quorum, fsyncs the canonical aggregate and its containing directory before returning, and recovers the same cached certificate on retry. A future Laravel/mobile client can present accepted/pending together with this verifiable object rather than a bare success boolean. The lower-level `check_in` returns the verified quorum without the aggregate cache. Witnesses retain the underlying receipts independently of app storage.

If two honest witnesses committed and the application crashed before acknowledging, the evidence counted and retry retrieves the original receipts. If only one receipt exists, no acceptance certificate exists; nevertheless that honest observation can conservatively block release. If a Byzantine witness withholds a receipt after acknowledgment loss, recovery of the aggregate may be unavailable even though an honest retained observation still prevents a conflicting absence certificate. Acceptance safety is not a promise that a lost certificate can always be retrieved.

## Static membership and quorum assumptions

The implemented profile is fixed: `N=3`, presence/claim acceptance `P=2`, absence/closed-slot finalisation `A=3`, fault bound `f=1`. At least two witnesses must follow the protocol and retain durable state. A malicious signer, erased/rolled-back state that forgets an observed proof, stolen signing identity or a clock that violates its declared observation model counts against this fault bound. Temporary unavailability contributes no signature and never becomes a vote for absence.

The minimum intersection of quorums is `P + A - N`. Requiring `P + A > N + f` ensures at least one honest witness in any presence/finalisation intersection. Also require `P > f`. For the implemented parameters, the intersection is two, exceeding one potentially dishonest witness. An honest witness that retained presence cannot subsequently sign ABSENT for that slot; an honest witness that closed ABSENT cannot later accept a new observation.

This establishes a conditional safety argument for static, uncoordinated certificates and durable local fences. It is **not** a consensus protocol, a global event order or a general impossibility theorem about other coordinated systems.

| N | P | A | f | Conflicting certificates prevented under local fences? | Crash-only availability |
| --- | --- | --- | --- | --- | --- |
| 3 | 2 | 2 | 0 | Yes | One missing witness can be tolerated |
| 3 | 2 | 2 | 1 | No: malicious intersection signer can sign both | Majority availability does not repair safety |
| 3 | 2 | 3 | 1 | Yes, implemented | Presence can tolerate one missing; release cannot |
| 3 | 3 | 2 | 1 | Yes, alternative only | Presence requires everyone |
| 4 | 3 | 3 | 1 | Intersection candidate for future work | Not implemented |

For separate `u` unavailable and `f` Byzantine-withholding witnesses, guaranteed progress needs each required quorum no larger than `N-f-u`; safety alone does not provide this. The 0.3 profile deliberately sacrifices release liveness. One silent or refusing witness can withhold release indefinitely.

## Version-3 manifest and finite slots

A signed object has exactly `{message,signature}`. Canonical JSON is the existing restricted ASCII/integer profile; cryptographic encodings are lowercase hexadecimal. The manifest message has exactly:

```text
v:3, capsule, epoch:1, policy, commitment, payload,
witnesses:{"1":public1,"2":public2,"3":public3},
custody:{k:2,n:3,keys:{"1":key1,"2":key2,"3":key3}},
quorum:{presence:2,absence:3,faults:1},
slots:[{contract,challenge,open,deadline},...],
operation:{attempt:"release-1",kind:"reconstruct-aes-128-gcm"}
```

The owner signs the complete manifest. Its hash binds all new rules; policy commitment remains the original canonical policy hash. Ciphertext identity is SHA-256 of nonce/GCM ciphertext/tag. AES-GCM associated data is canonical `{v:3,capsule,commitment,epoch}`. Witness keys and custody keys are separate, statically pinned sets. Each must contain three distinct identities. Provisioning belongs to the trusted creator/infrastructure boundary and is not an additional human authorisation.

For absence contracts, every committed challenge becomes one slot in policy order. For attestation contracts, the manifest adds one `attestation` slot with an explicit finite cutoff and enough time before contract expiration for grace. Arming this profile means enrolling the owner's signed release commitment. No uncommitted additional challenge, dynamic membership, revocation/reopening, epoch rotation or silent amendment is supported. Change conditions by creating a new commitment and safely disarming the predecessor where still possible.

Each witness observes at most one distinct proof per slot, and finalises each slot once. An identical submission ID/proof retry returns the original signed receipt before checking today's deadline; changing bytes under an observed ID is rejected. Different claims for the same already observed slot are refused. Thus this profile commits to first observation per witness and a closed evidence window, not an indefinitely editable attestation history. Accepted claim certificates are authenticated statements, not objective truth or an immediately final contract result. Split contradictory claim observations cannot produce unanimous positive finalisation.

## Signed proofs and receipts

A signed proof message has exactly:

```text
{v:3,id,capsule,manifest,contract,contract_version,challenge,authority,
 valid_from,valid_until,value:boolean}
```

`manifest` is the manifest message digest. The contract's pinned authority signs every field. Absence contracts permit only `value=true` (presence); attestation contracts permit true or false. The witness validates Capsule, manifest, contract revision, challenge, authority, schema/signature and proof validity against its own observation interval.

Each receipt message has exactly:

```text
{v:3,kind:"OBSERVATION"|"FINAL",capsule,manifest,witness,
 contract,challenge,operation,seq,prev,lower,upper,proof,value,not_before}
```

`operation` is the digest of `{v:3,capsule,epoch,manifest,commitment,payload,...manifest.operation}`. `seq` increases within that witness's Capsule lineage; `prev` hashes its previous complete signed receipt, or zeroes at genesis. There is no shared sequence across witnesses. `not_before = deadline + 1 + grace` in discrete seconds. `proof` contains the signed authority proof or null.

An OBSERVATION is valid only if `open <= lower <= upper <= deadline` and `valid_from <= lower <= upper < valid_until`. The inclusive deadline is eligible. Eligibility is determined by the witness's bounded sample; durable commit establishes retention. As in 0.2, physical sampling-to-commit latency is not bounded by this experiment. Serialising observation/finalisation on each honest witness prevents a stalled accepted write from being overtaken locally.

Observation values are PRESENT for absence, or TRUE/FALSE for attestations. The signed receipt is returned only after its state transaction commits; losing that response does not undo it.

## Closed acceptance windows and compact release

A FINAL requires `lower >= deadline + 1 + grace` and a healthy observation clock. An honest witness finalises its retained proof unchanged, or signs ABSENT (absence contract) / EMPTY (attestation) if none exists. It will never add a new observation after finalisation. Real-clock restart uncertainty withholds new finalisation; controlled service clocks are used for accelerated laboratory scenarios. No global absence, human death or universal network reachability is claimed.

A presence/claim acknowledgment is `{manifest:signed_manifest, receipts:[signed_observation,...]}` with at least two distinct witness identities, identical scoped proof and valid receipt signatures. Client persistence makes the aggregate durable; the underlying quorum can also reconstruct it after lost acknowledgment if its issuers remain available.

A compact release object has exactly:

```text
{v:3,manifest:signed_manifest,
 finals:[[signed_final_for_each_witness],...one_group_per_manifest_slot],
 operation,authorisation}
```

`authorisation` is SHA-256 of the canonical object without that field. All manifest slots must be present in manifest order; the operator cannot omit a contract or choose a convenient two-witness subset. Each group requires all three distinct witnesses. This is a deterministic proof-derived authorisation, not a separate operator's signed interpretation.

An absence slot is true only if every finalisation says ABSENT. Retained PRESENT makes that slot false forever. An absence contract is satisfied if any of its challenges is truly absent. An attestation slot is true only if all finalisations say TRUE for the same proof, and it remains valid at the certificate's evaluation time (maximum finalisation upper bound). Contract validity and policy composition are then checked at that time. Council still permits two positive contracts to outweigh an unsatisfied third, but the third's finalisation group cannot be omitted.

Custodians independently verify the complete compact object in Python and JavaScript. A retained presence acknowledgment for the same absence slot vetoes a contradictory release even if too many witnesses have been compromised and signatures alone would otherwise verify. The custody response binds Capsule, manifest, ciphertext, operation, certificate authorisation and custody share index. The recipient verifies these bindings, distinct indices and AES-GCM before recovering synthetic content.

The certificate is compact relative to the entire event history: it has one final record per witness per committed slot, plus relevant signed proofs. It is not constant-size with respect to the number of challenges. Signed context does not turn static Shamir shares into cryptographically enforced policy. The original malicious-custody-quorum bypass remains possible.

## Retained commitments, rollback and disarm

Witnesses can retain one another's signed receipts. Duplicate retention is idempotent. Two different signed records at the same lineage position, conflicting observation/finalisation proofs or a finalised slot followed by a new observation expose equivocation. The observer retains the evidence and identifies the faulty source; another node's misconduct does not quarantine unrelated honest local state.

If a restored witness is shown its own independently retained receipt missing from its local prefix, it quarantines itself and issues no new observation/finalisation. The experiment restores the entire SQLite database while peers keep their own commitments. Detection requires a surviving retained receipt to be delivered; it is not automatic global rollback detection. Omitting that audit makes the forgetful witness a fault, still tolerated for absence safety while the total fault bound holds. Losing every relevant retained state remains outside the guarantee. Automatic reconstruction/re-enrollment is not implemented.

An owner-signed DISARM binds Capsule, manifest and operation. A witness records a durable terminal fence before any local finalisation; it refuses disarm after signing any FINAL. Disarming all honest witnesses before finalisation prevents a complete release certificate. There is no new total-order disarm service: partial finalisation can conservatively make disarm unavailable before all release records exist. Once enough finalisations establish permission, it cannot be recalled; once two custody shares escape, capability cannot be recalled. Generation 0.2's ordered disarm experiments remain preserved separately.


## Generation 0.4 — separately versioned available-witness profile

The new wire-version-4 profile is specified in [doc/generation04/PROTOCOL.md](doc/generation04/PROTOCOL.md). Its static four-member committee, immutable manifest, three-receipt durable acknowledgement, same-identity repair, quorum disarm and fixed-operation custody certificates do not change the older profiles above. The finite-batch snapshot and timing/repair availability limitations are explicit.
