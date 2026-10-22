# Custody research and prior art

Research checked on 14 October 2026. Otherwise makes no novelty claim. Its experimental contribution is a concrete, replayable combination of independently scoped obligations, explicit evidence authority, deterministic release policy and hostile scheduling tests. Threshold access structures and inactivity-triggered information handling have long precedents.

## What exists already

Google's Inactive Account Manager uses account activity signals and user-configured plans to notify contacts/share selected data. It illustrates the usefulness of inactivity policies and the need to distinguish lack of activity from objective death. Its documented behaviour is not an open acceptance/replay protocol or a claim about independent cryptographic custody. [Google documentation](https://support.google.com/accounts/answer/3036546).

Shamir's 1979 secret-sharing construction allows reconstruction from a threshold of shares while fewer shares do not reveal the secret under its model. This supplies a custody primitive, not a judgement about whether an obligation was satisfied. [Original paper hosted by the University of Pittsburgh](https://people.cs.pitt.edu/~litman/courses/cs2001/lectures/lecture-02-p612-shamir.pdf).

Vault provides Shamir unsealing and alternative auto-unseal models. Its documentation makes clear that recovery keys and unseal mechanisms have different roles. An operational unseal quorum is not automatically a per-Capsule threshold release decision. [Vault seal/unseal](https://docs.hashicorp.com/vault/docs/concepts/seal).

NIST describes threshold cryptographic operations that distribute key use among parties without reconstructing the key as part of the computation. This is a stronger basis for studying non-unilateral custody than putting a server-held key behind a signed policy. [NIST threshold cryptography project](https://csrc.nist.gov/Projects/threshold-cryptography).

Rivest, Shamir and Wagner explored timed-release cryptography and time-lock puzzles. Delay primitives address time-dependent decryption, rather than conditional, revocable, evidenced obligations. Our inference: such mechanisms alone do not implement Otherwise's disarm and contractual evidence semantics. [Original MIT report](https://publications.csail.mit.edu/lcs/pubs/pdf/MIT-LCS-TR-684.pdf).

The reference wire profile deliberately limits JSON instead of claiming arbitrary JSON interoperability. Full JCS support would require the RFC's number and string canonicalisation rules. [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785).

## Custody choices

The following are design assessments, not implemented or empirically demonstrated here.

| Option | Can prevent one operator decrypting early? | Dependencies and costs |
| --- | --- | --- |
| Current server-held AES key | No | Anyone controlling key access and ciphertext can decrypt |
| Client encrypts but gives the server the complete key | No | Changes upload/storage exposure, not release custody |
| Shamir shares held by genuinely independent custodians | Yes, below reconstruction threshold, if no complete retained key | Custodian collusion, authentic shares, backup discipline, availability; reconstruction endpoint sees the complete key |
| Threshold decryption without key reconstruction | Potentially, below its corruption threshold | Audited scheme, independent operators, protocol security and authenticated evidence snapshots; not implemented |
| HSM/KMS wrapping with one administrator able to invoke unwrap | Usually distributes operational control only | Administrator may invoke decrypt or reconfigure access; examine exact hardware and control model |
| Hardware with immutable attested policy and enforced quorum | Potentially, against defined operator powers | Vendor/firmware trust, rollback protection, provisioning and independent policy verification |
| Creator-only recovery secret mandatory for decrypt | Yes against server alone | Prevents autonomous release if creator disappears; conflicts with pure silence release |
| Optional creator recovery secret alongside threshold release | Depends on every alternate path | Recovery cannot become a hidden unilateral bypass |
| Distributed authorisation signatures over one committed decision | Limits unilateral permission if quorum independent | Does not prevent decrypt if another party still holds the full key |
| Witnessed custody-transition receipts / transparency log | Detects some misconduct | Evidence and accountability do not by themselves block decryption |

## A useful next experiment

Give independent custodians authentic Capsule commitments and complete evidence snapshots. Require each to independently derive the same authorised decision before producing a partial decryption operation. Bind each operation to Capsule ID, commitment, payload digest, decision hash, evidence-head and evaluation time. Separate evidence authorities from key custodians: counting contract leaves is not automatically counting custody shares.

Test one malicious custodian, stale snapshots, revocation ordering, rollback, unavailable peers, changed commitments and policy amendments. Establish what an honest minority can reject and what a colluding threshold can still do. Use an established, reviewed threshold construction and external cryptographic review; do not design new cryptography to match the policy grammar.

Our research question has a bounded answer in 0.1: a final software decision can be composed without any one of three independent attesters alone satisfying 2-of-3. The acceptance operator still controls custody. Removing its unilateral decryption power is a separate next-generation experiment, not an implication of the current result.

---

# Generation 0.2 implementation assessment — 15 October 2026

We implemented the share-and-reconstruct feasibility option using PyCryptodome's Shamir API and a 16-byte AES-GCM key. Its documented secret size is 16 bytes; using AES-128 avoids inventing a larger-secret sharing construction. Shares have no intrinsic conditional-policy enforcement. [Maintainer documentation](https://pycryptodome.readthedocs.io/en/latest/src/protocol/ss.html).

The new observation adapter uses Python's wall and monotonic clocks, with explicit bounds and restart handling. A monotonic counter is an elapsed-time tool, not authenticated UTC or portable persisted time. [Python clock documentation](https://docs.python.org/3/library/time.html).

The real findings narrow the research claim. Application-held decryption capability can be removed from the normal workflow using trusted creator provisioning and separately controlled shares. Independently retained histories constrain a dishonest app. However, two share holders can reconstruct without policy, and a corrupt observation authority can conceal previously unwitnessed evidence from otherwise honest custodians. Static response signatures bind honest participation to context; they do not prevent holders combining raw shares outside the verifier.

See [recorded attacks and six answers](doc/generation02/RESULTS.md). The next investigation should distinguish preventing unilateral application decryption, retaining evidence against corrupt observation authorities, preventing key reconstruction during legitimate operations and resisting a malicious custody threshold. These are separate properties; success on the first does not establish the others.

## Generation 0.3 — retention is a separate threshold

The retained-witness experiment adds an evidence quorum distinct from cryptographic custody. The tested profile uses three witnesses, two receipt signers and three absence finalisers under a one-fault bound. Its safety argument uses honest quorum intersection plus irreversible local observation/finalisation fences. The original Byzantine quorum-system literature provides the general intersection foundation; this experiment does not claim consensus or novelty. [Malkhi and Reiter](https://malkhi.com/files/byzquorums-STOC1997.pdf).

The important negative finding is practical: protecting presence with three witnesses can require unanimity for release and therefore surrender release availability. Increasing witness retention does not remove a malicious custody quorum's ability to reconstruct shares. See [0.3 research](doc/generation03/RESEARCH.md) and the [four-witness candidate for 0.4](doc/generation03/GENERATION_0_4.md), which remains proposed rather than implemented.


## Generation 0.4 — explicit provider compatibility

The injectable custody gate now advertises explicit operation, owner-disarm, certificate-validation, simulation and cryptographic-enforcement capabilities. Python/Node gates can be substituted; both retain the weak static-share material model. Conformance rejects a request for cryptographically enforced policy rather than silently selecting the lab provider. [Architecture and replacement requirements](doc/generation04/ARCHITECTURE.md) describe the future provider boundary; [the transport comparison](doc/generation04/UNREACHABLE_AUTHORITY.md) does not implement PorterNet.


## Generation 0.5 — custody remains a separate trust boundary

The early static-quorum reconstruction attack remains successful. [Concrete alternatives](doc/generation05/CUSTODY.md) compare administrative separation, witness-gated threshold/MPC release, hardware enforcement, future-beacon timelocks and stronger research assumptions. None is falsely advertised as implemented cryptographic enforcement.
