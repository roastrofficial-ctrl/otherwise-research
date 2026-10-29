# The Last Word — research decision, 29 October 2026

Historical U and V were reproduced **before implementation**, using the unchanged 0.7 fixtures (`results08/before07`). They remain successful historical counterexamples. No old lifecycle or source fingerprint is rewritten.

## Competing meanings

| Model | Safety / expectation | Coordination, failure and recovery | Decision |
|---|---|---|---|
| A: authorisation wins | Once the authoritative complete-predicate decision is ordered, disclosure is entitled; no claim of cancellation afterward. Policy evidence alone is not that decision | One terminal DISARM or RELEASE consensus entry. Durable votes and safe view change required. Cryptographic disclosure may happen later | **Selected**, with authorisation and commitment coincident by explicit protocol rule |
| B: commitment wins after authorisation | Additional period for creator cancellation; recipient cannot yet rely on an authorisation | Requires a separately ordered authorisation and commitment, expiry/reservation and recovery rules; voting/locks still create pending uncertain races | Deferred; do not silently label a policy proof as authoritative permission |
| C: first disclosure wins | Appears most creator-friendly, but secret operations may already be irreversible, hidden or partially delivered | No atomic global observation of “first plaintext learned”; retries, partial delivery, malicious holders and rollback complicate proof. Revocation cannot erase knowledge | Rejected for this generation |

Evidence finality, window closure, policy satisfaction, authoritative permission, irreversible protocol commitment and actual disclosure are separate concepts. In selected A, only the fourth and fifth intentionally coincide. Earlier PRESENT window finals cannot block a new terminal disarm decision.

## Ordering construction and scope

A **single-instance signed PBFT-style research harness** uses four fixed witness identities, f<=1, prepare quorum3, commit quorum3, and three-source view-change certificates carrying highest prepared proofs. The same committee is sufficient only with these protocol rules, durable single-vote/view promises, signature/hash assumptions and immutable membership. Three signatures on an arbitrary fact are not consensus. This is not a production PBFT library, a proven implementation or a full multi-entry blockchain.

Every participant persists its vote/proposal, highest prepared certificate, view promises and terminal decision before reply. A new-view proposal must carry three view-change messages and preserve their highest prepared value. The designated leader rotates by view; any independent client/worker can relay messages and retrieve certificates. No permanent privileged coordinator, SaaS ordering database, wall-clock tie breaker or “fastest responder wins” decision rule exists.

Concurrent valid requests are nondeterministically ordered by a consensus execution. Network scheduling can influence which valid proposal is selected; the **proof of order** is the durable certificate, not packet arrival time. A schedule-independent promise that every earlier-sent or still-undelivered disarm wins would require additional assumptions and conflicts with autonomous progress under unbounded delay. Prepared/in-flight locks can already constrain an attempt before the requester sees a terminal certificate. Missing acknowledgement is uncertainty, never cancellation success.

Safety is intended under arbitrary delay and f<=1 with honest durable state and authenticated recovery. Liveness additionally needs eventual timely delivery, enough compatible honest replicas, a fair/stable relay/pacemaker and a functioning honest leader. Permanent2/2 partitions cannot decide. The bounded client driver and fixed local timeouts are a laboratory, not an implementation/proof of every partial-synchrony execution. Model checking explores bounded phases/views and cannot certify the whole system.

## Alternatives

A reviewed PBFT/HotStuff/Tendermint implementation with operational gossip/pacemaker and independently reviewed light clients is a realistic next integration; it adds substantial deployment/state-machine scope. A conventional Raft/Paxos service is simpler under crash faults but does not meet the stated Byzantine-signing threat model. A single sequencer is an explicit unilateral ordering trust root, rejected here. Separate committees or larger quorums without lock/view-change rules do not solve ordering. Membership reconfiguration requires old/new quorum continuity or pre-authorised succession, not merely changing a key list.

## Primary literature

[Castro–Liskov's correctness memorandum](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/01/tm590.pdf) specifies unoptimised Byzantine replication and proves its safety (not liveness). Our restricted implementation borrows prepare/commit/view-change structure; that proof does not automatically apply to our code. [Tendermint's consensus specification](https://docs.tendermint.com/master/spec/consensus/consensus.html) documents rounds, locks and gossip beyond arithmetic. [Fischer–Lynch–Paterson](https://groups.csail.mit.edu/tds/papers/Lynch/jacm85.pdf) establishes possible nontermination in a fully asynchronous deterministic crash model; it is not a claim that safety must be abandoned during partitions.

0.7's split-capability cryptography is preserved as an unreviewed reference composition. Finality constrains honest holders; it does not restrain a combined coalition already holding both indispensable secrets. Related/private-reused entropy, malicious dealer, substituted keys, wrong share commitments, cross-domain reuse and common backups remain separate provisioning concerns, tested rather than assumed fixed by consensus.
