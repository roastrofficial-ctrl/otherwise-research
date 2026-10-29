# Otherwise

### A promise that outlives its author.

**Otherwise is an experimental protocol for conditional encrypted disclosure.** A creator commits to a standing instruction: keep a Capsule confidential while defined participation conditions are satisfied; permit disclosure to a designated recipient when the agreed evidence and release rules say otherwise.

It began as a simple dead-man's switch. It became a research programme about **consent, distributed authority, cryptographic custody, irreversible decisions, and what happens when the people or institutions keeping a promise disappear**.

> **Otherwise does not infer consent from absence. It preserves a standing instruction across absence.**

Absence is evidence about participation, **not proof of death, incapacity, intent, or existence**. The creator chooses the conditions in advance. The protocol evaluates observable evidence against those conditions; it does not pretend to know *why* someone stopped checking in.

**Status: experimental research, not a production security service.** All Capsules and disclosures in this repository are synthetic. The cryptographic compositions, consensus implementation, and infrastructure have not received an independent security audit. Do not use this code to protect real secrets or rely on it for real-world release decisions.

---

## The problem

Imagine encrypting information today with a standing instruction:

> Disclose this to my chosen recipient if I fail to establish participation according to these rules, unless I validly revoke the instruction before the agreed irreversible boundary.

A single custodian can implement that workflow. But what if the custodian lies, disappears, loses its keys, or decides to disclose early? What if witnesses disagree about whether a check-in happened? What if the creator attempts to cancel at the same moment the system prepares to release?

Otherwise investigates those questions by building working reference systems, attacking them, preserving counterexamples, and changing the architecture when assumptions fail.

**The research method:** Start with a simple human question. Build the smallest thing that answers it. Then keep asking what happens when its assumptions fail.

## What we've built

The repository preserves **eight generations of experiments (0.1–0.8)** rather than replacing old designs with a single polished narrative.

| Generation | Research question | What the experiments established |
|---|---|---|
| **0.1 — The Absent Witness** | Can one Capsule follow a standing conditional instruction? | A reference lifecycle with encryption, check-ins, evidence, disarm, and simulated release. |
| **0.2 — The Bounded Authority** | What if custodians or the operator are dishonest? | Separation of policy and custody, plus retained attacks against naive threshold custody. |
| **0.3 — The Retained Witness** | Who remembers a check-in when the application denies it? | Independently signed and retained witness evidence; an explicit safety-versus-availability trade-off. |
| **0.4 — The Available Witness** | Can the system tolerate a missing witness and a missing SaaS? | A four-witness, three-signature profile; independent operation and recovery demonstrations. |
| **0.5 — The Untrusted Operator** | What if the product operator controls the interface? | Creator-side signing and encryption; malicious-SaaS experiments and portable recovery. |
| **0.6 — The Honest Custodian** | Can honest custodians disclose without reconstructing a master private key? | Verifiable threshold partial operations; malicious threshold decryption still succeeds. |
| **0.7 — The Missing Piece** | Can compromising *one entire domain* cease to be enough? | Two indispensable cryptographic components, held by custody and authority domains; combined collusion still succeeds. |
| **0.8 — The Last Word** | Who wins when disarm and release race? | A versioned terminal-decision research protocol that corrects premature cancellation denial and produces independently verifiable release certificates. |

The historical implementations, test suites, attacks, and evidence remain available for inspection.

## The current experiment: 0.8 — The Last Word

Generation 0.7 exposed **Attack V**: finalising an earlier check-in window could prevent the creator from disarming even though the *complete* release condition was not satisfied.

Generation 0.8 separates six ideas that are easy to conflate:

1. Evidence has been finalised.
2. A particular check-in window has closed.
3. The complete release predicate is satisfied.
4. Release has been authorised.
5. The protocol has committed to an irreversible release decision.
6. Cryptographic disclosure has actually occurred.

The selected research model makes **release authorisation and irreversible protocol commitment coincide**, but does not confuse either with historical window closure or actual plaintext delivery.

The implementation uses a **restricted, single-instance, signed PBFT-style decision harness** with four fixed witnesses, a declared maximum of one Byzantine witness, durable voting state, and view-change handling. It is **not** a reviewed or production-ready consensus engine.

The lab also demonstrates a creator-independent release worker and an offline recipient that verifies the release package without trusting a SaaS status screen.

**Reported validation from the retained 0.8 run:**

- **150 passing test methods** across generations 0.1–0.8 (131 retained and 19 new).
- **21 terminal-decision conformance vectors** checked by independent Python and Node verifiers.
- **58,880 bounded model transitions** explored without conflicting commits under the model's stated assumptions; a deliberately unsafe variant produces a retained counterexample.
- A **network-disabled recipient** independently verifies and decrypts a legitimate synthetic release package.

These are repository-reported experimental results, **not an external audit or general proof of security**. Bounded exploration does not establish correctness under every possible execution.

Start here: [0.8 executive examination](doc/generation08/EXECUTIVE-0.8.md) · [protocol and state machine](doc/generation08/PROTOCOL-0.8.md) · [adversarial finality lab](doc/generation08/FINALITY-LAB-0.8.md) · [survival and recovery limits](doc/generation08/SURVIVAL-0.8.md) · [benchmarks](doc/generation08/BENCHMARKS-0.8.md).

## Architecture: the promise is not the institution

The experiments distinguish responsibilities rather than assigning everything to one trusted web application:

```text
                  CREATOR
        Standing instruction + keys
                       |
                       v
           Immutable Capsule policy
                       |
          +------------+------------+
          |                         |
          v                         v
  Independent witnesses      Encrypted Capsule
  Evidence + terminal        and commitments
  decision certificates            |
          |                         |
          v                         v
   Release decision        +------------------+
   independently           | Custody domain   |
   verifiable              | 2-of-3 capability|
          |                +------------------+
          |                +------------------+
          +--------------->| Authority domain |
                           | 2-of-3 capability|
                           +------------------+
                                    |
                                    v
                          RECIPIENT VERIFIER
                          Validates the proof
                          and recovers plaintext
```

*Conceptual architecture for the 0.7–0.8 research profile, not a claim of independent real-world operators.* The two cryptographic domains must be independently provisioned and administered for their separation to mean anything. A single Docker host does **not** establish that independence.

A separate Laravel consumer prototype exists in earlier generations, but **the protocol does not depend on Laravel, the SaaS database, or PorterNet**.

## The attacks that still work

The most important findings are not all successes:

- **Combined-domain collusion:** sufficient malicious holders from both cryptographic domains can decrypt prematurely, bypassing release policy. This is an intentionally retained successful attack.
- **Compromised provisioning:** a malicious creator/dealer, correlated keys, or shared administrative access can collapse supposedly independent custody boundaries.
- **Censorship:** a malicious operator can suppress or delay a check-in or disarm. Independent submission and verification reduce reliance on the SaaS but do not make censorship impossible.
- **Uncertain cancellation:** sending a disarm request is not the same as receiving a valid terminal **DISARM** certificate. A prepared release may constrain later requests before the creator sees the outcome.
- **Loss of continuity:** if a domain loses its threshold of keys, or an uncommitted witness committee disappears, legitimate disclosure can become impossible without pre-authorised recovery or succession.
- **Shared infrastructure:** separate containers and identities on one host are not independent institutions. Host compromise, backups, update channels, and rollback remain consequential.

**Confidentiality and availability are separate properties.** Keeping a secret safe forever because nobody can recover it is not successful conditional custody.

Read [the 0.7 executive examination](doc/generation07/EXECUTIVE-0.7.md), [the 0.8 security analysis](doc/generation08/SECURITY-0.8.md), and [the 0.8 finality laboratory](doc/generation08/FINALITY-LAB-0.8.md) for exact attack assumptions and outcomes.

## Reproduce the laboratory

**Prerequisites:** Docker with Compose, a POSIX-compatible shell, and the local prerequisites described in the relevant generation runbooks. Experiments use synthetic content, disposable identities, and simulated disclosure.

From the repository root:

```sh
# Run the current generation's integrated laboratory
./scripts/experiment08.sh

# Rerun the preserved historical regression suites
python3 scripts/regression08.py

# Run the local performance comparison
./scripts/performance08.sh
```

Some experiments provision disposable TLS and key material locally and use fault-injection capabilities **strictly for the laboratory**. Inspect scripts and port/subnet configuration before running them on a shared machine. Results and measurements are retained in [`doc/results08/`](doc/results08/).

Older generations have their own entry points (`scripts/experiment.sh`, `scripts/experiment02.sh`, …, `scripts/experiment07.sh`) and documentation. Do not treat their security semantics as interchangeable with 0.8.

## Explore the repository

| Path | Purpose |
|---|---|
| [`doc/generation08/`](doc/generation08/) | Current finality, attack, recovery, security and performance research |
| [`doc/generation07/`](doc/generation07/) | Split-capability custody and authority experiments |
| [`doc/generation06/`](doc/generation06/) | Honest threshold-decryption research and its impossibility boundary |
| [`doc/generation05/`](doc/generation05/) | Malicious SaaS, trusted creator client and recovery |
| [`doc/generation04/`](doc/generation04/) | Available witness architecture and standalone operation |
| [`doc/generation03/`](doc/generation03/) | Retained signed evidence and quorum intersection |
| [`doc/generation02/`](doc/generation02/) | Early custody and authority separation |
| [`tests08/`](tests08/) | Current adversarial schedules, consensus and integration tests |
| [`Protocol/`](Protocol/) | Versioned protocol material and conformance vectors |
| [`Verifier/`](Verifier/) | Independent JavaScript proof verification |
| [`scripts/`](scripts/) | Reproduction, regression and benchmark entry points |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`CONFORMANCE.md`](CONFORMANCE.md) | Foundational threat model and cross-language verification |

The repository is a **research archive**, not yet a minimal public protocol SDK. A smaller, versioned, single-custodian reference protocol and a separately maintained consumer application are planned as distinct deliverables.

## What this project does *not* claim

- It does not prove that a person is alive, dead, incapacitated, or acting voluntarily.
- It does not infer consent from a missed check-in. Consent comes from the creator's original standing instruction and valid subsequent amendments or revocations.
- It does not guarantee that a creator can revoke after a release has become irreversibly committed.
- It does not prevent premature disclosure by sufficiently colluding secret holders.
- It does not guarantee release if all necessary witnesses, keys, or recovery anchors disappear.
- It does not provide audited cryptography, production Byzantine consensus, secure automatic client updates, independent multi-organisation hosting, or decades-long succession.
- It must not be used as a real-world dead-man's switch, whistleblower vault, inheritance service, or emergency disclosure mechanism in its present form.

## Where this is going

Three deliberately separate efforts:

1. **Otherwise Research** — the public, adversarial laboratory you are reading.
2. **Otherwise Protocol** — a future language-neutral, versioned specification with a small reference implementation and conformance suite, beginning with an explicit single-custodian trust model.
3. **Otherwise Cloud** — a separately maintained consumer SaaS that implements the public protocol without defining its security semantics.

The long-term research question is broader than conditional release:

> **Can the security of a promise be separated from the continuity of the institution keeping it?**

A promise may remain authentic while its keys, witnesses, administrators or recipients disappear. Otherwise investigates both whether an instruction remains **unchanged** and whether it remains **executable**.

---

## Licence

Copyright 2026 Levi Godolphin. Original Otherwise code and project documentation are licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE). Third-party dependencies and referenced works retain their own licences and notices.

## Security reporting

Please read [SECURITY.md](SECURITY.md) before reporting a new vulnerability. Use private reporting for undisclosed security findings or exposed operational material; documented synthetic attacks remain part of the public research record.

### Research ethos

**The human owns the questions. The agent proposes answers. Reality gets the final vote.**

Successful attacks are findings, not embarrassing tests to delete. Historical failures stay reproducible. Assumptions are part of the result. A negative experiment is useful when it tells us which promise we cannot honestly make.

*Otherwise is ongoing independent engineering research. Critique, reproducibility reports and documented synthetic counterexamples are welcome. Please follow [SECURITY.md](SECURITY.md) for new security findings or exposed operational material.*
