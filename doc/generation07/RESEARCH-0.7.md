# Research decision — 23 October 2026

Read the 0.6 implementation, records and limitations before this design. The pre-change Python/Node wire4 corpus passed (`results07/conformance-before.txt`). This is a **research harness**, not reviewed production cryptography. All previous code and successful attacks remain intact.

## Practical candidates

| Candidate | Indispensable secrets / compromise result | Availability, recovery and maintenance | Decision |
|---|---|---|---|
| A1: separate domains, layered authenticated encryption | Custody opens an outer layer; authorisation opens an inner layer (or reverse). Both layers must remain secret. Intermediate plaintext/key exposure depends on order and which process unwraps | Mature AEAD libraries; careful recipient scoping and migration; avoid sending inner secret to an untrusted combiner | Useful baseline, not selected: two payload layers complicate interpretation of intermediate exposure |
| A2: separate domains, 2-of-2 content-key sharing; threshold-wrap each component | Random A and B=A XOR DEK; two independently generated 2/3 threshold-DH keys wrap A and B. Full custody-domain compromise reveals only A; full authorisation-domain compromise reveals only B. Both domains together decrypt early | Reuses 0.6 point/proof arithmetic and established XOR secret sharing + AES-GCM/HKDF. More services and backups; either domain losing threshold blocks release. Trusted creator/dealer is an explicit exposure | **Selected limited harness**. Smaller change; no new primitive or proof-of-security claim for the integrated system |
| B: existing witnesses also hold B | Same algebra can make witness-held B indispensable, but witness compromise now simultaneously corrupts observations and releases cryptographic capability | Fewer committees; greater correlated authority, repair/rotation complexity; privilege must be explicitly granted, not inferred from attestation identity | Not selected: separate keys/services make the additional boundary and its collapse testable |

A2 makes the missing share cryptographically necessary, unlike a signature checked only by a cooperative server. Plaintext is encrypted once; each domain sees only its own wrapped key component. The recipient alone combines the components in normal operation. There is no online coordinator with both secrets. **The trusted creator/dealer temporarily knows DEK and all setup material; this exposure is not eliminated.** No DKG, proactive refresh or secure erasure is claimed. Separate key generation does not prove separate administrators.

## Bounded advanced-cryptography track

| Approach | Precise property and indispensable authority | Why it does not remove the stated boundary / maturity assessment |
|---|---|---|
| Threshold/MPC predicate evaluation | Distributes evaluation and key operations under a scheme's corruption/security assumptions | If the coalition owns all decryption secrets, it can run another computation. A protocol with an indispensable honest party or external capability changes that assumption. MPyC is an implemented research framework, not an audited malicious-quorum Otherwise release service |
| Verifiable computation / ZK | Verifier can check a statement/computation without trusting its prover (and sometimes without learning private inputs) | A proof is not inherently needed by the underlying decrypt algorithm. A malicious secret-holder can skip the verifier unless a separate cryptographic capability is derived or withheld on that basis |
| ABE | Ciphertext policy can restrict which attribute secret keys decrypt, under the specific scheme's collusion model | Attribute-key authority/master-secret compromise is a different threat. Static attributes do not automatically express revocable absence, complete observation or irreversible disarm. Epoch attributes require correct issuance and retained-old-ciphertext analysis |
| Functional encryption | A function-specific key reveals the authorised function of an encrypted input | Who issues function keys/master authority remains indispensable; lifecycle/time/absence must be correctly represented as authenticated inputs. This is not automatic safety against compromised key issuers |
| Witness encryption | In its formal model, a witness for an NP statement enables decryption, rather than merely approving software | This genuinely changes the proof/decrypt relation, but its security definition/assumptions must fit the statement. Mutable absence/disarm needs trusted complete observations/finality; historical signatures remain witnesses. We identified no reviewed drop-in implementation for this lifecycle and decades-long custody requirement; not integrated |

No time-lock, VDF, scheduled key revelation or future-beacon release mechanism is investigated or implemented here. Time is used only by the preserved evidence lifecycle.

## Primary references and assessment scope

- [Cramer–Gennaro–Schoenmakers, sections 2.3–2.4](https://crypto.ethz.ch/publications/files/CrGeSc97b.pdf): threshold decryption using group-element interpolation and proofs of matching discrete logs. We reuse the unreviewed 0.6 P-256 reference implementation, not a certified election or DKG implementation.
- [RFC 9497, section 2.2](https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2): DLEQ proofs; our retained transcript is **not** RFC wire conformance.
- [Bethencourt–Sahai–Waters CP-ABE](https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf): encryption-bound attribute access policies; its issuer/collusion model must not be conflated with compromised Otherwise domains.
- [Boneh–Sahai–Waters FE](https://eprint.iacr.org/2010/543): function-specific disclosure and key authority.
- [Garg–Gentry–Sahai–Waters witness encryption](https://eprint.iacr.org/2013/258) and [NIST's 2025 research presentation](https://csrc.nist.gov/presentations/2025/stppa7-witness-encryption): formal witness-based decryption and research development, not deployment evidence for this protocol.
- [MPyC maintainer documentation](https://mpyc.readthedocs.io/en/latest/): executable MPC framework and examples, not an asserted malicious-security guarantee for Otherwise.

These assessments are bounded design judgments, not a comprehensive library audit or a claim that advanced schemes are impossible. The selected composition still needs external cryptographic review, hardened key generation/implementation, independently administered infrastructure, authenticated software distribution and a funded migration/backup plan for decades of operation.

### A witness-encryption mapping caveat

Our inference from the original witness-encryption definition is narrower than “encrypt to a signature check”. Basic WE confidentiality is specified for instances **outside** the language. An NP statement such as “there exists a valid threshold signature on this decision” may already be true mathematically before the holders issue that signature. Merely making its witness hard to obtain is not the same as a false instance covered by that basic definition. An Otherwise integration would need a precisely justified construction/security notion (and its observation/finality assumptions), not just a signature verifier encoded as a circuit. This is another reason not to market a speculative proof-dependent scheme as an implemented solution.
