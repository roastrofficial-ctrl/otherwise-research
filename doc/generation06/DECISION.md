# 0.6 research decision — 22 October 2026

This generation is an explicitly limited research harness, not an audited cryptosystem or a production custody provider. Read the retained [0.5 custody result](../generation05/CUSTODY.md) first. No earlier provider is replaced.

## Candidate assessment

| Candidate | Maturity and assumptions | Cost, recovery and decades-long custody | Decision |
|---|---|---|---|
| Static Shamir/AES (0.5) | Established library; trusted creator/dealer; threshold can reconstruct at any time | Cheap; complete AES key appears at recovery; backup copies count toward compromise | Retain baseline and successful early reconstruction |
| Threshold ElGamal/DH with verifiable partial decryptions | Documented threshold exponentiation and equality-of-discrete-log proofs; group arithmetic library is mature, this integration is unreviewed | Public-key operations and proofs per release; threshold availability; secure key refresh, DKG and migration are additional protocols | Selected **reference harness**, trusted dealer, 2/3 P-256, no production security claim |
| DKG instead of dealer | Established protocols remove one participant's initial knowledge of the whole private scalar; need authenticated channels, complaints, qualification and malicious-party handling | More setup rounds and state; recovery/refresh/rotation must preserve corruption bound across time | Not approximated by adding random shares; deferred to reviewed implementation |
| Hardware-enforced predicate | HSM/TEE can introduce capability unavailable to a server administrator only under precise device policy | Vendor/firmware roots, attestation, trusted time, anti-rollback, backup and replacement policies; long-term hardware/vendor continuity | No hardware available; no hardware guarantee claimed |
| Future beacon/timelock | tlock is implemented; future capability depends on beacon security. Sequential-delay systems depend on speed assumptions | Round/time is not revocable absence evidence; retained old ciphertext remains decryptable; decades change algorithms and operators | Wrong predicate for the current lifecycle |
| MPC evaluates release predicate | General computation can distribute evaluation, subject to protocol corruption assumptions and authenticated inputs | Large integration/round complexity; state, clocks, backups and censorship still matter | Merely computing a Boolean does not bind an already available decrypt algorithm against its controlling threshold |
| Mandatory external/creator secret | Can keep sufficient capability outside custodians | A disappeared creator cannot supply a mandatory secret; an alternate autonomous path must be analysed separately | Conflicts with unconditional autonomous silence release |

## Sources and scope

[Cramer, Gennaro, Schoenmakers, EUROCRYPT 1997, sections 2.3–2.4](https://crypto.ethz.ch/publications/files/CrGeSc97b.pdf) describes threshold ElGamal decryption by combining group elements rather than private scalars, with Chaum–Pedersen correctness proofs. We use that established algebra in additive P-256 notation. This is not an implementation of the paper's election system or its distributed key generation.

[PyCryptodome ECC API](https://www.pycryptodome.org/src/public_key/ecc) supplies validated curve points and arithmetic. It does not supply or audit our threshold protocol. [RFC 9497 section 2](https://www.rfc-editor.org/rfc/rfc9497.html#section-2) documents discrete-log equality proofs; our simple context-tagged Chaum–Pedersen transcript is **not RFC 9497 wire conformance**. HKDF-SHA256/AES-GCM wrap the existing per-Capsule AES key; X25519/HKDF/AES-GCM encrypt each partial to an owner-committed synthetic recipient. This composition and serialization require external review; no CCA, side-channel or composable-security claim follows from a library dependency.

[NIST IR 8214C](https://csrc.nist.gov/pubs/ir/8214/c/final) distinguishes distributed execution of cryptographic primitives from merely sharing storage. [NIST IR 8214](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8214.pdf) discusses key generation, deployment and validation challenges. These are research references, not certification of Otherwise.

[drand tlock](https://github.com/drand/tlock) demonstrates future-beacon encryption. [Intel SGX](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html) describes an isolation boundary, not Otherwise predicate enforcement or trustworthy time.

## Selected scope

A reusable dealer-generated scalar x is shared as x_i=x+a*i mod q. Public commitments X=xG and Y_i=x_iG allow verification of enrollment. Each custodian computes D_i=x_iR and proves log_G(Y_i)=log_R(D_i). The recipient interpolates **points** to xR, derives a wrapping key, unwraps one Capsule's AES key, then decrypts the existing ciphertext. Honest release never interpolates x. The dealer initially knows x and every share; Python provides no secure erasure. This is deliberately not DKG.

The v6 owner-signed custody sidecar commits to the existing immutable wire4 manifest, ciphertext digest, recipient and key generation. Wire4 witness receipts and Boolean authorisation semantics are unchanged. Its legacy operation name still describes AES-key recovery; v6 capabilities explicitly select the different custody method. It is an experimental adapter, not a silently wire-compatible replacement for /release. The legacy static enrollment path is not used by the v6 client.

A malicious threshold can compute the same xR before release, without reconstructing x, without proofs, and without invoking either honest server. This is the central successful counterexample. Context signatures and proof challenges constrain honest/verifying participants; they do not stop holders from doing group arithmetic privately.
