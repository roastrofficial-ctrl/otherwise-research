# Security policy

Otherwise is an experimental research archive. Its cryptographic compositions, consensus code, clients and deployment profiles have not received an independent security audit. Do not use this repository to protect real secrets or make real-world disclosure decisions.

## Reporting a vulnerability privately

Please use this repository's **Security → Advisories → Report a vulnerability** option on GitHub, when private vulnerability reporting is enabled. Do not put new vulnerability details, working exploits against live systems, credentials or real Capsule data in a public issue, discussion or pull request.

Private reporting is a separate GitHub repository setting; this file does not enable it. If the reporting option is absent, open an issue containing only a request for a private security contact, with no vulnerability details. Wait for a private channel before sending sensitive material. No security email address or encryption key is advertised by this repository unless a maintainer explicitly adds one here.

Useful reports include:

- The affected commit, generation, component and relevant configuration.
- A concise description of the expected guarantee and the observed violation.
- The attacker's actual capabilities, including any assumed compromised creator, witness, custodian, authorisation holder, administrator or recipient.
- Reproduction steps using a fresh, isolated environment and synthetic data; include commands, a minimal proof of concept and sanitised logs where possible.
- The impact, affected trust boundary and whether the result is prevention failure, detection only, availability loss or an incorrect security claim.
- Any suggested fix, relevant related research, and your preferred acknowledgement or anonymity.

Do not include genuine private keys, passphrases, access tokens, personal information or third-party plaintext. If you discover an exposed operational credential, describe its location and type privately rather than copying the credential into a report.

## What receives attention

| Material | Handling |
| --- | --- |
| Current development branch, including the latest reference profile | Reports are investigated on a best-effort basis; no production support or remediation SLA |
| Earlier generations and retained counterexamples | Preserved as research evidence; not maintained security releases and not promised backports |
| New impact from a historical weakness | Welcome, particularly if it invalidates a current guarantee, crosses a new boundary or exposes operational secrets |
| Dependencies and external services | Report relevant Otherwise impact here; use the upstream project's private channel for its vulnerability where appropriate |

There are no supported production releases or long-term security-maintenance commitments. A passing experiment or a generation number is not a security certification.

## Known attacks versus undisclosed vulnerabilities

Successful attacks are deliberately retained in the public research record. Examples include combined custody/authorisation collusion, compromised or correlated provisioning, shared administration, and historical cancellation failures. Synthetic test shares and test encryption keys may appear in labelled fixtures or attack transcripts; they are not deployment credentials and must never be reused for real data.

Reproducing an already documented synthetic attack is appropriate for a public research discussion. Use private reporting for new vulnerabilities, leaked operational material, or uncertainty about whether a finding is safe to publish. The project does not dismiss a new confidentiality failure merely because the implementation is experimental or the attack uses valid cryptographic arithmetic.

The threat model matters: distinguish a signed assertion from objective truth, a policy proof from a terminal commitment, and a commitment from actual plaintext disclosure. Explain where a finding changes the project's stated guarantees rather than assuming that more signatures or passing tests establish security.

## Coordinated disclosure

Maintainers will review reports as availability permits, reproduce credible findings with synthetic data, and discuss impact, mitigations and an appropriate publication timeline with the reporter. Response and fix dates are not guaranteed. There is no advertised bug-bounty programme or payment commitment.

Disclosure timing should be agreed case by case, considering active exploitation, exposed credentials, affected dependencies and available mitigations. Please do not interpret a delayed response as confirmation that a finding is safe or harmless. Where practical, published findings should include a minimal synthetic reproduction, affected versions/commits, the actual trust assumptions, and whether a fix prevents harm or only detects it. Reporters can request credit or anonymity.

Historical failed designs and counterexamples should remain available. Corrections should update the current guarantees and explicitly version changed semantics, rather than erase evidence or silently claim that an old design was secure.

## Research boundaries

Use local, isolated environments and synthetic Capsules that you control. Do not access, decrypt, disclose or alter anyone else's information, test third-party infrastructure without its owner's permission, or run denial-of-service experiments against public services. Stop if an experiment unexpectedly encounters real data or credentials, and report privately.

This reporting policy does not modify the permissions granted by the project licence. It is not permission to test third-party systems, a legal safe-harbour agreement, or authority to bypass another owner's controls. It cannot provide assurances on behalf of infrastructure operators, contributors or upstream projects.

For the project's technical assumptions and retained outcomes, see [THREAT_MODEL.md](THREAT_MODEL.md), [CONFORMANCE.md](CONFORMANCE.md), and the [Generation 0.8 security analysis](doc/generation08/SECURITY-0.8.md).
