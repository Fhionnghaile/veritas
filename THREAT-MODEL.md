# Veritas: threat model

Method: STRIDE, revised 2026-11-26 against the code as it stands (the first version, kept in git
history, described some of the design rather than the code; the differences are marked **Gap** below).
Status: **Mitigated**, **Partial**, **Gap**, **Accepted**.

**Asset:** a claim that a subject holds a skill at a level, trustworthy without a central lookup.
**Trust boundaries:** issuer (holds the secret key) → holder (stores and shares tokens) → verifier
(anyone with the issuer's public key; may be offline).

## STRIDE
| # | Threat | Mitigation (evidence) | Status |
|---|---|---|---|
| S1 | Forge a credential | Ed25519 detached signature over `"v1." + payload` (`src/Issuer.php`, `src/Verifier.php`); golden vectors verified identically in PHP, Python, Kotlin and Swift (`testGoldenVectors`) | Mitigated |
| S2 | Present a credential signed by a different issuer | Verifier is constructed with exactly one issuer public key and checks its length | Mitigated |
| T1 | Change any byte after issue | Signature fails for a change at **every** byte position (`testTamperAnyByteFails`) | Mitigated |
| T2 | Downgrade or swap the format | Version prefix is inside the signed bytes; credentials (`v1.`) and share grants (`s1.`) use different prefixes, so one cannot be passed off as the other | Mitigated |
| R1 | Issuer denies having issued a credential | Only the issuer's key can produce a valid signature (non-repudiation for as long as the key is not compromised) | Mitigated |
| I1 | A share link reveals more than the holder chose | The verifier displays only the chosen fields, **but the share token contains the whole credential**, which anyone holding the link can decode | **Gap**, fix F1 |
| E1 | Keep using a credential after it should stop working | Expiry and revocation by `jti` are checked offline; the expiry/revocation logic is model-checked in veritas-tla and matches the PHP verifier on 47,898 of 47,898 decisions | Mitigated for credentials that carry `exp` and `jti` |
| E2 | A credential issued without `exp` never expires; one without `jti` can never be revoked | `Issuer::issue` does not require either field | **Gap**, fix F2 |
| E3 | The sample endpoint `public/verify.php` ignores revocation | It builds a `Verifier` with no revocation list | **Gap** (demo only), fix F3 |
| D1 | Verification depends on a server being up | None needed: verification is offline by design | Mitigated |
| K1 | Issuer key compromise | `kid` is signed into each credential, so a key can be identified, but the verifier takes a single key; key-set lookup by `kid` and published key rotation are **designed, not built** | **Gap**, fix F4 |

## Fixes, in priority order
- **F1 (I1):** real selective disclosure: sign salted hashes of each field (SD-JWT style) so a share carries only the disclosed fields plus their salts. Until then, the README describes share grants as display-scoped, not cryptographic.
- **F2 (E2):** make `exp` and `jti` mandatory in `Issuer::issue`; reject credentials without them in `Verifier::verify`.
- **F3 (E3):** wire the published revocation list into `public/verify.php`.
- **F4 (K1):** verifier accepts a key set keyed by `kid` (from `/.well-known/veritas-keys.json`); rotation runbook.

## Out of scope
Protecting the issuer's secret key at rest (HSM/KMS) and transport security (TLS).
