# Veritas — threat model

**Asset:** a claim that a subject holds a skill at a level, trustworthy without a central lookup.

| Threat | Mitigation |
|--------|-----------|
| Forge a credential | Ed25519 signature over `"v1."+payload`; without the issuer secret, infeasible. |
| Tamper after issue | Any changed byte breaks the signature — verification fails (test: every byte position). |
| Replay an old/withdrawn credential | `exp` (short-lived) + revocation by `jti`; share grants carry their own `exp`. |
| Over-disclosure in a share | Share grant lists exactly which fields are revealed; verifier projects only those. |
| Issuer key compromise | `kid` in the payload enables rotation; publish current keys at `/.well-known/veritas-keys.json`. |
| Downgrade the format | Version string is inside the signed bytes — can't be swapped without breaking the signature. |

**Out of scope:** securing the issuer's secret key at rest (HSM/KMS), and transport security (use TLS).
**Revocation design:** a signed, published revocation list keyed by `jti`, cached by verifiers; absence of network ⇒ fall back to `exp`. No per-verify callback, so verification stays offline and private.
