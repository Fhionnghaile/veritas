# ADR 0002: Expiry is inclusive of the exp second

Status: Accepted · Recorded 2026-11-26, retrospectively, from the design as built

## Context
A credential's validity at the exact second of expiry must be defined once and implemented identically everywhere. The formal model (veritas-tla) originally assumed the stricter rule; trace validation found the mismatch.

## Decision
A credential is expired only when `exp < now`: valid up to and including the `exp` second, as in the format spec and all four reference verifiers. The TLA+ model was corrected to match.

## Consequences
One rule across spec, code and proof, with 47,898 of 47,898 model decisions matching the PHP verifier. This differs from JWT/RFC 7519 (rejected at `exp`); integrators converting from JWT must note it.

## Alternatives considered
Switch to RFC 7519 semantics (deferred: a behaviour change across five implementations, chosen against for now).
