# ADR 0001: Ed25519 detached signatures over canonical JSON

Status: Accepted · Recorded 2026-11-26, retrospectively, from the design as built

## Context
A credential must verify identically in PHP, Python, Kotlin and Swift, offline, and any change to any field must break it.

## Decision
Claims are serialised as canonical JSON (sorted keys, compact) and signed with Ed25519; shared test vectors are verified by every implementation.

## Consequences
Interoperability is proven by vectors, not assumed. Canonicalisation is now part of the contract: every implementation must reproduce the exact bytes (checked by `CanonicalCheck`).

## Alternatives considered
JWT/JWS (rejected: algorithm-confusion history and larger surface); RSA (rejected: larger keys and signatures, slower).
