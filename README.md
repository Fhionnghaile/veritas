# Veritas — verifiable skill credentials

<!-- at-a-glance -->
> **Skill credentials that carry their own proof: verifiable offline, tamper-evident, scoped and revocable.**  
> **Result:** 3 PHP suites + the same credential verified byte-for-byte by reference verifiers in Python, Kotlin and Swift against shared vectors.  
> **Reproduce:** `composer install && composer test   # or: php tests/run.php`  
> ![CI](https://github.com/fhionnghaile/veritas/actions/workflows/ci.yml/badge.svg) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Fhionnghaile/veritas/badge)](https://scorecard.dev/viewer/?uri=github.com/Fhionnghaile/veritas)
>
> **What this is worth:** An employer can trust a credential without phoning home — the basis of a portable, fraud-resistant skills record.


Signed, offline-verifiable skill credentials (Ed25519). Issue a credential, verify it anywhere
**without calling back to a database**, scope what a share link reveals, and revoke by id.

![verify demo](docs/screenshot.png)

## Why
"Trust us, the database says they passed" isn't verifiable. A Veritas credential is a signed token:
anyone with the issuer's public key can confirm it's authentic and untampered — on a plane, offline,
in a browser.

## Run it
```bash
# library tests (no dependencies beyond PHP + ext-sodium)
php tests/run.php
# or the full suite
composer install && composer test
# the public demo (static — open in a browser, or serve public/)
php -S localhost:8000 -t public
```
The demo vendors tweetnacl (public/vendor/nacl.min.js, MIT) so it runs offline — no CDN.

Live tamper demo: open `public/index.html` → **Load sample** → **Verify** (✓) → **Tamper one byte** → **Verify** (✗).

## How it works
- **Token** `v1.<base64url(payload)>.<base64url(sig)>`; signature covers `"v1."+payload` so canonicalisation can't drift across languages.
- **Issuer** (`src/Issuer.php`) signs with an Ed25519 seed; **Verifier** (`src/Verifier.php`) checks signature, expiry and revocation offline.
- **Share grants** (`makeShare`) disclose only chosen fields, expire on their own clock, and are revocable.
- The canonical format + cross-language golden vectors live in [`../credential/`](../credential/) — the same bytes the Laravel issuer and the iOS/Android apps test against.

## Tests
`php tests/run.php` checks the golden vectors (valid / tampered / expired), a full issue→verify round-trip,
revocation, and scoped share projection. CI runs on every push.

## License
MIT.

## Key decisions

- Ed25519 detached signatures over a canonical JSON payload, so any field change breaks the signature.
- Scoped, time-limited, revocable share grants — the trust model, not just the signing, is the hard part.
- Cross-implementation test vectors, so the format is provably interoperable, not 'works on my stack'.

## Scope & limits

- Revocation uses a published list; very-high-scale would add sharding/caching (the lifecycle logic is machine-checked in veritas-tla).
- Key custody is the operator's responsibility; the issuer seed never ships.

