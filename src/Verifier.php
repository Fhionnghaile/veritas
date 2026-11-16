<?php
declare(strict_types=1);
namespace Veritas;

/** Verifies credential + share tokens offline: signature, expiry, revocation. */
final class Verifier
{
    private string $pk; // 32-byte raw public key
    private ?Revocation $rev;

    public function __construct(string $publicKeyB64, ?Revocation $rev = null)
    {
        $this->pk = Credential::b64urlDecode($publicKeyB64);
        if (strlen($this->pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \InvalidArgumentException('public key must be 32 bytes');
        }
        $this->rev = $rev;
    }

    /** @return array{valid:bool,reason:string,payload:?array} */
    public function verify(string $token, int $now): array
    {
        $p = explode('.', $token);
        if (count($p) !== 3 || $p[0] !== Credential::VERSION) {
            return ['valid' => false, 'reason' => 'bad format', 'payload' => null];
        }
        try {
            $sig = Credential::b64urlDecode($p[2]);
            if (!sodium_crypto_sign_verify_detached($sig, Credential::signingInput($p[1]), $this->pk)) {
                return ['valid' => false, 'reason' => 'signature invalid', 'payload' => null];
            }
            $payload = json_decode(Credential::b64urlDecode($p[1]), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            return ['valid' => false, 'reason' => 'malformed', 'payload' => null];
        }
        if (isset($payload['exp']) && (int)$payload['exp'] < $now) {
            return ['valid' => false, 'reason' => 'expired', 'payload' => $payload];
        }
        if ($this->rev && isset($payload['jti']) && $this->rev->isRevoked($payload['jti'])) {
            return ['valid' => false, 'reason' => 'revoked', 'payload' => $payload];
        }
        return ['valid' => true, 'reason' => 'ok', 'payload' => $payload];
    }

    /** Verify a share grant, then the inner credential, then project disclosed fields. */
    public function verifyShare(string $share, int $now): array
    {
        $p = explode('.', $share);
        if (count($p) !== 3 || $p[0] !== 's1') {
            return ['valid' => false, 'reason' => 'bad share format', 'payload' => null];
        }
        try {
            $sig = Credential::b64urlDecode($p[2]);
            if (!sodium_crypto_sign_verify_detached($sig, 's1.' . $p[1], $this->pk)) {
                return ['valid' => false, 'reason' => 'share signature invalid', 'payload' => null];
            }
            $grant = json_decode(Credential::b64urlDecode($p[1]), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            return ['valid' => false, 'reason' => 'malformed share', 'payload' => null];
        }
        if ((int)($grant['exp'] ?? 0) < $now) {
            return ['valid' => false, 'reason' => 'share expired', 'payload' => null];
        }
        if ($this->rev && isset($grant['jti']) && $this->rev->isRevoked($grant['jti'])) {
            return ['valid' => false, 'reason' => 'share revoked', 'payload' => null];
        }
        $inner = $this->verify($grant['cred'] ?? '', $now);
        if (!$inner['valid']) { return $inner; }
        $disc = array_flip($grant['disc'] ?? []);
        $projected = array_intersect_key($inner['payload'], $disc);
        return ['valid' => true, 'reason' => 'ok', 'payload' => $projected];
    }
}
