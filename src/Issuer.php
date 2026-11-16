<?php
declare(strict_types=1);
namespace Veritas;

/** Signs credentials and scoped share grants with an Ed25519 secret key. */
final class Issuer
{
    private string $sk; // 64-byte libsodium secret key

    /** @param string $seed 32-byte Ed25519 seed (keep secret; never ship). */
    public function __construct(string $seed)
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('seed must be 32 bytes');
        }
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $this->sk = sodium_crypto_sign_secretkey($kp);
    }

    public function publicKeyB64(): string
    {
        $kp = sodium_crypto_sign_seed_keypair(sodium_crypto_sign_sk_to_seed($this->sk));
        return Credential::b64urlEncode(sodium_crypto_sign_publickey($kp));
    }

    /** Issue a credential token from claim fields (iss, kid, sub, skill, level, iat, exp, jti). */
    public function issue(array $claims): string
    {
        $payloadB64 = Credential::b64urlEncode(Credential::canonical($claims));
        $sig = sodium_crypto_sign_detached(Credential::signingInput($payloadB64), $this->sk);
        return Credential::VERSION . '.' . $payloadB64 . '.' . Credential::b64urlEncode($sig);
    }

    /**
     * A scoped, time-limited share grant over an existing credential.
     * Token form: s1.<b64url(json{cred,disc,exp,jti})>.<b64url(sig)>.
     */
    public function makeShare(string $credentialToken, array $discloseFields, int $ttlSeconds, int $now): string
    {
        $grant = [
            'cred' => $credentialToken,
            'disc' => array_values($discloseFields),
            'exp'  => $now + $ttlSeconds,
            'jti'  => 'share_' . bin2hex(random_bytes(6)),
        ];
        $b64 = Credential::b64urlEncode(Credential::canonical($grant));
        $sig = sodium_crypto_sign_detached('s1.' . $b64, $this->sk);
        return 's1.' . $b64 . '.' . Credential::b64urlEncode($sig);
    }
}
