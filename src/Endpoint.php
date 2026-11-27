<?php
declare(strict_types=1);
namespace Veritas;

/**
 * The logic behind public/verify.php, kept here so it is testable.
 * Threat model E3: the endpoint must honour the published revocation list. If that list cannot be
 * read, it fails closed (reports the credential as not verifiable) rather than silently skipping
 * revocation.
 */
final class Endpoint
{
    /** Revocation list file format: {"revoked": ["jti", ...]}. Returns null if missing or invalid. */
    public static function loadRevocation(string $path): ?InMemoryRevocation
    {
        if (!is_file($path)) { return null; }
        $j = json_decode((string)file_get_contents($path), true);
        if (!is_array($j) || !isset($j['revoked']) || !is_array($j['revoked'])) { return null; }
        foreach ($j['revoked'] as $id) { if (!is_string($id)) { return null; } }
        return new InMemoryRevocation($j['revoked']);
    }

    /** @return array{valid:bool,reason:string,payload:?array} */
    public static function verify(string $publicKeyB64url, string $revocationPath, string $token, int $now): array
    {
        $rev = self::loadRevocation($revocationPath);
        if ($rev === null) {
            return ['valid' => false, 'reason' => 'revocation list unavailable', 'payload' => null];
        }
        return (new Verifier($publicKeyB64url, $rev))->verify($token, $now);
    }
}
