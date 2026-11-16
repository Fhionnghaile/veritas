<?php
declare(strict_types=1);
namespace Veritas;

/** Encodes/decodes the v1 credential token: v1.<b64url(payload)>.<b64url(sig)>. */
final class Credential
{
    public const VERSION = 'v1';

    public static function b64urlEncode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }
    public static function b64urlDecode(string $s): string
    {
        $bin = base64_decode(strtr($s, '-_', '+/'), true);
        if ($bin === false) { throw new \InvalidArgumentException('bad base64url'); }
        return $bin;
    }

    /** Canonical payload JSON: sorted keys, no whitespace, UTF-8. */
    public static function canonical(array $payload): string
    {
        ksort($payload);
        return json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** signing_input = ASCII("v1." + payload_b64) — version is inside the signed data. */
    public static function signingInput(string $payloadB64): string
    {
        return self::VERSION . '.' . $payloadB64;
    }
}
