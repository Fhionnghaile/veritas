<?php
declare(strict_types=1);
namespace Veritas;

/** Revocation by credential/share jti. Offline-checkable: a published, signed list in production. */
interface Revocation { public function isRevoked(string $jti): bool; }

final class InMemoryRevocation implements Revocation
{
    /** @var array<string,bool> */
    private array $set = [];
    public function __construct(array $jtis = []) { foreach ($jtis as $j) { $this->set[$j] = true; } }
    public function revoke(string $jti): void { $this->set[$jti] = true; }
    public function isRevoked(string $jti): bool { return isset($this->set[$jti]); }
}
