<?php
declare(strict_types=1);
namespace Veritas\Tests;
use PHPUnit\Framework\TestCase;
use Veritas\{Issuer, Verifier, InMemoryRevocation};

final class VerifierTest extends TestCase
{
    private array $v;
    protected function setUp(): void { $this->v = json_decode(file_get_contents(__DIR__.'/../samples/vectors.json'), true); }

    public function testGoldenVectors(): void
    {
        $ver = new Verifier($this->v['issuer_public_key_b64url']);
        foreach ($this->v['vectors'] as $vec) {
            $res = $ver->verify($vec['token'], $this->v['verify_at_unix']);
            $this->assertSame($vec['expect']['valid'], $res['valid'], $vec['name'].': '.$res['reason']);
        }
    }

    public function testTamperAnyByteFails(): void
    {
        $ver = new Verifier($this->v['issuer_public_key_b64url']);
        $valid = $this->v['vectors'][0]['token'];
        [$h,$pb,$sg] = explode('.', $valid);
        for ($i=0; $i<strlen($pb); $i++) {
            $m = $pb; $m[$i] = $m[$i]==='A' ? 'B' : 'A';
            if ($m === $pb) continue;
            $res = $ver->verify("$h.$m.$sg", $this->v['verify_at_unix']);
            $this->assertFalse($res['valid'], "tamper at $i should fail");
        }
    }

    public function testRevocationAndShare(): void
    {
        $now = $this->v['verify_at_unix'];
        $seed = sodium_base642bin(strtr($this->v['TEST_ONLY_private_seed_b64url'],'-_','+/'), SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        $iss = new Issuer($seed);
        $tok = $iss->issue(['iss'=>'i','kid'=>'k','sub'=>'s','skill'=>'docker','level'=>'Advanced','iat'=>$now-1,'exp'=>$now+100,'jti'=>'c1']);
        $this->assertTrue((new Verifier($this->v['issuer_public_key_b64url']))->verify($tok,$now)['valid']);
        $rev = new InMemoryRevocation(['c1']);
        $this->assertFalse((new Verifier($this->v['issuer_public_key_b64url'],$rev))->verify($tok,$now)['valid']);
        $share = $iss->makeShare($tok, ['skill'], 60, $now);
        $out = (new Verifier($this->v['issuer_public_key_b64url']))->verifyShare($share,$now);
        $this->assertSame(['skill'], array_keys($out['payload']));
    }
}
