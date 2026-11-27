<?php
declare(strict_types=1);
namespace Veritas\Tests;
use PHPUnit\Framework\TestCase;
use Veritas\{Credential, Endpoint, Issuer, Verifier, InMemoryRevocation};

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

    private function seed(): string
    {
        return sodium_base642bin(strtr($this->v['TEST_ONLY_private_seed_b64url'],'-_','+/'), SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /** Signs arbitrary claims directly, bypassing Issuer's checks, to model a non-conforming issuer. */
    private function rawToken(array $claims): string
    {
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($this->seed()));
        $pb = Credential::b64urlEncode(Credential::canonical($claims));
        return Credential::VERSION.'.'.$pb.'.'.Credential::b64urlEncode(sodium_crypto_sign_detached(Credential::signingInput($pb), $sk));
    }

    /** Threat model E2: the issuer refuses credentials that could never expire or never be revoked. */
    public function testIssuerRequiresExpAndJti(): void
    {
        $iss = new Issuer($this->seed());
        foreach ([['jti'=>'c1'], ['exp'=>2000000000], ['exp'=>'2000000000','jti'=>'c1'], ['exp'=>2000000000,'jti'=>'']] as $bad) {
            try { $iss->issue(['iss'=>'i','sub'=>'s'] + $bad); $this->fail('issued without valid exp/jti: '.json_encode($bad)); }
            catch (\InvalidArgumentException $e) { $this->assertTrue(true); }
        }
    }

    /** Threat model E2: a validly signed credential without exp or jti is still rejected. */
    public function testVerifierRejectsMissingExpOrJti(): void
    {
        $now = $this->v['verify_at_unix'];
        $ver = new Verifier($this->v['issuer_public_key_b64url']);
        $this->assertSame('missing exp', $ver->verify($this->rawToken(['sub'=>'s','jti'=>'c1']), $now)['reason']);
        $this->assertSame('missing jti', $ver->verify($this->rawToken(['sub'=>'s','exp'=>$now+100]), $now)['reason']);
        $this->assertTrue($ver->verify($this->rawToken(['sub'=>'s','exp'=>$now+100,'jti'=>'c1']), $now)['valid']);
    }

    /** Threat model E3: the endpoint honours the published list, and fails closed without it. */
    public function testEndpointHonoursRevocationListAndFailsClosed(): void
    {
        $now = $this->v['verify_at_unix'];
        $pub = $this->v['issuer_public_key_b64url'];
        $tok = (new Issuer($this->seed()))->issue(['sub'=>'s','iat'=>$now-1,'exp'=>$now+100,'jti'=>'c9']);
        $dir = sys_get_temp_dir().'/veritas-'.bin2hex(random_bytes(4)); mkdir($dir);
        file_put_contents("$dir/ok.json", json_encode(['revoked'=>[]]));
        file_put_contents("$dir/rev.json", json_encode(['revoked'=>['c9']]));
        file_put_contents("$dir/bad.json", '{not json');
        $this->assertTrue(Endpoint::verify($pub, "$dir/ok.json", $tok, $now)['valid']);
        $this->assertSame('revoked', Endpoint::verify($pub, "$dir/rev.json", $tok, $now)['reason']);
        $this->assertSame('revocation list unavailable', Endpoint::verify($pub, "$dir/bad.json", $tok, $now)['reason']);
        $this->assertSame('revocation list unavailable', Endpoint::verify($pub, "$dir/missing.json", $tok, $now)['reason']);
        $this->assertTrue(Endpoint::verify($pub, __DIR__.'/../samples/revoked.json', $tok, $now)['valid']);
        array_map('unlink', glob("$dir/*")); rmdir($dir);
    }
}
