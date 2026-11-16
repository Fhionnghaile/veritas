<?php
// Plain test runner (no PHPUnit needed): php tests/run.php
require __DIR__ . '/../src/Credential.php';
require __DIR__ . '/../src/Issuer.php';
require __DIR__ . '/../src/Verifier.php';
require __DIR__ . '/../src/Revocation.php';
use Veritas\{Issuer, Verifier, InMemoryRevocation};

$v = json_decode(file_get_contents(__DIR__ . '/../samples/vectors.json'), true);
$pub = $v['issuer_public_key_b64url'];
$now = $v['verify_at_unix'];
$fail = 0;

foreach ($v['vectors'] as $vec) {
    $res = (new Verifier($pub))->verify($vec['token'], $now);
    $exp = $vec['expect']['valid'];
    $ok = ($res['valid'] === $exp);
    printf("golden %-9s got=%-5s expect=%-5s reason=%-18s %s\n",
        $vec['name'], $res['valid']?'true':'false', $exp?'true':'false', $res['reason'], $ok?'OK':'FAIL');
    if (!$ok) { $fail++; }
}

// round-trip: issue -> verify -> revoke -> share
$seed = sodium_base642bin(strtr($v['TEST_ONLY_private_seed_b64url'], '-_', '+/'), SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
$iss = new Issuer($seed);
$tok = $iss->issue(['iss'=>'did:web:derrytraining.com','kid'=>'k1','sub'=>'s','skill'=>'docker','level'=>'Advanced','iat'=>$now-1,'exp'=>$now+100,'jti'=>'c1']);
$r1 = (new Verifier($pub))->verify($tok, $now);
printf("roundtrip issue+verify            got=%-5s %s\n", $r1['valid']?'true':'false', $r1['valid']?'OK':'FAIL'); if(!$r1['valid'])$fail++;

$rev = new InMemoryRevocation(['c1']);
$r2 = (new Verifier($pub, $rev))->verify($tok, $now);
printf("revocation (c1 revoked)           got=%-5s reason=%-9s %s\n", $r2['valid']?'true':'false', $r2['reason'], (!$r2['valid'] && $r2['reason']==='revoked')?'OK':'FAIL'); if($r2['valid']||$r2['reason']!=='revoked')$fail++;

$share = $iss->makeShare($tok, ['skill','level'], 60, $now);
$r3 = (new Verifier($pub))->verifyShare($share, $now);
$projOk = $r3['valid'] && array_keys($r3['payload'])===['level','skill'];
printf("scoped share (disclose skill,lvl) got=%-5s fields=%s %s\n", $r3['valid']?'true':'false', implode(',',array_keys($r3['payload']??[])), $projOk?'OK':'FAIL'); if(!$projOk)$fail++;

echo $fail===0 ? "\nALL PASS\n" : "\n$fail FAILED\n";
exit($fail===0 ? 0 : 1);
