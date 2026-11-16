<?php
// Optional server-side verify endpoint. GET/POST ?token=... -> JSON.
require __DIR__.'/../src/Credential.php'; require __DIR__.'/../src/Verifier.php'; require __DIR__.'/../src/Revocation.php';
use Veritas\Verifier;
$v = json_decode(file_get_contents(__DIR__.'/../samples/vectors.json'), true);
$token = $_REQUEST['token'] ?? '';
header('Content-Type: application/json');
echo json_encode((new Verifier($v['issuer_public_key_b64url']))->verify($token, time()));
