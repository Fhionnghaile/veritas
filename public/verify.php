<?php
// Optional server-side verify endpoint. GET/POST ?token=... -> JSON.
// Honours the published revocation list (samples/revoked.json) and fails closed if it cannot be read.
require __DIR__.'/../src/Credential.php'; require __DIR__.'/../src/Verifier.php';
require __DIR__.'/../src/Revocation.php'; require __DIR__.'/../src/Endpoint.php';
use Veritas\Endpoint;
$v = json_decode(file_get_contents(__DIR__.'/../samples/vectors.json'), true);
$token = is_string($_REQUEST['token'] ?? null) ? $_REQUEST['token'] : '';
header('Content-Type: application/json');
echo json_encode(Endpoint::verify($v['issuer_public_key_b64url'], __DIR__.'/../samples/revoked.json', $token, time()));
