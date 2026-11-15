<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\AgentCard;
use Touchque\AgentKeys;
use Touchque\CrossAppAccess;
use Touchque\Exceptions\TouchqueAgentCardException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueIdJagException;
use Touchque\IdJagVerifier;
use Touchque\McpAuth;

/**
 * Cross App Access (ID-JAG) and A2A agent card signatures against the shared
 * fake API: an app trades a member's ID token for an ID-JAG at the identity
 * provider and redeems it; an authorization server checks one (issuer,
 * audience, client, expiry, typ, once); a card signed in RFC 8785 form by the
 * fake (JavaScript) verifies here with keys from its own host and fails when
 * changed or pointed elsewhere. DPoP (RFC 9449): the proofs, and token
 * endpoints written here (PHP's built-in server) that bind to the proof's key
 * or ask for a nonce, with nonce headers and WWW-Authenticate challenges of
 * every shape, up to 64 KB.
 */
class CrossAppAccessTest extends TestCase
{
    private static FakeApi $api;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    private function verifier(): IdJagVerifier
    {
        return new IdJagVerifier(['issuer' => self::$api->baseUrl . '/idp', 'audience' => 'https://rs.example']);
    }

    private static function reason(callable $fn): string
    {
        try {
            $fn();
            return 'accepted';
        } catch (TouchqueIdJagException $e) {
            return $e->getMessage();
        }
    }

    public function testRequestRedeemAndVerify(): void
    {
        $idp = self::$api->baseUrl . '/idp';
        $jag = CrossAppAccess::requestIdJag(['issuer' => $idp, 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'resource' => 'https://rs.example/files']);
        $this->assertSame('files:read', $jag['scope']);
        try {
            CrossAppAccess::requestIdJag(['issuer' => $idp, 'clientId' => 'tqapp_test', 'clientSecret' => 'wrong', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example']);
            $this->fail('accepted');
        } catch (TouchqueIdJagException $e) {
            $this->assertSame(['invalid_client', 401], [$e->error, $e->status]);
        }
        $v = $this->verifier();
        $claims = $v->verify($jag['assertion'], 'acme-at-rs');
        $this->assertSame(['ada', 'acme-at-rs', ['files:read'], 'https://rs.example/files'], [$claims['sub'], $claims['clientId'], $claims['scopes'], $claims['resource']]);
        $this->assertSame('already used', self::reason(fn () => $v->verify($jag['assertion'], 'acme-at-rs')));
        $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => self::$api->baseUrl . '/rs/token', 'clientId' => 'acme-at-rs', 'assertion' => $jag['assertion']]);
        $this->assertSame('Bearer', $tokens['token_type']);
    }

    public function testRefusals(): void
    {
        $v = $this->verifier();
        $mint = fn (array $claims = [], ?string $typ = null) => self::$api->post('/__test/id-jag', ['claims' => (object)$claims] + ($typ ? ['typ' => $typ] : []))['assertion'];
        $this->assertSame('issued to another client', self::reason(fn () => $v->verify($mint(), 'someone-else')));
        $this->assertSame('not for this authorization server', self::reason(fn () => $v->verify($mint(['aud' => 'https://evil.example']), 'acme-at-rs')));
        $this->assertSame('not for this authorization server', self::reason(fn () => $v->verify($mint(['aud' => ['https://rs.example', 'https://b.example']]), 'acme-at-rs')));
        $this->assertSame('another issuer', self::reason(fn () => $v->verify($mint(['iss' => 'https://evil.example']), 'acme-at-rs')));
        $this->assertSame('not an ID-JAG (typ oauth-id-jag+jwt)', self::reason(fn () => $v->verify($mint([], 'at+jwt'), 'acme-at-rs')));
        $this->assertSame('expired', self::reason(fn () => $v->verify($mint(['exp' => time() - 600]), 'acme-at-rs')));
        [$h, $b, $s] = explode('.', $mint());
        $forged = AgentKeys::b64url(json_encode(['sub' => 'mallory'] + json_decode(AgentKeys::b64urlDecode($b), true)));
        $this->assertSame('signature does not verify', self::reason(fn () => $v->verify("{$h}.{$forged}.{$s}", 'acme-at-rs')));
    }

    /**
     * Runs $fn($baseUrl, $requests) against PHP's built-in server with $router: PHP code that has the
     * SDK's classes and $log, a file it appends one JSON line per request to. $requests() returns
     * those lines and forgets them.
     */
    private function withServer(string $router, callable $fn): void
    {
        $dir = sys_get_temp_dir() . '/tq-dpop-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $log = $dir . '/seen.jsonl';
        file_put_contents($dir . '/router.php', "<?php\nrequire " . $this->export((string)realpath(__DIR__ . '/../vendor/autoload.php')) . ";\n\$log = " . $this->export($log) . ";\n" . $router);
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int)substr(strrchr(stream_socket_get_name($probe, false), ':'), 1);
        fclose($probe);
        $server = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$port}", $dir . '/router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        try {
            for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
                usleep(100000);
            }
            $fn("http://127.0.0.1:{$port}", static function () use ($log): array {
                $lines = is_file($log) ? file($log, FILE_IGNORE_NEW_LINES) : [];
                @unlink($log);
                return array_map(static fn ($l) => json_decode($l, true), $lines);
            });
        } finally {
            proc_terminate($server);
            proc_close($server);
            @unlink($log);
            @unlink($dir . '/router.php');
            @rmdir($dir);
        }
    }

    /** An identity provider and an authorization server that check the proof and bind to its key. */
    private const BINDING_ROUTER = <<<'PHP'
use Touchque\AgentKeys;
use Touchque\McpAuth;
[$h, $p, $sig] = array_pad(explode('.', $_SERVER['HTTP_DPOP'] ?? ''), 3, '');
$header = json_decode(AgentKeys::b64urlDecode($h), true) ?: [];
$payload = json_decode(AgentKeys::b64urlDecode($p), true) ?: [];
$jwk = is_array($header['jwk'] ?? null) ? $header['jwk'] : [];
$ok = $jwk !== [] && McpAuth::verifySignature("$h.$p", AgentKeys::b64urlDecode($sig), 'ES256', $jwk);
$jkt = $jwk !== [] ? AgentKeys::thumbprint($jwk) : '';
file_put_contents($log, json_encode(['path' => $_SERVER['REQUEST_URI'], 'header' => $header, 'payload' => $payload, 'jkt' => $jkt]) . "\n", FILE_APPEND);
header('Content-Type: application/json');
if (!$ok) {
    http_response_code(400);
    echo '{"error":"invalid_dpop_proof"}';
    return true;
}
if ($_SERVER['REQUEST_URI'] === '/idp/token?x=1') {
    $jag = AgentKeys::b64url('{"typ":"oauth-id-jag+jwt","alg":"RS256"}') . '.' . AgentKeys::b64url(json_encode(['cnf' => ['jkt' => $jkt]])) . '.sig';
    echo json_encode(['access_token' => $jag, 'issued_token_type' => 'urn:ietf:params:oauth:token-type:id-jag', 'token_type' => 'N_A']);
    return true;
}
echo '{"access_token":"at","token_type":"DPoP"}';
return true;
PHP;

    /**
     * Token endpoints that ask for a DPoP nonce (RFC 9449 section 8), by path: once with 400 and the
     * JSON error, once with 401 and only a WWW-Authenticate challenge, once with 401 and the JSON
     * error, always (a new nonce each time), once and then refusing the proof that has it, without
     * a DPoP-Nonce header, with another error, with 403; one whose answer is JSON but not an object
     * (the JSON in b); /scripted/token, which answers what its query says (s, h[] header lines, b;
     * a proof carrying the nonce r gets s2, h2[], b2, by default 200 and an ID-JAG); and /big/token,
     * a 64 KB WWW-Authenticate (shape c) or DPoP-Nonce (shape n) with status s and body b.
     */
    private const NONCE_ROUTER = <<<'PHP'
use Touchque\AgentKeys;
$in = array_change_key_case(getallheaders(), CASE_LOWER);
$proof = isset($in['dpop']) ? json_decode(AgentKeys::b64urlDecode(explode('.', $in['dpop'] . '..')[1]), true) : null;
$hasNonce = is_array($proof) && ($proof['nonce'] ?? null) === 'n-1';
$jag = '{"access_token":"jag","issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","token_type":"N_A","expires_in":300}';
$ask = '{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}';
switch (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)) {
    case '/ask400/token':
        $answer = $hasNonce ? [200, [], $jag] : [400, ['DPoP-Nonce: n-1'], $ask];
        break;
    case '/ask401/token':
        $answer = $hasNonce ? [200, [], '{"access_token":"at","token_type":"DPoP"}']
            : [401, ['WWW-Authenticate: DPoP algs="ES256", error="use_dpop_nonce", error_description="nonce required"', 'DPoP-Nonce: n-1'], ''];
        break;
    case '/ask401json/token':
        $answer = $hasNonce ? [200, [], '{"access_token":"at","token_type":"DPoP"}'] : [401, ['DPoP-Nonce: n-1'], $ask];
        break;
    case '/always/token':
        $answer = [400, ['DPoP-Nonce: n-' . bin2hex(random_bytes(4))], $ask];
        break;
    case '/then-refused/token':
        $answer = $hasNonce ? [400, [], '{"error":"invalid_dpop_proof","error_description":"the proof is too old"}'] : [400, ['DPoP-Nonce: n-1'], $ask];
        break;
    case '/no-header/token':
        $answer = [400, [], $ask];
        break;
    case '/other-error/token':
        $answer = [400, ['DPoP-Nonce: n-9'], '{"error":"invalid_grant","error_description":"the assertion expired"}'];
        break;
    case '/forbidden/token':
        $answer = [403, ['DPoP-Nonce: n-9'], $ask];
        break;
    case '/not-an-object/token':
        $answer = [200, [], $_GET['b'] ?? '"ok"'];
        break;
    case '/scripted/token':
        $retried = isset($_GET['r']) && ($proof['nonce'] ?? null) === $_GET['r'];
        $answer = $retried ? [(int)($_GET['s2'] ?? 200), $_GET['h2'] ?? [], $_GET['b2'] ?? $jag] : [(int)$_GET['s'], $_GET['h'] ?? [], $_GET['b'] ?? ''];
        break;
    case '/big/token':
        $challenges = [
            'quoted' => 'DPoP realm="' . str_repeat('a', 65536) . '"',
            'commas' => 'DPoP ' . str_repeat('a,', 30000),
            'escapes' => 'DPoP error="' . str_repeat('\\"', 32768), // never closes
            'schemes' => str_repeat(',DPoP x', 9000) . ' use_dpop_nonce', // a backtracking pattern's worst case
            'params' => 'DPoP ' . str_repeat('error=x, ', 7300),
            'asks-at-the-end' => 'DPoP ' . str_repeat('a=b, ', 13000) . 'error="use_dpop_nonce"',
        ];
        $nonces = ['n-1' => 'n-1', 'valid' => str_repeat('n', 65536), 'invalid' => str_repeat('n', 65535) . '"'];
        $lines = isset($_GET['c']) ? ['WWW-Authenticate: ' . $challenges[$_GET['c']]] : [];
        if (isset($_GET['n'])) {
            $lines[] = 'DPoP-Nonce: ' . $nonces[$_GET['n']];
        }
        $answer = $hasNonce ? [200, [], $jag] : [(int)$_GET['s'], $lines, ['jag' => $jag, 'ask' => $ask, '' => ''][$_GET['b'] ?? '']];
        break;
    default:
        $answer = [404, [], '{"error":"not_found"}'];
}
$sent = null;
foreach ($answer[1] as $line) {
    if (stripos($line, 'DPoP-Nonce:') === 0) {
        $sent = trim(substr($line, 11));
    }
}
file_put_contents($log, json_encode(['path' => $_SERVER['REQUEST_URI'], 'authorization' => $in['authorization'] ?? null, 'body' => file_get_contents('php://input'),
    'dpop' => $in['dpop'] ?? null, 'proof' => $proof, 'sent' => $sent], JSON_INVALID_UTF8_SUBSTITUTE) . "\n", FILE_APPEND);
header('Content-Type: application/json');
foreach ($answer[1] as $line) {
    header($line, false); // a header line given twice is sent twice
}
http_response_code($answer[0]); // after the headers: PHP makes any answer with WWW-Authenticate a 401
echo $answer[2];
return true;
PHP;

    public function testDpopBoundRequestRedeemAndVerify(): void
    {
        $this->withServer(self::BINDING_ROUTER, function (string $local, callable $requests) {
            $key = CrossAppAccess::createIdJagDpopKey();
            $got = CrossAppAccess::requestIdJag(['tokenEndpoint' => $local . '/idp/token?x=1', 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'dpopKey' => $key]);
            $this->assertTrue($got['dpopBound']);
            $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => $local . '/rs/token', 'clientId' => 'acme-at-rs', 'assertion' => $got['assertion'], 'dpopKey' => $key]);
            $this->assertSame('DPoP', $tokens['token_type']);
            $seen = $requests();
            $this->assertCount(2, $seen);
            $this->assertSame(['dpop+jwt', 'ES256', $key['thumbprint']], [$seen[0]['header']['typ'], $seen[0]['header']['alg'], $seen[0]['jkt']]);
            $this->assertArrayNotHasKey('d', $seen[0]['header']['jwk']);
            $this->assertSame(['POST', $local . '/idp/token'], [$seen[0]['payload']['htm'], $seen[0]['payload']['htu']]);
            $this->assertSame([$local . '/rs/token', $key['thumbprint']], [$seen[1]['payload']['htu'], $seen[1]['jkt']]);
            $this->assertNotSame($seen[0]['payload']['jti'], $seen[1]['payload']['jti']);
        });
        // An identity provider that ignores DPoP answers with a bearer ID-JAG: dpopBound false.
        $plainJag = CrossAppAccess::requestIdJag(['issuer' => self::$api->baseUrl . '/idp', 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'dpopKey' => CrossAppAccess::createIdJagDpopKey()]);
        $this->assertFalse($plainJag['dpopBound']);

        // The verifier: a bound ID-JAG needs the proof key's thumbprint, refused before it is used up.
        $v = $this->verifier();
        $mint = fn (array $claims) => self::$api->post('/__test/id-jag', ['claims' => (object)$claims])['assertion'];
        $bound = $mint(['cnf' => ['jkt' => 'right-key-thumbprint']]);
        $this->assertSame('bound to a DPoP key: a DPoP proof with that key is required', self::reason(fn () => $v->verify($bound, 'acme-at-rs')));
        $this->assertSame('the DPoP proof was made with another key', self::reason(fn () => $v->verify($bound, 'acme-at-rs', 'other-key')));
        $this->assertSame('right-key-thumbprint', $v->verify($bound, 'acme-at-rs', 'right-key-thumbprint')['cnfJkt']);
        $this->assertSame('unsupported confirmation method (only DPoP cnf.jkt)', self::reason(fn () => $v->verify($mint(['cnf' => ['x5t' => 'abc']]), 'acme-at-rs', 'x')));
        // Unbound: as before, with or without a proof key.
        $this->assertNull($v->verify($mint([]), 'acme-at-rs', 'any')['cnfJkt']);
    }

    /** A proof's header, payload and raw signature, and whether the signature verifies with the header's jwk. */
    private static function proofParts(string $proof): array
    {
        [$h, $p, $s] = explode('.', $proof);
        $header = json_decode(AgentKeys::b64urlDecode($h), true);
        $signature = AgentKeys::b64urlDecode($s);
        return [
            'header' => $header, 'payload' => json_decode(AgentKeys::b64urlDecode($p), true), 'signature' => $signature,
            'verifies' => McpAuth::verifySignature("{$h}.{$p}", $signature, 'ES256', $header['jwk']),
        ];
    }

    public function testDpopProofOptions(): void
    {
        $key = CrossAppAccess::createIdJagDpopKey();
        // The two-argument form: a proof for one POST.
        $post = self::proofParts(CrossAppAccess::idJagDpopProof($key, 'https://sso.touchque.com/sso/token?x=1#f'));
        $this->assertSame(['typ' => 'dpop+jwt', 'alg' => 'ES256', 'jwk' => $key['publicJwk']], $post['header']);
        $this->assertSame(['kty', 'crv', 'x', 'y'], array_keys($post['header']['jwk']));
        $this->assertSame([32, 32], [strlen(AgentKeys::b64urlDecode($post['header']['jwk']['x'])), strlen(AgentKeys::b64urlDecode($post['header']['jwk']['y']))]);
        $this->assertSame($key['thumbprint'], AgentKeys::thumbprint($post['header']['jwk']));
        $this->assertSame(['htm', 'htu', 'iat', 'jti'], array_keys($post['payload']));
        $this->assertSame(['POST', 'https://sso.touchque.com/sso/token'], [$post['payload']['htm'], $post['payload']['htu']]);
        $this->assertIsInt($post['payload']['iat']);
        $this->assertEqualsWithDelta(time(), $post['payload']['iat'], 5);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $post['payload']['jti']);
        $this->assertSame(64, strlen($post['signature']));
        $this->assertTrue($post['verifies']);

        // A call with a DPoP-bound access token: the method uppercased, ath over the token (the
        // access token and ath of RFC 9449's examples), the server's nonce.
        $get = self::proofParts(CrossAppAccess::idJagDpopProof($key, 'https://API.Example.com:443/v1/files?x=1', [
            'method' => 'get', 'accessToken' => 'Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU', 'nonce' => 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
        ]));
        $this->assertSame(['htm', 'htu', 'iat', 'jti', 'ath', 'nonce'], array_keys($get['payload']));
        $this->assertSame(
            ['GET', 'https://api.example.com/v1/files', 'fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo', 'eyJ7S_zG.eyJH0-Z.HX4w-7v'],
            [$get['payload']['htm'], $get['payload']['htu'], $get['payload']['ath'], $get['payload']['nonce']]
        );
        $this->assertSame($post['header'], $get['header']);
        $this->assertTrue($get['verifies']);
        $this->assertNotSame($post['payload']['jti'], $get['payload']['jti']);
        $this->assertSame('DELETE', self::proofParts(CrossAppAccess::idJagDpopProof($key, 'https://a.example/x', ['method' => 'Delete']))['payload']['htm']);
        // Each access token its own ath; an empty or null option adds nothing.
        $this->assertSame(AgentKeys::b64url(hash('sha256', 'at-2', true)), self::proofParts(CrossAppAccess::idJagDpopProof($key, 'https://a.example/x', ['accessToken' => 'at-2']))['payload']['ath']);
        $this->assertSame(['htm', 'htu', 'iat', 'jti'], array_keys(self::proofParts(CrossAppAccess::idJagDpopProof($key, 'https://a.example/x', ['accessToken' => null, 'nonce' => '']))['payload']));

        // Only the public members go in the header, whatever the key array carries.
        $padded = ['privateKey' => $key['privateKey'], 'publicJwk' => $key['publicJwk'] + ['d' => 'private', 'kid' => 'k1', 'alg' => 'ES256'], 'thumbprint' => 'x'];
        $this->assertSame($key['publicJwk'], self::proofParts(CrossAppAccess::idJagDpopProof($padded, 'https://a.example/x'))['header']['jwk']);
        $other = CrossAppAccess::createIdJagDpopKey();
        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $p384 = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        $publicOnly = openssl_pkey_get_public(openssl_pkey_get_details($key['privateKey'])['key']);
        openssl_pkey_export($key['privateKey'], $pem);
        $bads = [
            [], ['privateKey' => $key['privateKey']], ['publicJwk' => $key['publicJwk']],
            ['privateKey' => $key['privateKey'], 'publicJwk' => ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'abc']],
            ['privateKey' => $key['privateKey'], 'publicJwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => $key['publicJwk']['x'], 'y' => 'abc']],
            ['privateKey' => $key['privateKey'], 'publicJwk' => $other['publicJwk']], // another key's public part
            ['privateKey' => $rsa, 'publicJwk' => $key['publicJwk']], ['privateKey' => $p384, 'publicJwk' => $key['publicJwk']],
            ['privateKey' => $publicOnly, 'publicJwk' => $key['publicJwk']], ['privateKey' => $pem, 'publicJwk' => $key['publicJwk']],
            ['privateKey' => new \stdClass(), 'publicJwk' => $key['publicJwk']],
        ];
        foreach ($bads as $i => $bad) {
            $this->assertSame('the DPoP key must be one from createIdJagDpopKey()', self::configError(fn () => CrossAppAccess::idJagDpopProof($bad, 'https://a.example/x')), "key {$i}");
        }
    }

    /** The message of the TouchqueConfigException $fn throws. */
    private static function configError(callable $fn): string
    {
        try {
            $fn();
        } catch (TouchqueConfigException $e) {
            return $e->getMessage();
        }
        throw new \RuntimeException('no TouchqueConfigException');
    }

    public function testDpopProofMethodAndOptionsAreChecked(): void
    {
        $key = CrossAppAccess::createIdJagDpopKey();
        $htm = static fn (array $options) => self::proofParts(CrossAppAccess::idJagDpopProof($key, 'https://a.example/x', $options))['payload']['htm'];
        // Trimmed and uppercased; nothing left (or no method): POST.
        foreach (['' => 'POST', " \t\r\n " => 'POST', ' get ' => 'GET', "patch\n" => 'PATCH', 'Options' => 'OPTIONS', 'm-search' => 'M-SEARCH', "!#$%&'*+-.^_`|~09az" => "!#$%&'*+-.^_`|~09AZ"] as $method => $sent) {
            $this->assertSame($sent, $htm(['method' => (string)$method]), json_encode($method));
        }
        $this->assertSame('POST', $htm(['method' => null]));
        // Not an RFC 9110 token: a configuration error, before anything is signed.
        foreach (['GE T', 'GET(', 'G"ET', 'GET/1', 'GÉT', "G\x00T", "G\xffT", 'GET,POST'] as $method) {
            $this->assertSame(
                'CrossAppAccess::idJagDpopProof(): method ' . json_encode($method, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . ' is not an HTTP method (RFC 9110 token characters only)',
                self::configError(fn () => $htm(['method' => $method]))
            );
        }
        // An option the proof does not know (a snake_case or misspelt key, a list) is named, not ignored.
        $known = ' (options are camelCase: method, accessToken, nonce)';
        $this->assertSame('CrossAppAccess::idJagDpopProof(): unknown option(s) access_token' . $known, self::configError(fn () => $htm(['access_token' => 'at'])));
        $this->assertSame('CrossAppAccess::idJagDpopProof(): unknown option(s) Method, ath' . $known, self::configError(fn () => $htm(['Method' => 'GET', 'ath' => 'x', 'nonce' => 'n'])));
        $this->assertSame('CrossAppAccess::idJagDpopProof(): unknown option(s) 0' . $known, self::configError(fn () => $htm(['GET'])));
        foreach (['method' => ['GET'], 'accessToken' => 42, 'nonce' => true] as $name => $value) {
            $this->assertSame("CrossAppAccess::idJagDpopProof(): {$name} must be a string", self::configError(fn () => $htm([$name => $value])));
        }
    }

    public function testDpopProofHtu(): void
    {
        // Scheme and host lowercased, the default port dropped, "/" for an empty path, the path as given
        // (no dot-segment removal, no percent-encoding changes), no user info, query or fragment.
        $key = CrossAppAccess::createIdJagDpopKey();
        $cases = [
            'https://example.com/a/../b/./c' => 'https://example.com/a/../b/./c',
            'https://example.com/a b/ünï' => 'https://example.com/a b/ünï',
            'https://example.com//x//' => 'https://example.com//x//',
            'https://sso.touchque.com/sso/token?x=1#f' => 'https://sso.touchque.com/sso/token',
            'https://API.Example.com:443/v1/files?x=1' => 'https://api.example.com/v1/files',
            'HTTPS://Example.COM' => 'https://example.com/',
            'https://example.com?q=1' => 'https://example.com/',
            'https://example.com#top' => 'https://example.com/',
            'http://Localhost:80/a' => 'http://localhost/a',
            'http://127.0.0.1:8080/token' => 'http://127.0.0.1:8080/token',
            'http://example.com:443/x' => 'http://example.com:443/x',
            'https://example.com:80/x' => 'https://example.com:80/x',
            'https://example.com:0443/p' => 'https://example.com/p',
            'https://example.com:8443/a%2Fb%7e/C' => 'https://example.com:8443/a%2Fb%7e/C',
            'https://user:secret@Example.com/x' => 'https://example.com/x',
            'https://[::1]:443/x' => 'https://[::1]/x',
        ];
        foreach ($cases as $url => $htu) {
            $this->assertSame($htu, self::proofParts(CrossAppAccess::idJagDpopProof($key, $url))['payload']['htu'], $url);
        }
        foreach (['/token', 'sso.touchque.com/token', 'https:///token'] as $url) {
            try {
                CrossAppAccess::idJagDpopProof($key, $url);
                $this->fail("accepted {$url}");
            } catch (TouchqueConfigException $e) {
                $this->assertSame("{$url} is not an absolute URL", $e->getMessage());
            }
        }
        // A control character would come out of parse_url() as "_": refused instead.
        foreach (["https://example.com/x\ty" => 'https://example.com/x\ty', "https://example.com/x\n" => 'https://example.com/x\n', "https://exa\x7Fmple.com/" => 'https://exa\177mple.com/'] as $url => $shown) {
            $this->assertSame("the URL {$shown} has a control character", self::configError(fn () => CrossAppAccess::idJagDpopProof($key, $url)));
        }
    }

    /** The two requests of a nonce retry: the same body and client authentication, a new proof with the nonce. */
    private function assertSentOnceMore(array $seen, string $nonce): void
    {
        $this->assertCount(2, $seen);
        [$first, $second] = [$seen[0]['proof'], $seen[1]['proof']];
        $this->assertArrayNotHasKey('nonce', $first);
        $this->assertSame($nonce, $second['nonce']);
        $this->assertNotSame($first['jti'], $second['jti']);
        $this->assertIsInt($second['iat']);
        $this->assertSame([$first['htm'], $first['htu']], [$second['htm'], $second['htu']]);
        $this->assertNotSame($seen[0]['dpop'], $seen[1]['dpop']);
        $this->assertSame([$seen[0]['path'], $seen[0]['body'], $seen[0]['authorization']], [$seen[1]['path'], $seen[1]['body'], $seen[1]['authorization']]);
    }

    private static function idJagError(callable $fn): TouchqueIdJagException
    {
        try {
            $fn();
        } catch (TouchqueIdJagException $e) {
            return $e;
        }
        throw new \RuntimeException('no TouchqueIdJagException');
    }

    public function testATokenEndpointsNonceIsSentOnceMore(): void
    {
        $this->withServer(self::NONCE_ROUTER, function (string $local, callable $requests) {
            $key = CrossAppAccess::createIdJagDpopKey();
            // 400 use_dpop_nonce with a DPoP-Nonce header, at the identity provider (client_secret_basic).
            $jag = CrossAppAccess::requestIdJag(['tokenEndpoint' => $local . '/ask400/token?x=1', 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test',
                'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'scope' => ['files:read'], 'dpopKey' => $key]);
            $this->assertSame(['jag', 300], [$jag['assertion'], $jag['expiresIn']]);
            $seen = $requests();
            $this->assertSentOnceMore($seen, 'n-1');
            $this->assertSame('Basic ' . base64_encode('tqapp_test:tqs_test'), $seen[1]['authorization']);
            $this->assertStringContainsString('subject_token=idtoken%3Aada', $seen[1]['body']);
            $this->assertSame($local . '/ask400/token', $seen[1]['proof']['htu']);

            // 401 with only a WWW-Authenticate: DPoP error="use_dpop_nonce" challenge, at the authorization
            // server; the client in the body (no secret).
            $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => $local . '/ask401/token', 'clientId' => 'acme-at-rs', 'assertion' => 'jag', 'dpopKey' => $key]);
            $this->assertSame(['at', 'DPoP'], [$tokens['access_token'], $tokens['token_type']]);
            $seen = $requests();
            $this->assertSentOnceMore($seen, 'n-1');
            $this->assertNull($seen[1]['authorization']);
            $this->assertStringContainsString('client_id=acme-at-rs', $seen[1]['body']);

            // 401 with the JSON error, client_secret_basic.
            $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => $local . '/ask401json/token', 'clientId' => 'acme-at-rs', 'clientSecret' => 's3cret', 'assertion' => 'jag', 'dpopKey' => $key]);
            $this->assertSame('DPoP', $tokens['token_type']);
            $seen = $requests();
            $this->assertSentOnceMore($seen, 'n-1');
            $this->assertSame('Basic ' . base64_encode('acme-at-rs:s3cret'), $seen[1]['authorization']);
        });
    }

    public function testNoNonceRetryWithoutAKeyAndNeverASecondOne(): void
    {
        $this->withServer(self::NONCE_ROUTER, function (string $local, callable $requests) {
            $key = CrossAppAccess::createIdJagDpopKey();
            $ask = static fn (string $path, ?array $dpopKey) => self::idJagError(fn () => CrossAppAccess::requestIdJag([
                'tokenEndpoint' => $local . $path, 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'dpopKey' => $dpopKey,
            ]));

            // Without a key: one request, no DPoP header, the server's nonce on the error.
            $e = $ask('/ask400/token', null);
            $this->assertSame(['use_dpop_nonce', 400, 'n-1'], [$e->error, $e->status, $e->dpopNonce]);
            $seen = $requests();
            $this->assertCount(1, $seen);
            $this->assertNull($seen[0]['dpop']);

            // A server that asks again: two requests, never a third; the error has its latest nonce.
            $e = $ask('/always/token', $key);
            $seen = $requests();
            $this->assertCount(2, $seen);
            $this->assertSame($seen[0]['sent'], $seen[1]['proof']['nonce']);
            $this->assertNotSame($seen[0]['sent'], $seen[1]['sent']);
            $this->assertSame(['use_dpop_nonce', 400, $seen[1]['sent']], [$e->error, $e->status, $e->dpopNonce]);
            $this->assertSame('Authorization server requires nonce in DPoP proof', $e->getMessage());
            // Refused again without a new nonce: the usual error, with the nonce the server sent before.
            $e = $ask('/then-refused/token', $key);
            $this->assertSame(['invalid_dpop_proof', 400, 'n-1', 'the proof is too old'], [$e->error, $e->status, $e->dpopNonce, $e->getMessage()]);
            $this->assertSentOnceMore($requests(), 'n-1');

            // No DPoP-Nonce header, another error, or another status: one request; any nonce sent is on the error.
            $e = $ask('/no-header/token', $key);
            $this->assertSame(['use_dpop_nonce', 400, null], [$e->error, $e->status, $e->dpopNonce]);
            $this->assertCount(1, $requests());
            $e = $ask('/other-error/token', $key);
            $this->assertSame(['invalid_grant', 400, 'n-9'], [$e->error, $e->status, $e->dpopNonce]);
            $this->assertCount(1, $requests());
            $e = $ask('/forbidden/token', $key);
            $this->assertSame(['use_dpop_nonce', 403, 'n-9'], [$e->error, $e->status, $e->dpopNonce]);
            $this->assertCount(1, $requests());

            // An error from the verifier or the network has no nonce.
            $this->assertNull((new TouchqueIdJagException('invalid_grant', 'expired'))->dpopNonce);
        });
    }

    /**
     * A /scripted/token URL: the first answer ($status, $headers, $body); a proof carrying $retryNonce
     * gets $then ([status, header lines, body]; by default 200 and an ID-JAG).
     */
    private static function scripted(string $local, int $status, array $headers, string $body = '', ?string $retryNonce = null, ?array $then = null): string
    {
        $query = ['s' => $status, 'h' => $headers, 'b' => $body] + ($retryNonce === null ? [] : ['r' => $retryNonce]);
        if ($then !== null) {
            [$query['s2'], $query['h2'], $query['b2']] = $then;
        }
        return $local . '/scripted/token?' . http_build_query($query);
    }

    public function testOnlyOneValidNonceIsSentOnceMore(): void
    {
        $this->withServer(self::NONCE_ROUTER, function (string $local, callable $requests) {
            $key = CrossAppAccess::createIdJagDpopKey();
            $ask = '{"error":"use_dpop_nonce","error_description":"nonce required"}';
            $redeem = static fn (string $url, ?array $dpopKey) => CrossAppAccess::redeemIdJag(['tokenEndpoint' => $url, 'clientId' => 'acme-at-rs', 'assertion' => 'jag', 'dpopKey' => $dpopKey]);

            // RFC 9449 nonce syntax is 1*NQCHAR: printable ASCII but space, " and \. Any other DPoP-Nonce, an
            // empty one, or one repeated with different values: no retry, the usual error, no nonce on it.
            $refused = [
                'space' => ['DPoP-Nonce: n 1'], 'quote' => ['DPoP-Nonce: n"1'], 'backslash' => ['DPoP-Nonce: n\\1'], 'tab' => ["DPoP-Nonce: n\t1"],
                'DEL' => ["DPoP-Nonce: n\x7F"], 'UTF-8' => ['DPoP-Nonce: nönce'], 'not UTF-8' => ["DPoP-Nonce: n\xFF"], 'empty' => ['DPoP-Nonce:'],
                'two values' => ['DPoP-Nonce: n-1', 'DPoP-Nonce: n-2'], 'a value and an empty one' => ['DPoP-Nonce: n-1', 'DPoP-Nonce:'],
            ];
            foreach ($refused as $case => $lines) {
                foreach ([$key, null] as $dpopKey) {
                    $e = self::idJagError(fn () => $redeem(self::scripted($local, 400, $lines, $ask, 'n-1'), $dpopKey));
                    $this->assertSame(['use_dpop_nonce', 400, null], [$e->error, $e->status, $e->dpopNonce], $case);
                    $this->assertCount(1, $requests(), $case);
                }
                // The same in a 401's challenge.
                $e = self::idJagError(fn () => $redeem(self::scripted($local, 401, array_merge($lines, ['WWW-Authenticate: DPoP error="use_dpop_nonce"']), '', 'n-1'), $key));
                $this->assertSame([401, null], [$e->status, $e->dpopNonce], $case);
                $this->assertCount(1, $requests(), $case);
            }

            // One value given twice is one value; every NQCHAR is fine.
            $this->assertSame('jag', $redeem(self::scripted($local, 400, ['DPoP-Nonce: n-1', 'DPoP-Nonce: n-1'], $ask, 'n-1'), $key)['access_token']);
            $this->assertSentOnceMore($requests(), 'n-1');
            $every = implode('', array_map('chr', array_merge([0x21], range(0x23, 0x5B), range(0x5D, 0x7E))));
            $this->assertSame('jag', $redeem(self::scripted($local, 400, ["DPoP-Nonce: {$every}"], $ask, $every), $key)['access_token']);
            $this->assertSentOnceMore($requests(), $every);

            // The error has the latest valid nonce: the retry's answer's, else the first answer's.
            $tooOld = '{"error":"invalid_dpop_proof","error_description":"the proof is too old"}';
            foreach ([['DPoP-Nonce: n-2'], ['DPoP-Nonce: n 2'], ['DPoP-Nonce: n-2', 'DPoP-Nonce: n-3'], []] as $i => $then) {
                $e = self::idJagError(fn () => $redeem(self::scripted($local, 400, ['DPoP-Nonce: n-1'], $ask, 'n-1', [400, $then, $tooOld]), $key));
                $this->assertSame(['invalid_dpop_proof', $i === 0 ? 'n-2' : 'n-1'], [$e->error, $e->dpopNonce], "retry answer {$i}");
                $this->assertSentOnceMore($requests(), 'n-1');
            }

            // An identity provider's answer that is no ID-JAG: invalid_response, with its valid nonce.
            $request = static fn (string $url) => self::idJagError(fn () => CrossAppAccess::requestIdJag(['tokenEndpoint' => $url, 'clientId' => 'tqapp_test',
                'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'dpopKey' => $key]));
            $this->assertSame(['invalid_response', 'n-7'], [($e = $request(self::scripted($local, 200, ['DPoP-Nonce: n-7'], '{}')))->error, $e->dpopNonce]);
            $this->assertSame(['invalid_response', null], [($e = $request(self::scripted($local, 200, ['DPoP-Nonce: n 7'], '{}')))->error, $e->dpopNonce]);
            $requests();
        });
    }

    public function testWhichChallengesAskForANonce(): void
    {
        // RFC 9110 section 11.6.1: only a DPoP challenge's own error parameter counts.
        $this->withServer(self::NONCE_ROUTER, function (string $local, callable $requests) {
            $key = CrossAppAccess::createIdJagDpopKey();
            $redeem = static fn (array $challenges) => CrossAppAccess::redeemIdJag(['tokenEndpoint' => self::scripted($local, 401,
                array_merge(array_map(static fn (string $c) => "WWW-Authenticate: {$c}", $challenges), ['DPoP-Nonce: n-1']), '', 'n-1'), 'clientId' => 'acme-at-rs', 'assertion' => 'jag', 'dpopKey' => $key]);
            $asks = [
                ['DPoP error="use_dpop_nonce"'], ['dpop ERROR=use_dpop_nonce'], ['DPoP error = "use_dpop_nonce"'],
                ['Bearer realm="api", DPoP algs="ES256 PS256", error="use_dpop_nonce", error_description="a, \"quoted\" text"'],
                ['Basic YWxh/ZGRp==, DPoP error="use\_dpop\_nonce"'], ['Newauth realm="apps", type=1, title="Login to \"apps\"", DPoP error="use_dpop_nonce"'],
                ['Bearer realm="api"', 'DPoP error="use_dpop_nonce"'],
            ];
            foreach ($asks as $challenges) {
                $this->assertSame('jag', $redeem($challenges)['access_token'], implode(' | ', $challenges));
                $this->assertSentOnceMore($requests(), 'n-1');
            }
            $doesNotAsk = [
                ['Bearer error="use_dpop_nonce"'], ['Bearer realm="api", error="use_dpop_nonce", DPoP algs="ES256"'], ['DPoP realm="error=use_dpop_nonce"'],
                ['DPoP error="use_dpop_nonce_later"'], ['DPoP error="USE_DPOP_NONCE"'], ['DPoP error="use_dpop_nonce'], ['DPoP error_description="use_dpop_nonce"'],
                ['DPoPx error="use_dpop_nonce"'], ['DPoP error=, use_dpop_nonce'], ['DPoP error=="use_dpop_nonce"'], ['use_dpop_nonce'], ['"DPoP error=use_dpop_nonce"'],
            ];
            foreach ($doesNotAsk as $challenges) {
                $e = self::idJagError(fn () => $redeem($challenges));
                $this->assertSame(['server_error', 401, 'n-1'], [$e->error, $e->status, $e->dpopNonce], implode(' | ', $challenges));
                $this->assertCount(1, $requests(), implode(' | ', $challenges));
            }
        });
    }

    public function testHugeChallengesAndNoncesAreReadInLinearTime(): void
    {
        // 64 KB headers: answered at once, with the normal result or the ID-JAG error. Without PCRE's JIT too,
        // where a backtracking pattern over the challenge takes seconds.
        $jit = ini_get('pcre.jit');
        ini_set('pcre.jit', '0');
        try {
            $this->withServer(self::NONCE_ROUTER, function (string $local, callable $requests) {
                $key = CrossAppAccess::createIdJagDpopKey();
                $timed = function (string $query, ?array $dpopKey) use ($local) {
                    $start = hrtime(true);
                    try {
                        $out = CrossAppAccess::requestIdJag(['tokenEndpoint' => "{$local}/big/token?{$query}", 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test',
                            'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'dpopKey' => $dpopKey]);
                    } catch (TouchqueIdJagException $e) {
                        $out = $e;
                    }
                    $this->assertLessThan(1.0, (hrtime(true) - $start) / 1e9, $query);
                    return $out;
                };
                foreach (['quoted', 'commas', 'escapes', 'schemes', 'params'] as $shape) {
                    $this->assertSame('jag', $timed("c={$shape}&s=200&b=jag", null)['assertion'], $shape);
                    $e = $timed("c={$shape}&s=401&n=n-1", $key);
                    $this->assertInstanceOf(TouchqueIdJagException::class, $e, $shape);
                    $this->assertSame(['server_error', 401, 'n-1'], [$e->error, $e->status, $e->dpopNonce], $shape);
                    $this->assertCount(2, $requests(), $shape); // the 200 and the 401: no retry
                }
                // Asked for at the end of 64 KB: found, and the request goes once more.
                $this->assertSame('jag', $timed('c=asks-at-the-end&s=401&n=n-1', $key)['assertion']);
                $this->assertSentOnceMore($requests(), 'n-1');
                // A 64 KB DPoP-Nonce: one that is not nonce syntax at its end gets no retry and is not on the error.
                $e = $timed('n=invalid&s=400&b=ask', $key);
                $this->assertSame(['use_dpop_nonce', 400, null], [$e->error, $e->status, $e->dpopNonce]);
                $e = $timed('n=valid&s=403&b=ask', $key);
                $this->assertSame([403, str_repeat('n', 65536)], [$e->status, $e->dpopNonce]);
                $this->assertCount(2, $requests());
            });
        } finally {
            ini_set('pcre.jit', (string)$jit);
        }
    }

    public function testADpopKeyThatIsNotAnArrayIsAConfigurationError(): void
    {
        foreach ([fn () => CrossAppAccess::requestIdJag(['tokenEndpoint' => 'http://127.0.0.1:9/token', 'clientId' => 'c', 'clientSecret' => 's', 'idToken' => 'i', 'audience' => 'a', 'dpopKey' => 'key']),
                  fn () => CrossAppAccess::redeemIdJag(['tokenEndpoint' => 'http://127.0.0.1:9/token', 'clientId' => 'c', 'assertion' => 'a', 'dpopKey' => 'key'])] as $call) {
            $this->assertSame('the DPoP key must be one from createIdJagDpopKey()', self::configError($call));
        }
    }

    public function testATokenAnswerThatIsNotAJsonObject(): void
    {
        // A JSON string, number or boolean with a status below 400 used to end in a TypeError (postForm's
        // array return type). Any answer that is not a JSON object now counts as an empty one.
        $this->withServer(self::NONCE_ROUTER, function (string $local) {
            foreach (['"ok"', '123', '1.5', 'true', 'false', 'null', '[1,2]', ' [{"access_token":"at"}]', 'not json', ''] as $body) {
                $url = $local . '/not-an-object/token?' . http_build_query(['b' => $body]);
                $e = self::idJagError(fn () => CrossAppAccess::requestIdJag(['tokenEndpoint' => $url, 'clientId' => 'tqapp_test',
                    'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example']));
                $this->assertSame('invalid_response', $e->error, $body);
                $this->assertSame([], CrossAppAccess::redeemIdJag(['tokenEndpoint' => $url, 'clientId' => 'acme-at-rs', 'assertion' => 'jag']), $body);
            }
            $this->assertSame(['access_token' => 'at'], CrossAppAccess::redeemIdJag(['tokenEndpoint' => $local . '/not-an-object/token?b=' . rawurlencode(" \n{\"access_token\":\"at\"}"),
                'clientId' => 'acme-at-rs', 'assertion' => 'jag']));
        });
    }

    private function export(string $value): string
    {
        return var_export($value, true);
    }

    private static function code(callable $fn): string
    {
        try {
            $fn();
            return 'verified';
        } catch (TouchqueAgentCardException $e) {
            return $e->error;
        }
    }

    public function testAgentCards(): void
    {
        $url = self::$api->baseUrl . '/.well-known/agent-card.json';
        $card = file_get_contents($url);
        $this->assertSame(['kid' => 'a2a-1', 'alg' => 'ES256', 'keySource' => 'jku'], AgentCard::verify($card, ['cardUrl' => $url]));
        $this->assertSame('invalid_signature', self::code(fn () => AgentCard::verify(file_get_contents($url . '?tamper=1'), ['cardUrl' => $url])));
        $this->assertSame('untrusted_key', self::code(fn () => AgentCard::verify($card, ['cardUrl' => 'https://agent.example/.well-known/agent-card.json'])));
        $this->assertSame('unsigned', self::code(fn () => AgentCard::verify('{"name":"x"}')));

        $pair = sodium_crypto_sign_keypair();
        $signed = AgentCard::sign('{"name":"Mine","url":"https://mine.example/a2a","skills":[]}', sodium_crypto_sign_secretkey($pair), 'k1');
        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => AgentKeys::b64url(sodium_crypto_sign_publickey($pair)), 'kid' => 'k1'];
        $this->assertSame(['kid' => 'k1', 'alg' => 'EdDSA', 'keySource' => 'keys'], AgentCard::verify($signed, ['keys' => [$jwk]]));
        $this->assertSame('invalid_signature', self::code(fn () => AgentCard::verify(str_replace('mine.example', 'evil.example', $signed), ['keys' => [$jwk]])));

        $value = json_decode('{"€":"Euro","\r":"CR","😀":"smile","1":"one","a":[1e21,1e-7,0.5,-0,"tab\there",1e-5,100.0]}', false);
        $this->assertSame('{"\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\there",0.00001,100],"€":"Euro","😀":"smile"}', AgentCard::canonicalJson($value));
    }
}
