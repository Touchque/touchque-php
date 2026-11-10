<?php

namespace TouchQue;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Exceptions\TouchQueMcpAuthException;

/**
 * For an MCP server whose authorization server is TouchQue SSO (Organization
 * → MCP servers in the dashboard; issuer https://sso.touchque.com/mcp):
 *
 * - protectedResourceMetadata() is its RFC 9728 document, served at the paths
 *   metadataPaths() gives, so MCP clients find TouchQue and ask for a token
 *   for exactly this server;
 * - verify($method, $url, $headers) checks a request's token: signed by
 *   TouchQue (its JWKS), this issuer, audience = this server's URL (RFC 8707),
 *   not expired, and for a DPoP-bound token a fresh proof for this request.
 *   TouchQueMcpAuthException carries the status (401, 403) and the
 *   WWW-Authenticate header to send;
 * - requireTool($claims, $tool) refuses with 403 insufficient_scope naming
 *   the scope a tool needs, so the client asks the member for more.
 *
 *     $auth = new McpAuth(['issuer' => 'https://sso.touchque.com/mcp', 'resource' => 'https://mcp.acme.com/mcp',
 *         'tools' => ['search_tickets' => 'tickets:read', 'delete_ticket' => 'tickets:delete']]);
 *     try {
 *         $claims = $auth->verify($_SERVER['REQUEST_METHOD'], $url, getallheaders());
 *         $auth->requireTool($claims, $toolName);
 *     } catch (TouchQueMcpAuthException $e) {
 *         http_response_code($e->status);
 *         header('WWW-Authenticate: ' . $e->wwwAuthenticate);
 *     }
 *
 * Needs ext-openssl (Ed25519 DPoP proofs: ext-sodium).
 */
class McpAuth
{
    private string $issuer;
    private string $resource;
    private array $tools;
    private ?string $resourceName;
    private int $skew;
    /** @var callable */
    private $fetch;
    private array $keys = [];
    private int $keysAt = 0;
    private int $triedAt = 0;
    private array $proofs = [];

    /**
     * @param array $options issuer (TouchQue SSO's MCP issuer), resource (this server's URL),
     *   tools (tool => scope), resourceName, clockSkew (seconds, 60), fetch (callable(string $url): array, for tests).
     */
    public function __construct(array $options)
    {
        if (empty($options['issuer']) || empty($options['resource'])) {
            throw new TouchQueConfigException("McpAuth needs issuer (TouchQue SSO's MCP issuer) and resource (this server's URL)");
        }
        $this->issuer = rtrim($options['issuer'], '/');
        $this->resource = $options['resource'];
        $this->tools = $options['tools'] ?? [];
        $this->resourceName = $options['resourceName'] ?? null;
        $this->skew = (int)($options['clockSkew'] ?? 60);
        $this->fetch = $options['fetch'] ?? [self::class, 'getJson'];
    }

    /** @return string[] where to serve protectedResourceMetadata() */
    public function metadataPaths(): array
    {
        $path = rtrim((string)(parse_url($this->resource, PHP_URL_PATH) ?? ''), '/');
        return $path === '' ? ['/.well-known/oauth-protected-resource'] : ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource' . $path];
    }

    public function metadataUrl(): string
    {
        $u = parse_url($this->resource);
        $paths = $this->metadataPaths();
        return $u['scheme'] . '://' . $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '') . end($paths);
    }

    public function protectedResourceMetadata(): array
    {
        $doc = [
            'resource' => $this->resource,
            'authorization_servers' => [$this->issuer],
            'bearer_methods_supported' => ['header'],
            'scopes_supported' => array_values(array_unique(array_values($this->tools))),
            'dpop_signing_alg_values_supported' => ['ES256', 'EdDSA'],
        ];
        if ($this->resourceName !== null) {
            $doc['resource_name'] = $this->resourceName;
        }
        return $doc;
    }

    /**
     * A request's token, checked.
     *
     * @param array $headers header name => value (any case)
     * @return array{sub:string,email:?string,clientId:string,scopes:string[],orgId:?string,expiresAt:int,dpopBound:bool,claims:array}
     */
    public function verify(string $method, string $url, array $headers): array
    {
        $lower = array_change_key_case($headers, CASE_LOWER);
        $parts = explode(' ', trim((string)($lower['authorization'] ?? '')), 2);
        $scheme = strtolower($parts[0]);
        $token = trim($parts[1] ?? '');
        if (!in_array($scheme, ['bearer', 'dpop'], true) || substr_count($token, '.') !== 2) {
            throw $this->fail(401, 'missing_token', 'A TouchQue access token is required');
        }
        $claims = $this->claims($token);
        $jkt = $claims['cnf']['jkt'] ?? null;
        if ($jkt) {
            if ($scheme !== 'dpop') {
                throw $this->fail(401, 'invalid_token', 'This token is bound to a DPoP key: send it as DPoP with a proof');
            }
            $this->checkProof($lower['dpop'] ?? null, $method, $url, $token, (string)$jkt);
        }
        return [
            'sub' => (string)($claims['sub'] ?? ''),
            'email' => $claims['email'] ?? null,
            'clientId' => (string)($claims['client_id'] ?? ''),
            'scopes' => array_values(array_filter(explode(' ', (string)($claims['scope'] ?? '')))),
            'orgId' => $claims['org_id'] ?? null,
            'expiresAt' => (int)$claims['exp'],
            'dpopBound' => (bool)$jkt,
            'claims' => $claims,
        ];
    }

    public function requireScope(array $claims, string $scope): void
    {
        if (!in_array($scope, $claims['scopes'] ?? [], true)) {
            throw $this->fail(403, 'insufficient_scope', "This needs the {$scope} scope", $scope);
        }
    }

    public function requireTool(array $claims, string $tool): void
    {
        if (empty($this->tools[$tool])) {
            throw $this->fail(403, 'insufficient_scope', "No scope is set for the tool {$tool}");
        }
        $this->requireScope($claims, $this->tools[$tool]);
    }

    private function fail(int $status, string $code, string $message, ?string $scope = null): TouchQueMcpAuthException
    {
        $parts = ['resource_metadata="' . $this->metadataUrl() . '"'];
        if ($code !== 'missing_token') {
            $parts[] = "error=\"{$code}\"";
            $parts[] = 'error_description="' . str_replace('"', "'", $message) . '"';
            if ($scope !== null) {
                $parts[] = "scope=\"{$scope}\"";
            }
        }
        return new TouchQueMcpAuthException($status, $code, $message, 'Bearer ' . implode(', ', $parts));
    }

    private static function part(string $text): array
    {
        $value = json_decode(AgentKeys::b64urlDecode($text), true);
        if (!is_array($value)) {
            throw new \UnexpectedValueException('malformed');
        }
        return $value;
    }

    private function claims(string $token): array
    {
        [$h, $p, $s] = explode('.', $token);
        try {
            $head = self::part($h);
            $claims = self::part($p);
        } catch (\UnexpectedValueException $e) {
            throw $this->fail(401, 'invalid_token', 'The token is malformed');
        }
        if (($head['typ'] ?? '') !== 'at+jwt' || !in_array($head['alg'] ?? '', ['RS256', 'ES256'], true)) {
            throw $this->fail(401, 'invalid_token', 'Not a TouchQue access token');
        }
        try {
            $key = $this->keyFor((string)($head['kid'] ?? ''));
        } catch (\Throwable $e) {
            throw $this->fail(401, 'invalid_token', "The authorization server's keys could not be read");
        }
        if ($key === null || !self::verifySignature("{$h}.{$p}", AgentKeys::b64urlDecode($s), $head['alg'], $key)) {
            throw $this->fail(401, 'invalid_token', 'The token signature does not verify');
        }
        if (rtrim((string)($claims['iss'] ?? ''), '/') !== $this->issuer) {
            throw $this->fail(401, 'invalid_token', 'The token is from another issuer');
        }
        $aud = $claims['aud'] ?? null;
        if (!in_array($this->resource, is_array($aud) ? $aud : [$aud], true)) {
            throw $this->fail(401, 'invalid_token', 'The token is for another server');
        }
        if (!is_numeric($claims['exp'] ?? null) || $claims['exp'] + $this->skew <= time()) {
            throw $this->fail(401, 'invalid_token', 'The token expired');
        }
        return $claims;
    }

    private function loadKeys(): void
    {
        $u = parse_url($this->issuer);
        $origin = $u['scheme'] . '://' . $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
        $meta = ($this->fetch)($origin . '/.well-known/oauth-authorization-server' . rtrim($u['path'] ?? '', '/'));
        if (rtrim((string)($meta['issuer'] ?? ''), '/') !== $this->issuer || empty($meta['jwks_uri'])) {
            throw new \UnexpectedValueException('the authorization server metadata does not match the issuer');
        }
        $keys = [];
        foreach ((($this->fetch)($meta['jwks_uri'])['keys'] ?? []) as $jwk) {
            if (!empty($jwk['kid'])) {
                $keys[$jwk['kid']] = $jwk;
            }
        }
        $this->keys = $keys;
        $this->keysAt = time();
    }

    private function keyFor(string $kid): ?array
    {
        if (!$this->keysAt || time() - $this->keysAt > 600) {
            $this->loadKeys();
        }
        if (!isset($this->keys[$kid]) && time() - $this->triedAt > 60) {
            $this->triedAt = time();
            $this->loadKeys();
        }
        return $this->keys[$kid] ?? null;
    }

    /** @internal A JWS signature check (RS256, ES256 raw r||s, EdDSA); shared with IdJagVerifier and AgentCard. */
    public static function verifySignature(string $input, string $sig, string $alg, array $jwk): bool
    {
        $kty = $jwk['kty'] ?? '';
        if ($alg === 'RS256' && $kty === 'RSA') {
            return @openssl_verify($input, $sig, self::rsaPem(AgentKeys::b64urlDecode($jwk['n']), AgentKeys::b64urlDecode($jwk['e'])), OPENSSL_ALGO_SHA256) === 1;
        }
        if ($alg === 'ES256' && $kty === 'EC' && ($jwk['crv'] ?? '') === 'P-256') {
            return strlen($sig) === 64 && @openssl_verify($input, AgentKeys::rawToDer($sig), AgentKeys::ecPublicPem(AgentKeys::b64urlDecode($jwk['x']), AgentKeys::b64urlDecode($jwk['y'])), OPENSSL_ALGO_SHA256) === 1;
        }
        if ($alg === 'EdDSA' && $kty === 'OKP' && ($jwk['crv'] ?? '') === 'Ed25519' && function_exists('sodium_crypto_sign_verify_detached')) {
            return strlen($sig) === 64 && sodium_crypto_sign_verify_detached($sig, $input, AgentKeys::b64urlDecode($jwk['x']));
        }
        return false;
    }

    private function checkProof(?string $proof, string $method, string $url, string $token, string $jkt): void
    {
        $reject = function (string $why) {
            return $this->fail(401, 'invalid_dpop_proof', "DPoP proof: {$why}");
        };
        if (!$proof || substr_count($proof, '.') !== 2) {
            throw $reject('missing');
        }
        [$h, $p, $s] = explode('.', $proof);
        try {
            $head = self::part($h);
            $claims = self::part($p);
        } catch (\UnexpectedValueException $e) {
            throw $reject('malformed');
        }
        $jwk = $head['jwk'] ?? [];
        if (($head['typ'] ?? '') !== 'dpop+jwt' || !is_array($jwk) || isset($jwk['d']) || !in_array($jwk['kty'] ?? '', ['EC', 'OKP'], true) || AgentKeys::thumbprint($jwk) !== $jkt) {
            throw $reject('not the bound key');
        }
        if (!self::verifySignature("{$h}.{$p}", AgentKeys::b64urlDecode($s), (string)($head['alg'] ?? ''), $jwk)) {
            throw $reject('signature');
        }
        $u = parse_url($url);
        $htu = $u['scheme'] . '://' . $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '') . ($u['path'] ?? '');
        if (($claims['htm'] ?? '') !== strtoupper($method) || ($claims['htu'] ?? '') !== $htu) {
            throw $reject('htm/htu');
        }
        if (abs((int)($claims['iat'] ?? 0) - time()) > $this->skew) {
            throw $reject('iat');
        }
        if (($claims['ath'] ?? '') !== AgentKeys::b64url(hash('sha256', $token, true))) {
            throw $reject('ath');
        }
        $now = time();
        $this->proofs = array_filter($this->proofs, static fn (int $until): bool => $until >= $now);
        $jti = (string)($claims['jti'] ?? '');
        if ($jti === '' || isset($this->proofs[$jti])) {
            throw $reject('jti used');
        }
        $this->proofs[$jti] = $now + 2 * $this->skew;
    }

    // DER for SubjectPublicKeyInfo { rsaEncryption, RSAPublicKey { n, e } }, as PEM.
    private static function rsaPem(string $n, string $e): string
    {
        $len = static function (int $l): string {
            if ($l < 0x80) {
                return chr($l);
            }
            $b = ltrim(pack('N', $l), "\0");
            return chr(0x80 | strlen($b)) . $b;
        };
        $int = static function (string $bytes) use ($len): string {
            $bytes = ltrim($bytes, "\0");
            if ($bytes === '' || ord($bytes[0]) & 0x80) {
                $bytes = "\0" . $bytes;
            }
            return "\x02" . $len(strlen($bytes)) . $bytes;
        };
        $seq = static fn (string $body): string => "\x30" . $len(strlen($body)) . $body;
        $rsaKey = $seq($int($n) . $int($e));
        $algo = $seq("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
        $der = $seq($algo . "\x03" . $len(strlen($rsaKey) + 1) . "\0" . $rsaKey);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    public static function getJson(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_FOLLOWLOCATION => false, CURLOPT_HTTPHEADER => ['Accept: application/json']]);
        $raw = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($raw === false || $status >= 400) {
            throw new \UnexpectedValueException("{$url} answered {$status}");
        }
        return json_decode((string)$raw, true) ?? [];
    }
}
