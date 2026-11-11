<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueIdJagException;

/**
 * Your authorization server, taking ID-JAGs (Cross App Access) from an
 * organization's identity provider: checks the one an authenticated client
 * presents with the jwt-bearer grant and uses it once.
 *
 *   $v = new IdJagVerifier(['issuer' => 'https://sso.touchque.com', 'audience' => 'https://auth.files.example']);
 *   $claims = $v->verify($_POST['assertion'], $authenticatedClientId);
 *   // $claims['sub'] (the member at that identity provider), 'email', 'scopes', 'resource', 'tenant'
 *
 * Options: issuer, audience, jwksUri?, clockSkew? (60), firstUse? (callable(string $jti, int $exp): bool,
 * a shared store such as Redis SET NX; memory in this process by default). Needs ext-openssl
 * (EdDSA: ext-sodium).
 */
class IdJagVerifier
{
    private string $issuer;
    private string $audience;
    private ?string $jwksUri;
    private int $skew;
    /** @var callable */
    private $firstUse;
    /** @var callable */
    private $fetch;
    private array $keys = [];
    private int $keysAt = 0;
    private int $triedAt = 0;
    private array $seen = [];

    public function __construct(array $options)
    {
        if (empty($options['issuer']) || empty($options['audience'])) {
            throw new TouchqueConfigException("IdJagVerifier needs issuer (the identity provider) and audience (your authorization server's issuer)");
        }
        $this->issuer = $options['issuer'];
        $this->audience = $options['audience'];
        $this->jwksUri = $options['jwksUri'] ?? null;
        $this->skew = (int)($options['clockSkew'] ?? 60);
        $this->firstUse = $options['firstUse'] ?? [$this, 'rememberOnce'];
        $this->fetch = $options['fetch'] ?? [McpAuth::class, 'getJson'];
    }

    /** @internal */
    public function rememberOnce(string $jti, int $exp): bool
    {
        $now = time();
        foreach ($this->seen as $k => $until) {
            if ($until < $now) {
                unset($this->seen[$k]);
            }
        }
        if (isset($this->seen[$jti])) {
            return false;
        }
        $this->seen[$jti] = $exp + $this->skew;
        return true;
    }

    private function loadKeys(): void
    {
        if (!$this->jwksUri) {
            $uri = CrossAppAccess::discover($this->issuer)['jwks_uri'] ?? null;
            if (!is_string($uri)) {
                throw new \UnexpectedValueException('the identity provider names no jwks_uri');
            }
            $this->jwksUri = $uri;
        }
        $keys = [];
        foreach ((($this->fetch)($this->jwksUri)['keys'] ?? []) as $jwk) {
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

    /** The ID-JAG, checked and used once: its claims, or TouchqueIdJagException (error invalid_grant). */
    public function verify(string $assertion, string $clientId): array
    {
        $bad = static fn (string $m) => new TouchqueIdJagException('invalid_grant', $m);
        $parts = explode('.', $assertion);
        if (count($parts) !== 3) {
            throw $bad('assertion is not a JWT');
        }
        $head = json_decode(AgentKeys::b64urlDecode($parts[0]), true);
        $c = json_decode(AgentKeys::b64urlDecode($parts[1]), true);
        if (!is_array($head) || !is_array($c)) {
            throw $bad('assertion is not a JWT');
        }
        if (($head['typ'] ?? null) !== 'oauth-id-jag+jwt') {
            throw $bad('not an ID-JAG (typ oauth-id-jag+jwt)');
        }
        $alg = $head['alg'] ?? '';
        if (!in_array($alg, ['RS256', 'ES256', 'EdDSA'], true) || !is_string($head['kid'] ?? null)) {
            throw $bad('unsupported signature');
        }
        try {
            $jwk = $this->keyFor($head['kid']);
        } catch (\Throwable $e) {
            throw new TouchqueIdJagException('temporarily_unavailable', "the identity provider's keys could not be read: " . $e->getMessage());
        }
        if ($jwk === null || !McpAuth::verifySignature($parts[0] . '.' . $parts[1], AgentKeys::b64urlDecode($parts[2]), $alg, $jwk)) {
            throw $bad('signature does not verify');
        }
        $now = time();
        $auds = is_array($c['aud'] ?? null) ? $c['aud'] : [$c['aud'] ?? null];
        if (($c['iss'] ?? null) !== $this->issuer) {
            throw $bad('another issuer');
        }
        if (count($auds) !== 1 || $auds[0] !== $this->audience) {
            throw $bad('not for this authorization server');
        }
        if (!is_string($c['client_id'] ?? null) || $c['client_id'] !== $clientId) {
            throw $bad('issued to another client');
        }
        if (!is_numeric($c['exp'] ?? null) || $c['exp'] + $this->skew < $now) {
            throw $bad('expired');
        }
        if (!is_numeric($c['iat'] ?? null) || $c['iat'] - $this->skew > $now) {
            throw $bad('issued in the future');
        }
        if (!is_string($c['sub'] ?? null) || !is_string($c['jti'] ?? null)) {
            throw $bad('sub and jti are required');
        }
        if (!($this->firstUse)($c['jti'], (int)$c['exp'])) {
            throw $bad('already used');
        }
        return [
            'iss' => $c['iss'], 'sub' => $c['sub'], 'aud' => $auds[0], 'clientId' => $c['client_id'], 'jti' => $c['jti'],
            'issuedAt' => (int)$c['iat'], 'expiresAt' => (int)$c['exp'],
            'scopes' => is_string($c['scope'] ?? null) && $c['scope'] !== '' ? explode(' ', $c['scope']) : [],
            'resource' => $c['resource'] ?? null, 'tenant' => $c['tenant'] ?? null, 'email' => $c['email'] ?? null,
            'authTime' => $c['auth_time'] ?? null, 'amr' => $c['amr'] ?? null, 'claims' => $c,
        ];
    }
}
