<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueFeatureException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueNetworkException;
use Touchque\Exceptions\TouchqueTimeoutException;

/**
 * An organization's AI agent on Touchque SSO (Organization → AI agents in the
 * dashboard): it gets 5-minute tokens for one of the organization's apps,
 * proving who it is with its own key (private_key_jwt) or with the token its
 * platform already gives it (GitHub Actions, GitLab, Google Cloud, Azure,
 * Kubernetes), and binds each token to a DPoP key made when it starts. The app
 * checks the token with Touchque's JWKS and the DPoP proof on every call.
 *
 *     $agent = new TouchqueOrgAgent(['agentId' => 'oagt_...', 'privateKey' => getenv('TQ_ORG_AGENT_KEY')]);
 *     $headers = $agent->authorization('GET', 'https://payments.acme.com/invoices', ['resource' => 'tqapp_...']);
 *
 *     // In a GitHub Actions job (permissions: id-token: write), with no key to store:
 *     $agent = new TouchqueOrgAgent(['agentId' => 'oagt_...', 'assertion' => TouchqueOrgAgent::githubActionsToken('touchque')]);
 *
 * Acting for a member, when its admin allowed it (Organization → AI agents → Access):
 *
 *     $token = $agent->exchangeToken($membersAccessToken, ['resource' => 'tqapp_...']);   // RFC 8693
 *     $ask = $agent->askMember('ada@acme.com', ['bindingMessage' => 'Pay invoice 42', 'authorizationDetails' => [$payment]]);
 *     // show $ask['bindingCode'] in the conversation
 *     $approved = $agent->waitForMember($ask);                                          // CIBA, poll mode
 *     $google = $agent->getConnectionToken($membersAccessToken, 'google');                // token vault
 *     $ask = $agent->askToOpenSharedAccount('k3J...', 'ada@acme.com', 'Post the launch photo'); // the member's extension signs in
 *     $result = $agent->waitForSharedAccount($ask);                                       // opened | refused | declined | expired
 *
 * ES256 keys use ext-openssl, Ed25519 keys ext-sodium.
 */
class TouchqueOrgAgent
{
    private string $agentId;
    private string $issuer;
    /** @var callable|null */
    private $assertionSource;
    private ?string $keyAlg = null;
    /** @var \OpenSSLAsymmetricKey|resource|string|null */
    private $key = null;
    private ?string $kid = null;
    /** @var \OpenSSLAsymmetricKey|resource */
    private $dpopKey;
    private array $dpopJwk;
    private ?string $resource;
    private ?string $scope;
    private int $timeoutMs;
    private array $tokens = [];

    /**
     * @param array $options agentId (TQ_ORG_AGENT_ID), issuer (TQ_SSO_URL, https://sso.touchque.com),
     *   privateKey (JWK array/JSON or EC PEM; TQ_ORG_AGENT_KEY) and kid, or assertion (a callable
     *   returning the platform's token), resource, scope, timeoutMs.
     */
    public function __construct(array $options = [])
    {
        $agentId = $options['agentId'] ?? (getenv('TQ_ORG_AGENT_ID') ?: '');
        if (!preg_match('/^oagt_[a-z2-9]{20}$/', $agentId)) {
            throw new TouchqueConfigException('Set TQ_ORG_AGENT_ID (or pass agentId): the oagt_... id from Organization → AI agents');
        }
        $this->agentId = $agentId;
        $this->issuer = rtrim($options['issuer'] ?? (getenv('TQ_SSO_URL') ?: 'https://sso.touchque.com'), '/');
        $parts = parse_url($this->issuer);
        $host = $parts['host'] ?? '';
        $local = in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true);
        if (($parts['scheme'] ?? '') !== 'https' && !(($parts['scheme'] ?? '') === 'http' && $local)) {
            throw new TouchqueConfigException("Refusing a plaintext issuer for \"{$host}\": use https://");
        }
        if (isset($options['assertion'])) {
            if (!is_callable($options['assertion'])) {
                throw new TouchqueConfigException("assertion must be a callable returning the platform's token");
            }
            $this->assertionSource = $options['assertion'];
        } else {
            $privateKey = $options['privateKey'] ?? (getenv('TQ_ORG_AGENT_KEY') ?: null);
            if (!$privateKey) {
                throw new TouchqueConfigException("Pass privateKey (or set TQ_ORG_AGENT_KEY), or assertion with the platform's token");
            }
            $this->loadKey($privateKey, $options['kid'] ?? null);
        }
        // The DPoP key: made here, never leaves this process.
        $dpop = AgentKeys::generate('ES256')['privateJwk'];
        $this->dpopKey = openssl_pkey_get_private(AgentKeys::ecPem(AgentKeys::b64urlDecode($dpop['d']), AgentKeys::b64urlDecode($dpop['x']), AgentKeys::b64urlDecode($dpop['y'])));
        $this->dpopJwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $dpop['x'], 'y' => $dpop['y']];
        $this->resource = $options['resource'] ?? null;
        $this->scope = $options['scope'] ?? null;
        $this->timeoutMs = (int)($options['timeoutMs'] ?? 10000);
    }

    /** The token a GitHub Actions job may ask for (the job needs `permissions: id-token: write`). */
    public static function githubActionsToken(string $audience = 'touchque'): callable
    {
        return static function () use ($audience): string {
            $url = getenv('ACTIONS_ID_TOKEN_REQUEST_URL');
            $bearer = getenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN');
            if (!$url || !$bearer) {
                throw new TouchqueConfigException('Not in a GitHub Actions job with `permissions: id-token: write`');
            }
            $ch = curl_init($url . (strpos($url, '?') === false ? '?' : '&') . 'audience=' . rawurlencode($audience));
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $bearer], CURLOPT_TIMEOUT_MS => 10000]);
            $data = json_decode((string)curl_exec($ch), true);
            if (!is_array($data) || empty($data['value'])) {
                throw new TouchqueConfigException('GitHub gave no token');
            }
            return $data['value'];
        };
    }

    /** A token the platform writes to a file and renews (a Kubernetes projected service account token...). */
    public static function fileToken(string $path): callable
    {
        return static fn (): string => trim((string)file_get_contents($path));
    }

    public function getAgentId(): string
    {
        return $this->agentId;
    }

    private function loadKey($privateKey, ?string $kid): void
    {
        $jwk = is_array($privateKey) ? $privateKey : (is_string($privateKey) && ltrim($privateKey)[0] === '{' ? json_decode($privateKey, true) : null);
        if (is_array($jwk) && isset($jwk['d'])) {
            $d = AgentKeys::b64urlDecode($jwk['d']);
            if (($jwk['kty'] ?? '') === 'OKP' && ($jwk['crv'] ?? '') === 'Ed25519' && strlen($d) === 32) {
                $pair = sodium_crypto_sign_seed_keypair($d);
                $this->keyAlg = 'EdDSA';
                $this->key = sodium_crypto_sign_secretkey($pair);
                $public = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => AgentKeys::b64url(sodium_crypto_sign_publickey($pair))];
            } elseif (($jwk['kty'] ?? '') === 'EC' && ($jwk['crv'] ?? '') === 'P-256' && isset($jwk['x'], $jwk['y'])) {
                $this->keyAlg = 'ES256';
                $this->key = openssl_pkey_get_private(AgentKeys::ecPem($d, AgentKeys::b64urlDecode($jwk['x']), AgentKeys::b64urlDecode($jwk['y'])));
                $public = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $jwk['x'], 'y' => $jwk['y']];
            } else {
                throw new TouchqueConfigException('The agent key must be EC P-256 or Ed25519');
            }
            $this->kid = $kid ?? (isset($jwk['kid']) ? (string)$jwk['kid'] : AgentKeys::thumbprint($public));
            return;
        }
        $key = is_string($privateKey) ? @openssl_pkey_get_private($privateKey) : false;
        $details = $key ? openssl_pkey_get_details($key) : false;
        if (!$details || ($details['ec']['curve_name'] ?? '') !== 'prime256v1') {
            throw new TouchqueConfigException("privateKey must be the agent's private key: a JWK (array or JSON) or an EC P-256 PEM");
        }
        $this->keyAlg = 'ES256';
        $this->key = $key;
        $pad = static fn (string $b): string => str_pad($b, 32, "\0", STR_PAD_LEFT);
        $this->kid = $kid ?? AgentKeys::thumbprint(['kty' => 'EC', 'crv' => 'P-256', 'x' => AgentKeys::b64url($pad($details['ec']['x'])), 'y' => AgentKeys::b64url($pad($details['ec']['y']))]);
    }

    private static function jws(string $alg, $key, array $header, array $payload): string
    {
        $header['alg'] = $alg;
        $input = AgentKeys::b64url(json_encode($header, JSON_UNESCAPED_SLASHES)) . '.' . AgentKeys::b64url(json_encode($payload, JSON_UNESCAPED_SLASHES));
        if ($alg === 'EdDSA') {
            $sig = sodium_crypto_sign_detached($input, $key);
        } else {
            if (!openssl_sign($input, $der, $key, OPENSSL_ALGO_SHA256)) {
                throw new TouchqueConfigException('Could not sign with the key');
            }
            $sig = AgentKeys::derToRaw($der);
        }
        return $input . '.' . AgentKeys::b64url($sig);
    }

    /** A DPoP proof (RFC 9449) for one request: with the token, for a call to the app. */
    public function dpopProof(string $method, string $url, ?string $accessToken = null): string
    {
        $u = parse_url($url);
        $htu = ($u['scheme'] ?? 'https') . '://' . ($u['host'] ?? '') . (isset($u['port']) ? ':' . $u['port'] : '') . ($u['path'] ?? '');
        $claims = ['htm' => strtoupper($method), 'htu' => $htu, 'iat' => time(), 'jti' => bin2hex(random_bytes(16))];
        if ($accessToken !== null) {
            $claims['ath'] = AgentKeys::b64url(hash('sha256', $accessToken, true));
        }
        return self::jws('ES256', $this->dpopKey, ['typ' => 'dpop+jwt', 'jwk' => $this->dpopJwk], $claims);
    }

    private function assertion(string $tokenUrl): string
    {
        if ($this->assertionSource !== null) {
            return (string)($this->assertionSource)();
        }
        $now = time();
        return self::jws($this->keyAlg, $this->key, ['typ' => 'JWT', 'kid' => $this->kid], [
            'iss' => $this->agentId, 'sub' => $this->agentId, 'aud' => $tokenUrl, 'iat' => $now, 'exp' => $now + 60, 'jti' => bin2hex(random_bytes(16)),
        ]);
    }

    /** POSTs to the SSO with the agent's client assertion (and, at /sso/token, a DPoP proof). */
    private function post(string $path, array $fields, bool $dpop): array
    {
        $url = $this->issuer . $path;
        $form = ['client_id' => $this->agentId, 'client_assertion_type' => TouchqueAgent::ASSERTION_TYPE, 'client_assertion' => $this->assertion($this->issuer . '/sso/token')];
        foreach ($fields as $k => $v) {
            if ($v !== null && $v !== '') {
                $form[$k] = $v;
            }
        }
        $headers = ['Content-Type: application/x-www-form-urlencoded'];
        if ($dpop) {
            $headers[] = 'DPoP: ' . $this->dpopProof('POST', $url);
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($form), CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => $this->timeoutMs, CURLOPT_HTTPHEADER => $headers,
        ]);
        $raw = curl_exec($ch);
        $error = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($error || $raw === false) {
            throw new TouchqueNetworkException('Network error: ' . $error);
        }
        $data = json_decode((string)$raw, true) ?? [];
        if ($status !== 200) {
            $data['code'] = $data['error'] ?? null;
            throw TouchqueFeatureException::fromResponse($data['error_description'] ?? ($data['error'] ?? 'Unknown API Error'), $status, $data);
        }
        return $data;
    }

    private static function tokenOf(array $data): array
    {
        $token = ['accessToken' => $data['access_token'], 'tokenType' => 'DPoP', 'expiresIn' => (int)($data['expires_in'] ?? 300), 'scope' => $data['scope'] ?? ''];
        if (isset($data['authorization_details']) && is_array($data['authorization_details'])) {
            $token['authorizationDetails'] = $data['authorization_details'];
        }
        return $token;
    }

    /**
     * A token for one app (renewed 30 seconds before it expires):
     * `['accessToken', 'tokenType' => 'DPoP', 'expiresIn', 'scope']`. $options: resource, scope.
     */
    public function getToken(array $options = []): array
    {
        $resource = $options['resource'] ?? $this->resource;
        $scope = $options['scope'] ?? $this->scope;
        $cacheKey = ($resource ?? '') . ' ' . ($scope ?? '');
        if (isset($this->tokens[$cacheKey]) && $this->tokens[$cacheKey]['expiresAt'] - time() > 30) {
            return $this->tokens[$cacheKey]['token'];
        }
        $token = self::tokenOf($this->post('/sso/token', ['grant_type' => 'client_credentials', 'resource' => $resource, 'scope' => $scope], true));
        $this->tokens[$cacheKey] = ['token' => $token, 'expiresAt' => time() + $token['expiresIn']];
        return $token;
    }

    /** A token for a member, with their own access token for one of the agent's apps (RFC 8693): sub is the member, act the agent. */
    public function exchangeToken(string $subjectToken, array $options = []): array
    {
        return self::tokenOf($this->post('/sso/token', [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token' => $subjectToken,
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'resource' => $options['resource'] ?? $this->resource, 'scope' => $options['scope'] ?? $this->scope,
        ], true));
    }

    /**
     * The token vault: a member's own access token at another service (Google, Microsoft 365, GitHub…)
     * they connected on Touchque, for a connection that names this agent:
     * `['accessToken', 'tokenType' => 'Bearer', 'expiresIn' (null when the service does not say), 'scope', 'connection']`.
     * $subjectToken is the member's token, as for exchangeToken; $scope may only narrow what the member granted.
     * Touchque refreshes it; the refresh token never leaves. TouchqueAPIException invalid_grant: the member
     * has not connected it (or disconnected, or left).
     */
    public function getConnectionToken(string $subjectToken, string $connection, ?string $scope = null): array
    {
        $data = $this->post('/sso/token', [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token' => $subjectToken,
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type' => 'urn:touchque:params:oauth:token-type:connection-access-token', 'connection' => $connection, 'scope' => $scope,
        ], true);
        return [
            'accessToken' => (string) $data['access_token'], 'tokenType' => 'Bearer',
            'expiresIn' => isset($data['expires_in']) ? (int) $data['expires_in'] : null,
            'scope' => (string) ($data['scope'] ?? ''), 'connection' => (string) ($data['connection'] ?? $connection),
        ];
    }

    /**
     * Asks to open a shared account (its key, from Organization → AI agents → Access) for a member:
     * `['askId', 'openUrl', 'status', 'expiresIn']`. The member opens openUrl in the browser where their
     * Touchque extension is paired; their phone approves with this agent named and the extension signs
     * in there. The agent never sees the password. $message (at most 64 characters) is shown marked unverified.
     */
    public function askToOpenSharedAccount(string $account, string $loginHint, ?string $message = null): array
    {
        $data = $this->post('/sso/agents/shared-accounts/asks', ['account' => $account, 'login_hint' => $loginHint, 'binding_message' => $message], false);
        return ['askId' => (string) $data['ask_id'], 'openUrl' => (string) $data['open_url'], 'status' => (string) $data['status'], 'expiresIn' => (int) ($data['expires_in'] ?? 600)];
    }

    /** Where an ask stands: `['status', 'reason' => ?string, 'caseCode' => ?string]`; never anything of the account. */
    public function sharedAccountAskStatus(string $askId): array
    {
        $data = $this->post('/sso/agents/shared-accounts/asks/' . rawurlencode($askId), [], false);
        return ['status' => (string) $data['status'], 'reason' => $data['reason'] ?? null, 'caseCode' => $data['case_code'] ?? null];
    }

    /** Polls an ask until it ends: opened, refused, declined or expired (every $intervalMs). */
    public function waitForSharedAccount(array $ask, int $intervalMs = 3000): array
    {
        $deadline = time() + ($ask['expiresIn'] ?? 600) + 5;
        while (true) {
            $s = $this->sharedAccountAskStatus($ask['askId']);
            if (!in_array($s['status'], ['waiting_member', 'asked_phone'], true) || time() > $deadline) {
                return $s;
            }
            usleep($intervalMs * 1000);
        }
    }

    /**
     * Asks a member to approve on their phone (CIBA): `['authReqId', 'expiresIn', 'interval', 'bindingCode']`.
     * $options: bindingMessage, authorizationDetails, resource, scope, requestedExpiry.
     */
    public function askMember(string $loginHint, array $options = []): array
    {
        $data = $this->post('/sso/bc-authorize', [
            'login_hint' => $loginHint, 'binding_message' => $options['bindingMessage'] ?? null,
            'resource' => $options['resource'] ?? $this->resource, 'scope' => $options['scope'] ?? $this->scope,
            'authorization_details' => isset($options['authorizationDetails']) ? json_encode($options['authorizationDetails'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null,
            'requested_expiry' => isset($options['requestedExpiry']) ? (string)$options['requestedExpiry'] : null,
        ], false);
        return ['authReqId' => $data['auth_req_id'], 'expiresIn' => (int)($data['expires_in'] ?? 300), 'interval' => (int)($data['interval'] ?? 5)]
            + (isset($data['binding_code']) ? ['bindingCode' => $data['binding_code']] : []);
    }

    /**
     * The member's answer (polling at the interval, slower when asked): the token once they approve;
     * TouchqueAPIException access_denied or expired_token otherwise, TouchqueTimeoutException after it expired.
     */
    public function waitForMember(array $request): array
    {
        $interval = max(1, (int)$request['interval']);
        $deadline = time() + (int)$request['expiresIn'] + 5;
        while (time() < $deadline) {
            sleep($interval);
            try {
                return self::tokenOf($this->post('/sso/token', ['grant_type' => 'urn:openid:params:grant-type:ciba', 'auth_req_id' => $request['authReqId']], true));
            } catch (TouchqueAPIException $e) {
                if ($e->getErrorCode() === 'authorization_pending') {
                    continue;
                }
                if ($e->getErrorCode() === 'slow_down') {
                    $interval += 5;
                    continue;
                }
                throw $e;
            }
        }
        throw new TouchqueTimeoutException('The member did not answer in time');
    }

    /** The two headers for one call to the app: `['Authorization' => 'DPoP …', 'DPoP' => proof]`. */
    public function authorization(string $method, string $url, array $options = []): array
    {
        $token = $this->getToken($options)['accessToken'];
        return ['Authorization' => 'DPoP ' . $token, 'DPoP' => $this->dpopProof($method, $url, $token)];
    }
}
