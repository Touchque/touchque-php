<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueFeatureException;
use Touchque\Exceptions\TouchqueApprovalException;
use Touchque\Exceptions\TouchqueTimeoutException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueNetworkException;

/**
 * The agent side: an AI agent calls Touchque with its OWN key, never with
 * your API key. It signs a private_key_jwt assertion (RFC 7523) for a
 * 10-minute token bound to its key with DPoP (RFC 9449), and proves the key
 * on every call, so a stolen token is useless on its own.
 *
 *     $agent = new TouchqueAgent();      // TQ_AGENT_ID, TQ_AGENT_KEY (a JWK as JSON, or an EC PEM)
 *     $me = $agent->me();
 *
 * ES256 keys use ext-openssl, Ed25519 keys ext-sodium.
 */
class TouchqueAgent
{
    public const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    private string $agentId;
    private string $alg;
    /** @var resource|\OpenSSLAsymmetricKey|string openssl key (ES256) or sodium secret key (EdDSA) */
    private $key;
    private array $publicJwk;
    private string $kid;
    private string $baseUrl;
    private ?string $scope;
    private int $timeoutMs;
    private ?array $token = null;

    /**
     * @param array|string|null $privateKey JWK (array or JSON) or an EC PEM. Default: TQ_AGENT_KEY.
     * @param string|null $kid The kid it was registered with. Default: the JWK's kid, else its RFC 7638 thumbprint.
     */
    public function __construct(?string $agentId = null, $privateKey = null, ?string $kid = null, ?string $baseUrl = null, ?string $scope = null, int $timeoutMs = 10000)
    {
        $agentId = $agentId ?? (getenv('TQ_AGENT_ID') ?: '');
        if (!preg_match('/^agt_[a-z2-9]{20}$/', $agentId)) {
            throw new TouchqueConfigException('Set TQ_AGENT_ID (or pass $agentId): the agt_... id from $tq->agents->create()');
        }
        $privateKey = $privateKey ?? (getenv('TQ_AGENT_KEY') ?: null);
        if (!$privateKey) {
            throw new TouchqueConfigException("Set TQ_AGENT_KEY (or pass \$privateKey): the agent's private key");
        }
        $this->agentId = $agentId;
        $jwk = is_array($privateKey) ? $privateKey : (is_string($privateKey) && ltrim($privateKey)[0] === '{' ? json_decode($privateKey, true) : null);
        if (is_array($jwk)) {
            $this->loadJwk($jwk);
        } elseif (is_string($privateKey)) {
            $this->loadPem($privateKey);
        } else {
            throw new TouchqueConfigException("privateKey must be the agent's private key: a JWK (array or JSON) or an EC PEM");
        }
        $this->kid = $kid ?? (is_array($jwk) && isset($jwk['kid']) ? (string)$jwk['kid'] : AgentKeys::thumbprint($this->publicJwk));
        $this->baseUrl = rtrim($baseUrl ?? (getenv('TQ_API_URL') ?: 'https://api.touchque.com'), '/');
        $parts = parse_url($this->baseUrl);
        $host = $parts['host'] ?? '';
        $local = in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true);
        if (($parts['scheme'] ?? '') !== 'https' && !(($parts['scheme'] ?? '') === 'http' && $local)) {
            throw new TouchqueConfigException("Refusing a plaintext baseUrl for \"{$host}\": use https://");
        }
        $this->scope = $scope;
        $this->timeoutMs = $timeoutMs;
    }

    public function getAgentId(): string
    {
        return $this->agentId;
    }

    private function loadJwk(array $jwk): void
    {
        if (!isset($jwk['d'])) {
            throw new TouchqueConfigException("privateKey must be the agent's PRIVATE key (it has no d)");
        }
        $d = AgentKeys::b64urlDecode($jwk['d']);
        if (($jwk['kty'] ?? '') === 'OKP' && ($jwk['crv'] ?? '') === 'Ed25519' && strlen($d) === 32) {
            $pair = sodium_crypto_sign_seed_keypair($d);
            $this->alg = 'EdDSA';
            $this->key = sodium_crypto_sign_secretkey($pair);
            $this->publicJwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => AgentKeys::b64url(sodium_crypto_sign_publickey($pair))];
            return;
        }
        if (($jwk['kty'] ?? '') === 'EC' && ($jwk['crv'] ?? '') === 'P-256' && isset($jwk['x'], $jwk['y'])) {
            $this->loadPem(AgentKeys::ecPem($d, AgentKeys::b64urlDecode($jwk['x']), AgentKeys::b64urlDecode($jwk['y'])));
            return;
        }
        throw new TouchqueConfigException('The agent key must be EC P-256 or Ed25519');
    }

    private function loadPem(string $pem): void
    {
        $key = @openssl_pkey_get_private($pem);
        $details = $key ? openssl_pkey_get_details($key) : false;
        if (!$details || !isset($details['ec'])) {
            throw new TouchqueConfigException("privateKey must be the agent's private key: a JWK (array or JSON) or an EC PEM");
        }
        if (($details['ec']['curve_name'] ?? '') !== 'prime256v1') {
            throw new TouchqueConfigException('An EC agent key must be on P-256');
        }
        $this->alg = 'ES256';
        $this->key = $key;
        $this->publicJwk = [
            'kty' => 'EC', 'crv' => 'P-256',
            'x' => AgentKeys::b64url(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => AgentKeys::b64url(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
        ];
    }

    private function sign(array $header, array $payload): string
    {
        $header['alg'] = $this->alg;
        $input = AgentKeys::b64url(json_encode($header, JSON_UNESCAPED_SLASHES)) . '.' . AgentKeys::b64url(json_encode($payload, JSON_UNESCAPED_SLASHES));
        if ($this->alg === 'EdDSA') {
            $sig = sodium_crypto_sign_detached($input, $this->key);
        } else {
            if (!openssl_sign($input, $der, $this->key, OPENSSL_ALGO_SHA256)) {
                throw new TouchqueConfigException('Could not sign with the agent key');
            }
            $sig = AgentKeys::derToRaw($der);
        }
        return $input . '.' . AgentKeys::b64url($sig);
    }

    private function dpop(string $method, string $url, ?string $accessToken = null): string
    {
        $claims = ['htm' => $method, 'htu' => $url, 'iat' => time(), 'jti' => bin2hex(random_bytes(16))];
        if ($accessToken !== null) {
            $claims['ath'] = AgentKeys::b64url(hash('sha256', $accessToken, true));
        }
        return $this->sign(['typ' => 'dpop+jwt', 'jwk' => $this->publicJwk], $claims);
    }

    /** @return array{0:int,1:array} */
    private function http(string $method, string $url, array $headers, ?string $body): array
    {
        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT_MS => $this->timeoutMs,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CUSTOMREQUEST => $method,
        ];
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        $error = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (\PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
        if ($error || $raw === false) {
            throw new TouchqueNetworkException('Network error: ' . $error);
        }
        return [$status, json_decode((string)$raw, true) ?? []];
    }

    private static function failure(int $status, array $data): TouchqueAPIException
    {
        $data['code'] = $data['code'] ?? ($data['error'] ?? null);
        if (isset($data['retry_after']) && !isset($data['retryAfter'])) {
            $data['retryAfter'] = (int)$data['retry_after'];
        }
        return TouchqueFeatureException::fromResponse($data['error_description'] ?? ($data['error'] ?? 'Unknown API Error'), $status, $data);
    }

    private function fetchToken(): string
    {
        $url = $this->baseUrl . '/agents/token';
        $now = time();
        $assertion = $this->sign(['typ' => 'JWT', 'kid' => $this->kid], [
            'iss' => $this->agentId, 'sub' => $this->agentId, 'aud' => $url, 'iat' => $now, 'exp' => $now + 60, 'jti' => bin2hex(random_bytes(16)),
        ]);
        $form = ['grant_type' => 'client_credentials', 'client_assertion_type' => self::ASSERTION_TYPE, 'client_assertion' => $assertion];
        if ($this->scope) {
            $form['scope'] = $this->scope;
        }
        [$status, $data] = $this->http('POST', $url, ['Content-Type: application/x-www-form-urlencoded', 'DPoP: ' . $this->dpop('POST', $url)], http_build_query($form));
        if ($status !== 200) {
            throw self::failure($status, $data);
        }
        $this->token = ['value' => $data['access_token'], 'expiresAt' => time() + (int)($data['expires_in'] ?? 600)];
        return $this->token['value'];
    }

    /** The agent's current token (renewed a minute before it expires). */
    public function accessToken(): string
    {
        if ($this->token && $this->token['expiresAt'] - time() > 60) {
            return $this->token['value'];
        }
        return $this->fetchToken();
    }

    /** A call with the agent's token and a fresh DPoP proof; one retry with a new token when Touchque no longer knows it. */
    protected function request(string $method, string $path, ?array $body = null, bool $retried = false): array
    {
        $token = $this->accessToken();
        $url = $this->baseUrl . $path;
        $headers = ['Authorization: DPoP ' . $token, 'DPoP: ' . $this->dpop($method, explode('?', $url)[0], $token)];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        [$status, $data] = $this->http($method, $url, $headers, $body !== null ? json_encode($body === [] ? new \stdClass() : $body) : null);
        if ($status === 401 && !$retried && ($data['code'] ?? null) === 'invalid_token') {
            $this->token = null;
            return $this->request($method, $path, $body, true);
        }
        if ($status < 200 || $status >= 300) {
            throw self::failure($status, $data);
        }
        return $data;
    }

    /** The agent as Touchque sees it: its action types, owner, review date and workspace. */
    public function me(): array
    {
        return $this->request('GET', '/agents/me');
    }

    /**
     * Asks the person to approve on their Touchque phone. Show `challengeCode`
     * in your conversation (presence interactive, the default): the person
     * types it on the phone. Touchque draws the phone's rows from
     * $authorizationDetails. $options: reason, presence, expiresIn, locale,
     * referenceId, clientIp, userAgent.
     */
    public function requestApproval(string $user, string $type, array $authorizationDetails, array $options = []): array
    {
        $body = ['externalUsername' => $user, 'type' => $type, 'authorizationDetails' => $authorizationDetails];
        foreach (['reason', 'presence', 'expiresIn', 'locale', 'referenceId', 'clientIp', 'userAgent', 'mandateId'] as $key) {
            if (isset($options[$key])) {
                $body[$key] = $options[$key];
            }
        }
        return $this->request('POST', '/agents/approvals', $body);
    }

    /**
     * Asks the person for a mandate: one approval on the phone for a bounded
     * series of requests. $maxTotal: ['currency' => 'TRY', 'amount' => '1000'];
     * $options: perRequest, recipients, validFor, reason, expiresIn, locale.
     * Once active, pass ['mandateId' => …] to requestApproval: no push.
     */
    public function requestMandate(string $user, string $type, int $maxCount, array $maxTotal, array $options = []): array
    {
        $body = ['externalUsername' => $user, 'type' => $type, 'maxCount' => $maxCount, 'maxTotal' => $maxTotal];
        foreach (['perRequest', 'recipients', 'validFor', 'reason', 'expiresIn', 'locale'] as $key) {
            if (isset($options[$key])) {
                $body[$key] = $options[$key];
            }
        }
        return $this->request('POST', '/agents/mandates', $body);
    }

    /**
     * The token vault: a person's own access token at another service, for a connection that names this agent
     * ($tq->agents->vault): `['access_token', 'token_type' => 'Bearer', 'expires_in'?, 'scope', 'connection']`.
     * Touchque refreshes it; the refresh token never leaves. TouchqueAPIException not_connected when nothing is kept.
     */
    public function getConnectionToken(string $user, string $connection, ?string $scope = null): array
    {
        $body = ['externalUsername' => $user, 'connection' => $connection];
        if ($scope) {
            $body['scope'] = $scope;
        }
        return $this->request('POST', '/agents/vault/token', $body);
    }

    /** A mandate's state and what is left. */
    public function getMandate(string $mandateId): array
    {
        return $this->request('GET', '/agents/mandates/' . rawurlencode($mandateId));
    }

    /** Gives up a mandate. */
    public function revokeMandate(string $mandateId): array
    {
        return $this->request('POST', '/agents/mandates/' . rawurlencode($mandateId) . '/revoke', []);
    }

    /** Where an approval request is; `approvalToken` once approved. */
    public function getApproval(string $approvalId): array
    {
        return $this->request('GET', '/agents/approvals/' . rawurlencode($approvalId));
    }

    /**
     * Polls until the person approves (returns the state holding
     * `approvalToken`). Throws TouchqueApprovalException when it ends
     * otherwise and TouchqueTimeoutException after $timeoutSeconds. An approval
     * given during a phone call stays provisional until the phone confirms it.
     */
    /**
     * Asks the person's phone and waits for the answer: the approved state (holding
     * approvalToken), or TouchqueApprovalException / a timeout. $onChallenge (may be null)
     * gets the state while the phone waits: show its challengeCode in the conversation.
     * Put it in front of any tool call an agent framework makes so the call runs only after
     * the person approved.
     */
    public function requireApproval(string $user, string $type, array $authorizationDetails, array $options = [], ?callable $onChallenge = null, int $timeoutSeconds = 300): array
    {
        $asked = $this->requestApproval($user, $type, $authorizationDetails, $options);
        if (($asked['status'] ?? null) === 'approved' && !empty($asked['approvalToken'])) {
            return $asked;
        }
        if (!empty($asked['challengeCode']) && $onChallenge) {
            $onChallenge($asked);
        }
        return $this->waitForApproval($asked['approvalId'], $timeoutSeconds);
    }

    public function waitForApproval(string $approvalId, int $timeoutSeconds = 600, float $intervalSeconds = 2.0): array
    {
        $interval = max(0.5, $intervalSeconds);
        $end = microtime(true) + $timeoutSeconds;
        while (true) {
            $state = $this->getApproval($approvalId);
            if (($state['status'] ?? '') === 'approved' && !empty($state['approvalToken'])) {
                return $state;
            }
            if (in_array($state['status'] ?? '', ['rejected', 'blocked', 'revoked', 'expired', 'stale', 'redeemed'], true)) {
                throw new TouchqueApprovalException($approvalId, $state['status'], $state['reason'] ?? null);
            }
            if (microtime(true) + $interval > $end) {
                throw new TouchqueTimeoutException("Touchque: approval '{$approvalId}' was not approved within {$timeoutSeconds}s");
            }
            usleep((int)($interval * 1000000));
        }
    }
}
