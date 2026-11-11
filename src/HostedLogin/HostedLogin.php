<?php

namespace Touchque\HostedLogin;

/**
 * Touchque Login (hosted sign-in) for your app: an OpenID Connect client for
 * your tenant (acme.login.touchque.com or your own domain).
 *
 *   $login = new HostedLogin(['domain' => 'acme.login.touchque.com', 'clientId' => ..., 'clientSecret' => ..., 'redirectUri' => ...]);
 *   $req = $login->authorizationUrl();   // keep $req['state'], $req['nonce'], $req['codeVerifier'] in the session; redirect to $req['url']
 *   $tokens = $login->handleCallback($_GET, $req['state'], $req['nonce'], $req['codeVerifier']);
 *   $tokens['claims']['sub'], $tokens['accessToken'], $tokens['refreshToken']
 *
 * PKCE (S256) is always used. ID tokens are checked against the tenant's JWKS
 * (RS256 signature with ext-openssl, issuer, audience, expiry, nonce,
 * at_hash). Your API checks access tokens with verifyAccessToken().
 *
 * An app acting for a user (an AI agent; a confidential app whose grantTypes
 * list the grant, and an API that grants it scopes):
 *
 *   $forAda = $login->exchangeToken($adasAccessToken, 'https://api.acme.com');   // RFC 8693
 *   $ask = $login->askUser('ada@acme.com', 'openid payments:create', ['bindingMessage' => 'Pay invoice 42']);
 *   // show $ask['bindingCode'] in the conversation
 *   $approved = $login->waitForUser($ask);                                     // CIBA, poll mode
 */
class HostedLogin
{
    private string $issuer;
    private string $clientId;
    /** requested_token_type for the token vault (getConnectionToken). */
    public const CONNECTION_TOKEN_TYPE = 'urn:touchque:params:oauth:token-type:connection-access-token';
    /** @internal Why issuerFor() refused a domain. */
    public const PLAINTEXT_ISSUER = 'Refusing a plaintext http:// domain: codes, tokens and the client secret would travel in the clear. '
        . 'Use https:// (http:// only on localhost).';

    private ?string $clientSecret;
    private ?string $redirectUri;
    private string $scope;
    private ?string $audience;
    private int $clockTolerance;
    /** @var callable */
    private $transport;
    /** @var array<string, string> kid => PEM */
    private array $keys = [];
    private int $keysAt = 0;

    /**
     * @param array $config domain, clientId, clientSecret?, redirectUri?, scope?, audience?, clockTolerance?,
     *                      transport? (callable(string $method, string $url, array $headers, ?string $body): array{0:int,1:string})
     */
    public function __construct(array $config)
    {
        if (empty($config['domain'])) {
            throw new HostedLoginException('config', 'domain is required');
        }
        if (empty($config['clientId'])) {
            throw new HostedLoginException('config', 'clientId is required');
        }
        if (!function_exists('openssl_verify')) {
            throw new HostedLoginException('config', 'HostedLogin needs the openssl extension');
        }
        $issuer = self::issuerFor($config['domain']);
        if ($issuer === null) {
            throw new HostedLoginException('config', self::PLAINTEXT_ISSUER);
        }
        $this->issuer = $issuer;
        $this->clientId = $config['clientId'];
        $this->clientSecret = $config['clientSecret'] ?? null;
        $this->redirectUri = $config['redirectUri'] ?? null;
        $this->scope = $config['scope'] ?? 'openid profile email';
        $this->audience = $config['audience'] ?? null;
        $this->clockTolerance = (int) ($config['clockTolerance'] ?? 60);
        $this->transport = $config['transport'] ?? [self::class, 'curlTransport'];
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * @internal The issuer for a domain (`https://` added when it has no scheme): https, or http
     * only on this machine (localhost, 127.0.0.1, [::1], *.localhost), like the API baseUrl.
     * Null for a plaintext issuer anywhere else.
     */
    public static function issuerFor(string $domain): ?string
    {
        $raw = rtrim($domain, '/');
        if (!preg_match('#^https?://#', $raw)) {
            return "https://{$raw}";
        }
        if (strpos($raw, 'https://') === 0) {
            return $raw;
        }
        $host = strtolower(trim((string) parse_url($raw, PHP_URL_HOST), '[]'));
        $local = in_array($host, ['localhost', '127.0.0.1', '::1'], true) || substr($host, -10) === '.localhost';
        return $local ? $raw : null;
    }

    /**
     * The URL to send the browser to, and the values to keep until the callback.
     *
     * @param array $opts state?, nonce?, codeVerifier?, redirectUri?, scope?, audience?, prompt?, loginHint?,
     *                    screenHint?, uiLocales?, maxAge?, connection?, organization?, invitation?, acrValues?,
     *                    responseMode?, extraParams?
     * @return array{url: string, state: string, nonce: string, codeVerifier: string}
     */
    public function authorizationUrl(array $opts = []): array
    {
        $redirect = $opts['redirectUri'] ?? $this->redirectUri;
        if (!$redirect) {
            throw new HostedLoginException('config', 'redirectUri is required');
        }
        $state = $opts['state'] ?? self::random();
        $nonce = $opts['nonce'] ?? self::random();
        $verifier = $opts['codeVerifier'] ?? self::random(48);
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirect,
            'scope' => $opts['scope'] ?? $this->scope,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::b64u(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ];
        $map = [
            'audience' => $opts['audience'] ?? $this->audience, 'prompt' => $opts['prompt'] ?? null,
            'login_hint' => $opts['loginHint'] ?? null, 'screen_hint' => $opts['screenHint'] ?? null,
            'ui_locales' => $opts['uiLocales'] ?? null, 'max_age' => $opts['maxAge'] ?? null,
            'connection' => $opts['connection'] ?? null, 'organization' => $opts['organization'] ?? null,
            'invitation' => $opts['invitation'] ?? null, 'acr_values' => $opts['acrValues'] ?? null,
            'response_mode' => $opts['responseMode'] ?? null,
        ];
        foreach ($map as $k => $v) {
            if ($v !== null && $v !== '') {
                $params[$k] = (string) $v;
            }
        }
        foreach (($opts['extraParams'] ?? []) as $k => $v) {
            $params[$k] = (string) $v;
        }
        return [
            'url' => $this->issuer . '/authorize?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986),
            'state' => $state,
            'nonce' => $nonce,
            'codeVerifier' => $verifier,
        ];
    }

    /**
     * Checks state (and iss), exchanges the code with the PKCE verifier,
     * verifies the ID token.
     *
     * @param array|string $callback the query/form fields ($_GET, $_POST) or the callback URL
     * @return array{accessToken: string, tokenType: string, expiresAt: int, scope: string, idToken: ?string, refreshToken: ?string, claims: array}
     */
    public function handleCallback($callback, string $state, string $nonce, string $codeVerifier, ?string $redirectUri = null, ?int $maxAge = null): array
    {
        $p = self::params($callback);
        if (empty($p['state']) || $state === '' || !hash_equals($state, (string) $p['state'])) {
            throw new HostedLoginException('state_mismatch', 'The state does not match this sign-in');
        }
        // RFC 9207: a response that carries iss (even an empty one) must name this issuer,
        // the one the ID token is checked against. Servers that do not send iss yet are accepted.
        if (isset($p['iss']) && $p['iss'] !== $this->issuer) {
            $iss = is_string($p['iss']) ? $p['iss'] : '';
            throw new HostedLoginException('issuer_mismatch', $iss !== '' ? "The response came from {$iss}" : 'The response has an empty iss');
        }
        if (!empty($p['error'])) {
            throw new HostedLoginException((string) $p['error'], $p['error_description'] ?? null);
        }
        if (empty($p['code'])) {
            throw new HostedLoginException('invalid_request', 'The callback has no code');
        }
        $redirect = $redirectUri ?? $this->redirectUri;
        if (!$redirect) {
            throw new HostedLoginException('config', 'redirectUri is required');
        }
        $tokens = $this->token(['grant_type' => 'authorization_code', 'code' => (string) $p['code'], 'redirect_uri' => $redirect, 'code_verifier' => $codeVerifier]);
        if (empty($tokens['idToken'])) {
            throw new HostedLoginException('invalid_token', 'No ID token: ask for the openid scope');
        }
        $tokens['claims'] = $this->verifyIdToken($tokens['idToken'], $nonce, $tokens['accessToken'], $maxAge);
        return $tokens;
    }

    /** A new access token and a rotated refresh token: keep the new one. */
    public function refresh(string $refreshToken, ?string $scope = null): array
    {
        $fields = ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken];
        if ($scope) {
            $fields['scope'] = $scope;
        }
        $tokens = $this->token($fields);
        if (!empty($tokens['idToken'])) {
            $tokens['claims'] = $this->verifyIdToken($tokens['idToken'], null, $tokens['accessToken']);
        }
        return $tokens;
    }

    /**
     * A token for the My Account API (audience https://<domain>/me/) from the
     * refresh token a first-party app holds. The refresh token rotates: keep the
     * returned one. Scopes: read:me, update:me, manage:me:security, delete:me.
     */
    public function myAccountToken(string $refreshToken, string $scope = 'read:me update:me'): array
    {
        return $this->token(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken, 'audience' => $this->issuer . '/me/', 'scope' => $scope]);
    }

    /** The My Account API for the person holding $accessToken. */
    public function myAccount(string $accessToken): MyAccount
    {
        return new MyAccount($this->issuer, $accessToken, $this->transport);
    }

    /** The hosted account page (profile; 'security', 'devices' or 'privacy'). */
    public function accountUrl(?string $section = null): string
    {
        return $this->issuer . '/account' . ($section ? "/{$section}" : '');
    }

    /** Machine to machine: an access token for your API with the app's own credentials. */
    public function clientCredentials(string $audience, ?string $scope = null): array
    {
        $fields = ['grant_type' => 'client_credentials', 'audience' => $audience];
        if ($scope) {
            $fields['scope'] = $scope;
        }
        return $this->token($fields);
    }

    /**
     * RFC 8693: a signed-in user's access token, traded for one to call $audience on their
     * behalf (sub = the user, act.sub = this app). For a confidential app the API grants
     * scopes to; never longer than the user's token.
     */
    public function exchangeToken(string $subjectToken, string $audience, ?string $scope = null): array
    {
        $fields = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token' => $subjectToken,
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token', 'audience' => $audience,
        ];
        if ($scope) {
            $fields['scope'] = $scope;
        }
        return $this->token($fields);
    }

    /**
     * Token vault: the provider's own access token (Google, Microsoft, GitHub…) for the
     * signed-in user, from a connection that stores tokens. Touchque refreshes it; the
     * refresh token never leaves. $userAccessToken is the user's token for this app (or for
     * an app the connection lists). HostedLoginException invalid_grant: the user has not
     * signed in with the connection since it started storing tokens, or they stopped app access.
     */
    public function getConnectionToken(string $userAccessToken, string $connection, ?string $scope = null): array
    {
        $fields = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token' => $userAccessToken,
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type' => self::CONNECTION_TOKEN_TYPE, 'connection' => $connection,
        ];
        if ($scope) {
            $fields['scope'] = $scope;
        }
        return $this->token($fields);
    }

    /**
     * CIBA: asks the user (e-mail or usr_ id) to approve on their phone.
     *
     * @param array $options audience, bindingMessage (<= 64 characters), authorizationDetails (RFC 9396), requestedExpiry (30–300)
     * @return array{authReqId:string,expiresAt:int,interval:int,bindingCode:?string}
     */
    public function askUser(string $loginHint, string $scope, array $options = []): array
    {
        $fields = ['login_hint' => $loginHint, 'scope' => $scope];
        if (!empty($options['audience'])) {
            $fields['audience'] = $options['audience'];
        }
        if (!empty($options['bindingMessage'])) {
            $fields['binding_message'] = $options['bindingMessage'];
        }
        if (!empty($options['authorizationDetails'])) {
            $fields['authorization_details'] = json_encode($options['authorizationDetails'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        if (!empty($options['requestedExpiry'])) {
            $fields['requested_expiry'] = (string) $options['requestedExpiry'];
        }
        [$status, $body] = $this->post('/bc-authorize', $fields);
        if ($status >= 400) {
            throw self::error($status, $body);
        }
        $d = json_decode($body, true) ?: [];
        return [
            'authReqId' => (string) $d['auth_req_id'],
            'expiresAt' => time() + (int) ($d['expires_in'] ?? 0),
            'interval' => (int) ($d['interval'] ?? 5),
            'bindingCode' => $d['binding_code'] ?? null,
        ];
    }

    /** Polls until the user answers: the tokens, or HostedLoginException access_denied / expired_token. */
    public function waitForUser(array $request): array
    {
        $interval = (int) $request['interval'];
        while (true) {
            if (time() > $request['expiresAt']) {
                throw new HostedLoginException('expired_token', 'The user did not answer in time');
            }
            sleep($interval);
            try {
                return $this->token(['grant_type' => 'urn:openid:params:grant-type:ciba', 'auth_req_id' => $request['authReqId']]);
            } catch (HostedLoginException $e) {
                if ($e->getErrorCode() === 'slow_down') {
                    $interval += 5;
                } elseif ($e->getErrorCode() !== 'authorization_pending') {
                    throw $e;
                }
            }
        }
    }

    public function revoke(string $token): void
    {
        [$status, $body] = $this->post('/oauth/revoke', ['token' => $token]);
        if ($status >= 400) {
            throw self::error($status, $body);
        }
    }

    public function userinfo(string $accessToken): array
    {
        [$status, $body] = ($this->transport)('GET', $this->issuer . '/userinfo', ['Authorization: Bearer ' . $accessToken, 'Accept: application/json'], null);
        if ($status >= 400) {
            throw self::error($status, $body);
        }
        return json_decode($body, true) ?: [];
    }

    public function logoutUrl(?string $idTokenHint = null, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        $p = ['client_id' => $this->clientId];
        if ($idTokenHint) {
            $p['id_token_hint'] = $idTokenHint;
        }
        if ($postLogoutRedirectUri) {
            $p['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }
        if ($state) {
            $p['state'] = $state;
        }
        return $this->issuer . '/oidc/logout?' . http_build_query($p, '', '&', PHP_QUERY_RFC3986);
    }

    /** For your API: signature, issuer, audience, expiry, typ at+jwt, scopes. */
    public function verifyAccessToken(string $token, string $audience, array $requiredScopes = []): array
    {
        $payload = $this->verifyJwt($token, 'at+jwt');
        $auds = is_array($payload['aud'] ?? null) ? $payload['aud'] : [$payload['aud'] ?? null];
        if (!in_array($audience, $auds, true)) {
            throw new HostedLoginException('invalid_token', 'The token is for another audience');
        }
        $scopes = explode(' ', (string) ($payload['scope'] ?? ''));
        $missing = array_values(array_diff($requiredScopes, $scopes));
        if ($missing) {
            throw new HostedLoginException('insufficient_scope', 'Missing scope: ' . implode(' ', $missing), 403);
        }
        return $payload;
    }

    public function verifyIdToken(string $idToken, ?string $nonce = null, ?string $accessToken = null, ?int $maxAge = null): array
    {
        $payload = $this->verifyJwt($idToken, null);
        $auds = is_array($payload['aud'] ?? null) ? $payload['aud'] : [$payload['aud'] ?? null];
        if (!in_array($this->clientId, $auds, true)) {
            throw new HostedLoginException('invalid_token', 'The ID token is for another app');
        }
        if (count($auds) > 1 && ($payload['azp'] ?? null) !== $this->clientId) {
            throw new HostedLoginException('invalid_token', 'azp does not name this app');
        }
        if ($nonce !== null && !(is_string($payload['nonce'] ?? null) && hash_equals($nonce, $payload['nonce']))) {
            throw new HostedLoginException('nonce_mismatch', 'The nonce does not match this sign-in');
        }
        if ($accessToken !== null && is_string($payload['at_hash'] ?? null)) {
            $expected = self::b64u(substr(hash('sha256', $accessToken, true), 0, 16));
            if (!hash_equals($expected, $payload['at_hash'])) {
                throw new HostedLoginException('invalid_token', 'at_hash does not match the access token');
            }
        }
        if ($maxAge !== null && is_int($payload['auth_time'] ?? null) && time() - $payload['auth_time'] > $maxAge + $this->clockTolerance) {
            throw new HostedLoginException('login_required', 'The sign-in is older than maxAge');
        }
        return $payload;
    }

    // ── Internals ─────────────────────────────────────────────────────────

    private static function random(int $bytes = 32): string
    {
        return self::b64u(random_bytes($bytes));
    }

    private static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function b64uDecode(string $text): string
    {
        $out = base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
        if ($out === false) {
            throw new HostedLoginException('invalid_token', 'malformed base64url');
        }
        return $out;
    }

    /** @param array|string $callback */
    private static function params($callback): array
    {
        if (is_array($callback)) {
            return $callback;
        }
        $query = strpos($callback, '?') !== false ? (string) parse_url($callback, PHP_URL_QUERY) : $callback;
        parse_str($query, $out);
        return $out;
    }

    private function post(string $path, array $fields): array
    {
        $headers = ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'];
        if ($this->clientSecret !== null) {
            $headers[] = 'Authorization: Basic ' . base64_encode(urlencode($this->clientId) . ':' . urlencode($this->clientSecret));
        } else {
            $fields['client_id'] = $this->clientId;
        }
        return ($this->transport)('POST', $this->issuer . $path, $headers, http_build_query($fields, '', '&'));
    }

    private static function error(int $status, string $body): HostedLoginException
    {
        $d = json_decode($body, true) ?: [];
        return new HostedLoginException($d['error'] ?? "http_{$status}", $d['error_description'] ?? null, $status);
    }

    private function token(array $fields): array
    {
        [$status, $body] = $this->post('/oauth/token', $fields);
        if ($status >= 400) {
            throw self::error($status, $body);
        }
        $d = json_decode($body, true) ?: [];
        return [
            'accessToken' => (string) ($d['access_token'] ?? ''),
            'tokenType' => (string) ($d['token_type'] ?? 'Bearer'),
            'expiresAt' => time() + (int) ($d['expires_in'] ?? 0),
            'scope' => (string) ($d['scope'] ?? ''),
            'idToken' => $d['id_token'] ?? null,
            'refreshToken' => $d['refresh_token'] ?? null,
            'claims' => [],
            'authorizationDetails' => isset($d['authorization_details']) && is_array($d['authorization_details']) ? $d['authorization_details'] : null,
            'issuedTokenType' => $d['issued_token_type'] ?? null,
            'connection' => isset($d['connection']) && is_string($d['connection']) ? $d['connection'] : null,
        ];
    }

    private function loadKeys(bool $force = false): void
    {
        $age = time() - $this->keysAt;
        if (!$force && $this->keys && $age < 3600) {
            return;
        }
        if ($force && $age < 30) {
            return;
        }
        [$status, $body] = ($this->transport)('GET', $this->issuer . '/.well-known/jwks.json', ['Accept: application/json'], null);
        if ($status >= 400) {
            throw new HostedLoginException('jwks_unavailable', "JWKS answered {$status}");
        }
        $keys = [];
        foreach ((json_decode($body, true)['keys'] ?? []) as $k) {
            if (($k['kty'] ?? '') === 'RSA' && !empty($k['kid']) && !empty($k['n']) && !empty($k['e']) && ($k['use'] ?? 'sig') === 'sig') {
                $keys[$k['kid']] = self::rsaPem(self::b64uDecode($k['n']), self::b64uDecode($k['e']));
            }
        }
        $this->keys = $keys;
        $this->keysAt = time();
    }

    private function verifyJwt(string $token, ?string $typ): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new HostedLoginException('invalid_token', 'not a JWT');
        }
        $header = json_decode(self::b64uDecode($parts[0]), true);
        $payload = json_decode(self::b64uDecode($parts[1]), true);
        if (!is_array($header) || !is_array($payload)) {
            throw new HostedLoginException('invalid_token', 'malformed JWT');
        }
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new HostedLoginException('invalid_token', 'Unexpected alg');
        }
        if ($typ !== null && strtolower((string) ($header['typ'] ?? '')) !== $typ) {
            throw new HostedLoginException('invalid_token', 'Wrong token type');
        }
        $kid = (string) ($header['kid'] ?? '');
        $this->loadKeys();
        if (!isset($this->keys[$kid])) {
            $this->loadKeys(true);
        }
        if (!isset($this->keys[$kid])) {
            throw new HostedLoginException('invalid_token', 'Unknown signing key');
        }
        $ok = openssl_verify($parts[0] . '.' . $parts[1], self::b64uDecode($parts[2]), $this->keys[$kid], OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new HostedLoginException('invalid_token', 'Bad signature');
        }
        $now = time();
        if (($payload['iss'] ?? null) !== $this->issuer) {
            throw new HostedLoginException('invalid_token', 'Wrong issuer');
        }
        if (!is_numeric($payload['exp'] ?? null) || $now > $payload['exp'] + $this->clockTolerance) {
            throw new HostedLoginException('invalid_token', 'The token expired');
        }
        if (is_numeric($payload['iat'] ?? null) && $payload['iat'] > $now + $this->clockTolerance) {
            throw new HostedLoginException('invalid_token', 'The token is from the future');
        }
        return $payload;
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
        $bitString = "\x03" . $len(strlen($rsaKey) + 1) . "\0" . $rsaKey;
        $der = $seq($algo . $bitString);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** @return array{0:int,1:string} */
    public static function curlTransport(string $method, string $url, array $headers, ?string $body): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $out = curl_exec($ch);
        if ($out === false) {
            $err = curl_error($ch);
            throw new HostedLoginException('network_error', $err);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        return [$status, (string) $out];
    }
}
