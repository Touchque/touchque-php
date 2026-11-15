<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueIdJagException;

/**
 * Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
 * draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
 * organization's identity provider (Touchque SSO) decides which of its apps
 * may reach which other service for its members; the app trades a member's ID
 * token for an ID-JAG there, then the ID-JAG for an access token at the other
 * service's authorization server, with no consent screen per member.
 *
 *   $jag = CrossAppAccess::requestIdJag(['issuer' => 'https://sso.touchque.com', 'clientId' => $id, 'clientSecret' => $secret,
 *                                        'idToken' => $idToken, 'audience' => 'https://auth.files.example']);
 *   $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => 'https://auth.files.example/token', 'clientId' => 'acme',
 *                                          'clientSecret' => $filesSecret, 'assertion' => $jag['assertion']]);
 *
 * Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The ID-JAG is
 * then bound to it (cnf.jkt) and is useless to anyone who copies it without the key.
 *
 *   $dpopKey = CrossAppAccess::createIdJagDpopKey();
 *   $jag = CrossAppAccess::requestIdJag([... , 'dpopKey' => $dpopKey]);      // $jag['dpopBound']
 *   $tokens = CrossAppAccess::redeemIdJag([... , 'assertion' => $jag['assertion'], 'dpopKey' => $dpopKey]);
 *
 * A token endpoint that asks for a DPoP nonce (use_dpop_nonce, with one valid DPoP-Nonce header) gets
 * the same request once more with it. Each call with a DPoP-bound access token ($tokens['token_type']
 * 'DPoP') sends `Authorization: DPoP <access token>` and a new proof for that request:
 *
 *   $proof = CrossAppAccess::idJagDpopProof($dpopKey, $url, ['method' => 'GET', 'accessToken' => $tokens['access_token']]);
 *
 * Your own authorization server takes them with IdJagVerifier (pass the DPoP proof key's
 * thumbprint as its third argument: a bound ID-JAG without it is refused).
 */
final class CrossAppAccess
{
    public const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
    public const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
    public const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    /** The options idJagDpopProof() takes. */
    private const PROOF_OPTIONS = ['method', 'accessToken', 'nonce'];

    /** RFC 9110 tchar: the characters of a token (an HTTP method, an auth-scheme, an auth-param name). */
    private const TCHAR = '!#$%&\'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /** ASCII case mapping with strtr: strtolower()/strtoupper() follow the locale before PHP 8.2. */
    private const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWER = 'abcdefghijklmnopqrstuvwxyz';

    /** @internal https, or http on this machine (tests). */
    public static function safeUrl(string $url): bool
    {
        $u = parse_url($url);
        $host = $u['host'] ?? '';
        return ($u['scheme'] ?? '') === 'https' || (($u['scheme'] ?? '') === 'http' && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true));
    }

    /**
     * A fresh DPoP key (RFC 9449, P-256) for requestIdJag and redeemIdJag; keep it in this process.
     * `['privateKey' => OpenSSLAsymmetricKey, 'publicJwk' => array, 'thumbprint' => string]`, the
     * thumbprint (RFC 7638) being the ID-JAG's cnf.jkt.
     */
    public static function createIdJagDpopKey(): array
    {
        $jwk = AgentKeys::generate('ES256')['privateJwk'];
        $public = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $jwk['x'], 'y' => $jwk['y']];
        $key = openssl_pkey_get_private(AgentKeys::ecPem(AgentKeys::b64urlDecode($jwk['d']), AgentKeys::b64urlDecode($jwk['x']), AgentKeys::b64urlDecode($jwk['y'])));
        if ($key === false) {
            throw new TouchqueConfigException('Could not make a DPoP key');
        }
        return ['privateKey' => $key, 'publicJwk' => $public, 'thumbprint' => AgentKeys::thumbprint($public)];
    }

    /**
     * A DPoP proof (RFC 9449) with a key from createIdJagDpopKey(), for one request to $url. Options (a
     * string or null each; an option name not listed here, such as 'access_token', or a value of another
     * type throws TouchqueConfigException naming it):
     *  - method: the request's HTTP method, trimmed and uppercased (htm); empty or left out: POST. A method
     *    with a character that is not an RFC 9110 token character throws TouchqueConfigException.
     *  - accessToken: for a call with a DPoP-bound access token (sent as `Authorization: DPoP <access token>`):
     *    adds ath, the token's SHA-256 hash.
     *  - nonce: the server's DPoP-Nonce: adds the nonce claim.
     * htu is $url with its scheme and host lowercased, the default port (80 for http, 443 for https) dropped,
     * "/" for an empty path, the path kept as given (no dot-segment removal, no percent-encoding changes), and
     * no user info, query or fragment; a URL with a control character throws TouchqueConfigException. The
     * header's jwk is rebuilt from the key as exactly kty, crv, x and y.
     */
    public static function idJagDpopProof(array $key, string $url, array $options = []): string
    {
        $unknown = array_diff(array_map('strval', array_keys($options)), self::PROOF_OPTIONS);
        if ($unknown) {
            throw new TouchqueConfigException('CrossAppAccess::idJagDpopProof(): unknown option(s) ' . implode(', ', $unknown)
                . ' (options are camelCase: ' . implode(', ', self::PROOF_OPTIONS) . ')');
        }
        foreach (self::PROOF_OPTIONS as $name) {
            if (isset($options[$name]) && !is_string($options[$name])) {
                throw new TouchqueConfigException("CrossAppAccess::idJagDpopProof(): {$name} must be a string");
            }
        }
        $jwk = self::dpopPublicJwk($key);
        $claims = ['htm' => self::htm($options['method'] ?? ''), 'htu' => self::htu($url), 'iat' => time(), 'jti' => bin2hex(random_bytes(16))];
        if (($options['accessToken'] ?? '') !== '') {
            $claims['ath'] = AgentKeys::b64url(hash('sha256', $options['accessToken'], true));
        }
        if (($options['nonce'] ?? '') !== '') {
            $claims['nonce'] = $options['nonce'];
        }
        $header = json_encode(['typ' => 'dpop+jwt', 'alg' => 'ES256', 'jwk' => $jwk], JSON_UNESCAPED_SLASHES);
        $payload = json_encode($claims, JSON_UNESCAPED_SLASHES);
        if ($header === false || $payload === false) {
            throw new TouchqueConfigException('Could not encode the DPoP proof: ' . json_last_error_msg());
        }
        $input = AgentKeys::b64url($header) . '.' . AgentKeys::b64url($payload);
        if (!openssl_sign($input, $der, $key['privateKey'], OPENSSL_ALGO_SHA256)) {
            throw new TouchqueConfigException('Could not sign with the DPoP key');
        }
        return $input . '.' . AgentKeys::b64url(AgentKeys::derToRaw($der));
    }

    /**
     * The public part of a key from createIdJagDpopKey(), rebuilt from its private key as exactly kty, crv,
     * x and y, whatever else the key array carries. Anything else throws TouchqueConfigException: a private
     * key that is not P-256, or a publicJwk that is not its public part.
     */
    private static function dpopPublicJwk(array $key): array
    {
        $private = $key['privateKey'] ?? null;
        $given = $key['publicJwk'] ?? null;
        $ec = null;
        if ($private instanceof \OpenSSLAsymmetricKey || (is_resource($private) && get_resource_type($private) === 'OpenSSL key')) {
            $ec = openssl_pkey_get_details($private)['ec'] ?? null;
        }
        if (!is_array($ec) || ($ec['curve_name'] ?? null) !== 'prime256v1' || !isset($ec['d'], $ec['x'], $ec['y']) || !is_array($given)) {
            throw new TouchqueConfigException('the DPoP key must be one from createIdJagDpopKey()');
        }
        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => AgentKeys::b64url(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)), 'y' => AgentKeys::b64url(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT))];
        if (($given['x'] ?? null) !== $jwk['x'] || ($given['y'] ?? null) !== $jwk['y']) {
            throw new TouchqueConfigException('the DPoP key must be one from createIdJagDpopKey()');
        }
        return $jwk;
    }

    /** RFC 9449 htm: $method trimmed and uppercased, POST when that leaves nothing; only RFC 9110 token characters. */
    private static function htm(string $method): string
    {
        $htm = strtr(trim($method, " \t\n\r\x0B\x0C"), self::LOWER, self::UPPER);
        if ($htm === '') {
            return 'POST';
        }
        if (strspn($htm, self::TCHAR) !== strlen($htm)) {
            throw new TouchqueConfigException('CrossAppAccess::idJagDpopProof(): method ' . json_encode($method, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)
                . ' is not an HTTP method (RFC 9110 token characters only)');
        }
        return $htm;
    }

    /**
     * RFC 9449 htu of $url: scheme and host lowercased, the default port (80 for http, 443 for https) dropped,
     * "/" for an empty path, the path kept as given, and no user info, query or fragment.
     */
    private static function htu(string $url): string
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $url)) {
            // parse_url() would turn it into "_": the htu would not be the URL the request goes to.
            throw new TouchqueConfigException('the URL ' . addcslashes($url, "\0..\37\177") . ' has a control character');
        }
        $u = parse_url($url);
        if (!is_array($u) || ($u['scheme'] ?? '') === '' || ($u['host'] ?? '') === '') {
            throw new TouchqueConfigException("{$url} is not an absolute URL");
        }
        $scheme = strtr($u['scheme'], self::UPPER, self::LOWER);
        $defaultPort = ['http' => 80, 'https' => 443][$scheme] ?? null;
        $port = isset($u['port']) && $u['port'] !== $defaultPort ? ':' . $u['port'] : '';
        $path = $u['path'] ?? '';
        return $scheme . '://' . strtr($u['host'], self::UPPER, self::LOWER) . $port . ($path === '' ? '/' : $path);
    }

    /** @internal The identity provider's OpenID configuration, checked against its issuer. */
    public static function discover(string $issuer): array
    {
        $meta = McpAuth::getJson(rtrim($issuer, '/') . '/.well-known/openid-configuration');
        if (($meta['issuer'] ?? null) !== $issuer) {
            throw new TouchqueConfigException("the identity provider's metadata does not match its issuer");
        }
        return $meta;
    }

    /**
     * One token request: [the answer (a JSON object, else []), the latest valid DPoP-Nonce the server sent
     * (else null)]. An answer of 400 or more, or none, throws TouchqueIdJagException with that nonce.
     */
    private static function postForm(string $url, array $form, ?array $basic, ?array $dpopKey = null): array
    {
        if (!self::safeUrl($url)) {
            throw new TouchqueConfigException("{$url} must be an https URL");
        }
        $body = http_build_query(array_filter($form, static fn ($v) => $v !== null), '', '&', PHP_QUERY_RFC3986);
        $headers = ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'];
        if ($basic !== null) {
            $headers[] = 'Authorization: Basic ' . base64_encode(rawurlencode($basic[0]) . ':' . rawurlencode($basic[1]));
        }
        $answer = self::send($url, $body, $headers, $dpopKey, null);
        $nonce = $answer['nonce'];
        // RFC 9449 section 8: the server wants its nonce in the proof. When its DPoP-Nonce header is one valid
        // value, the same request (body, client authentication) goes once more with a new proof carrying it;
        // never more than once.
        if ($dpopKey !== null && $nonce !== null && self::asksForNonce($answer)) {
            $answer = self::send($url, $body, $headers, $dpopKey, $nonce);
            $nonce = $answer['nonce'] ?? $nonce; // the retry's answer's, when it has one
        }
        $status = $answer['status'];
        $data = $answer['data'];
        if ($answer['raw'] === false || $status >= 400) {
            $error = $data['error'] ?? 'server_error';
            $description = $data['error_description'] ?? "{$url} answered {$status}";
            throw new TouchqueIdJagException(is_array($error) ? 'server_error' : (string)$error,
                is_array($description) ? "{$url} answered {$status}" : (string)$description, $status ?: null, $nonce);
        }
        return [$data, $nonce];
    }

    /**
     * One POST, with a new DPoP proof when there is a key: ['raw', 'status', 'data' (the answer when it is a
     * JSON object, else []), 'nonce' (the DPoP-Nonce header when it is one value of valid nonce syntax, else
     * null), 'challenge' (WWW-Authenticate)].
     */
    private static function send(string $url, string $body, array $headers, ?array $dpopKey, ?string $nonce): array
    {
        if ($dpopKey !== null) {
            $headers[] = 'DPoP: ' . self::idJagDpopProof($dpopKey, $url, ['nonce' => $nonce]);
        }
        $received = [];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false, CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$received): int {
                if (strncasecmp($line, 'HTTP/', 5) === 0) {
                    $received = []; // a new response: only the last one's headers count (not a 100 Continue's)
                } elseif (($colon = strpos($line, ':')) !== false) {
                    $name = strtr(trim(substr($line, 0, $colon), " \t"), self::UPPER, self::LOWER);
                    $received[$name][] = trim(substr($line, $colon + 1), " \t\r\n");
                }
                return strlen($line);
            },
        ]);
        $raw = curl_exec($ch);
        $nonces = array_values(array_unique($received['dpop-nonce'] ?? []));
        return [
            'raw' => $raw, 'status' => (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE), 'data' => self::jsonObject($raw),
            'nonce' => count($nonces) === 1 && self::isNonce($nonces[0]) ? $nonces[0] : null,
            'challenge' => implode(', ', $received['www-authenticate'] ?? []),
        ];
    }

    /** $raw decoded when it is a JSON object, else [] (not JSON, or a JSON string, number, boolean, null or list). */
    private static function jsonObject($raw): array
    {
        if (!is_string($raw) || ($raw[strspn($raw, " \t\n\r")] ?? '') !== '{') {
            return [];
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    /** RFC 9449 section 8.1: nonce = 1*NQCHAR, NQCHAR = %x21 / %x23-5B / %x5D-7E (printable ASCII but space, " and \). */
    private static function isNonce(string $value): bool
    {
        return preg_match('/^[\x21\x23-\x5B\x5D-\x7E]++$/D', $value) === 1;
    }

    /** RFC 9449 section 8: a 400 or 401 use_dpop_nonce, in the JSON body or a 401's WWW-Authenticate DPoP challenge. */
    private static function asksForNonce(array $answer): bool
    {
        if ($answer['status'] !== 400 && $answer['status'] !== 401) {
            return false;
        }
        return ($answer['data']['error'] ?? null) === 'use_dpop_nonce'
            || ($answer['status'] === 401 && self::dpopChallengeAsksForNonce($answer['challenge']));
    }

    /**
     * Whether a WWW-Authenticate value (RFC 9110 section 11.6.1; several fields joined with commas) has a
     * DPoP challenge with error="use_dpop_nonce" (RFC 9449 section 9). Scheme and parameter names match
     * in any case; a quoted value counts with its quoted-pairs undone. One pass from left to right with
     * strspn()/strcspn(), never backing up: linear in the header's length, whatever it holds.
     */
    private static function dpopChallengeAsksForNonce(string $header): bool
    {
        $n = strlen($header);
        $scheme = '';
        $i = 0;
        while ($i < $n) {
            $i += strspn($header, " \t,", $i);
            if ($i >= $n) {
                break;
            }
            $len = strspn($header, self::TCHAR, $i);
            if ($len === 0) {
                $i = self::elementEnd($header, $i); // not a token (a stray character): skip this list element
                continue;
            }
            $name = strtr(substr($header, $i, $len), self::UPPER, self::LOWER);
            $i += $len;
            $j = $i + strspn($header, " \t", $i);
            if ($j < $n && $header[$j] === '=') {
                // auth-param = token BWS "=" BWS ( token / quoted-string )
                $k = $j + 1 + strspn($header, " \t", $j + 1);
                $value = null;
                if ($k < $n && $header[$k] === '"') {
                    [$value, $i] = self::quotedString($header, $k);
                } elseif (($valueLength = strspn($header, self::TCHAR, $k)) > 0) {
                    $value = substr($header, $k, $valueLength);
                    $i = $k + $valueLength;
                } else {
                    $i = self::elementEnd($header, $j); // a token68's "=" padding, or nothing after "="
                }
                if ($scheme === 'dpop' && $name === 'error' && $value === 'use_dpop_nonce') {
                    return true;
                }
            } elseif ($j === $n || $header[$j] === ',' || $j > $i) {
                $scheme = $name; // an auth-scheme: a new challenge
                $i = $j;
            } else {
                $i = self::elementEnd($header, $i); // a token68 such as abc/def
            }
        }
        return false;
    }

    /** The offset of the comma that ends the list element at $i (quoted strings skipped whole), or the end. */
    private static function elementEnd(string $s, int $i): int
    {
        $n = strlen($s);
        while ($i < $n) {
            $i += strcspn($s, ',"', $i);
            if ($i >= $n || $s[$i] === ',') {
                break;
            }
            $i = self::quotedString($s, $i)[1];
        }
        return $i;
    }

    /**
     * The quoted-string at $start (its opening quote): [its value with the quoted-pairs undone, or null when
     * it never closes; the offset after it].
     */
    private static function quotedString(string $s, int $start): array
    {
        $n = strlen($s);
        $value = '';
        $i = $start + 1;
        while ($i < $n) {
            $run = strcspn($s, '"\\', $i);
            $value .= substr($s, $i, $run);
            $i += $run;
            if ($i >= $n) {
                break;
            }
            if ($s[$i] === '"') {
                return [$value, $i + 1];
            }
            $value .= substr($s, $i + 1, 1); // a quoted-pair: the character after the backslash
            $i += 2;
        }
        return [null, $n];
    }

    private static function scopeText($scope): ?string
    {
        return is_array($scope) ? implode(' ', $scope) : $scope;
    }

    /** The dpopKey option: null or an array (checked in full when its first proof is made). */
    private static function dpopKeyOption(array $o): ?array
    {
        $key = $o['dpopKey'] ?? null;
        if ($key !== null && !is_array($key)) {
            throw new TouchqueConfigException('the DPoP key must be one from createIdJagDpopKey()');
        }
        return $key;
    }

    /**
     * Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic).
     * Options: issuer or tokenEndpoint, clientId, clientSecret, idToken, audience, resource?, scope?,
     * dpopKey? (binds the ID-JAG to that key; redeem it with the same key).
     * Returns ['assertion' => …, 'expiresIn' => …, 'scope' => …], plus with dpopKey 'dpopBound': whether
     * the returned ID-JAG carries that key's thumbprint (cnf.jkt).
     */
    public static function requestIdJag(array $o): array
    {
        $dpopKey = self::dpopKeyOption($o);
        $endpoint = $o['tokenEndpoint'] ?? null;
        if (!$endpoint) {
            if (empty($o['issuer'])) {
                throw new TouchqueConfigException('requestIdJag needs issuer or tokenEndpoint');
            }
            $endpoint = self::discover($o['issuer'])['token_endpoint'] ?? null;
            if (!is_string($endpoint)) {
                throw new TouchqueConfigException('the identity provider names no token_endpoint');
            }
        }
        [$data, $nonce] = self::postForm($endpoint, [
            'grant_type' => self::TOKEN_EXCHANGE_GRANT, 'requested_token_type' => self::ID_JAG_TOKEN_TYPE,
            'subject_token' => $o['idToken'] ?? '', 'subject_token_type' => self::ID_TOKEN_TYPE, 'audience' => $o['audience'] ?? '',
            'resource' => $o['resource'] ?? null, 'scope' => self::scopeText($o['scope'] ?? null),
        ], [$o['clientId'] ?? '', $o['clientSecret'] ?? ''], $dpopKey);
        if (($data['issued_token_type'] ?? null) !== self::ID_JAG_TOKEN_TYPE || !is_string($data['access_token'] ?? null)) {
            throw new TouchqueIdJagException('invalid_response', 'the identity provider did not answer with an ID-JAG', null, $nonce);
        }
        $out = ['assertion' => $data['access_token'], 'expiresIn' => $data['expires_in'] ?? null, 'scope' => $data['scope'] ?? null];
        if ($dpopKey !== null) {
            // An identity provider without DPoP support ignores the proof: say so instead of guessing.
            $parts = explode('.', $data['access_token']);
            $claims = count($parts) === 3 ? json_decode(AgentKeys::b64urlDecode($parts[1]), true) : null;
            $jkt = is_array($claims) && is_array($claims['cnf'] ?? null) ? ($claims['cnf']['jkt'] ?? null) : null;
            $out['dpopBound'] = is_string($jkt) && $jkt === AgentKeys::thumbprint(self::dpopPublicJwk($dpopKey));
        }
        return $out;
    }

    /**
     * Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer).
     * Options: tokenEndpoint, clientId, clientSecret?, assertion, resource?, scope?, dpopKey? (the key the
     * ID-JAG is bound to: a DPoP proof goes along, and the access token is then DPoP-bound too: each
     * call with it carries idJagDpopProof($dpopKey, $url, ['method' => …, 'accessToken' => …])).
     * Returns the token endpoint's answer (a JSON object; [] for anything else).
     * With dpopKey, a 400 or 401 use_dpop_nonce whose DPoP-Nonce header is one value of valid nonce syntax
     * (RFC 9449: printable ASCII but space, " and \) gets the same request once more with a proof carrying
     * that nonce (here and in requestIdJag); a missing or empty one, one repeated with different values, or
     * an invalid one gets no retry. A TouchqueIdJagException carries in $dpopNonce the latest valid
     * DPoP-Nonce the server sent in the call: the retry's answer's when it has one, else the first answer's
     * (null when there is none; an invalid value is never put there).
     */
    public static function redeemIdJag(array $o): array
    {
        $dpopKey = self::dpopKeyOption($o);
        $secret = $o['clientSecret'] ?? null;
        return self::postForm($o['tokenEndpoint'] ?? '', [
            'grant_type' => self::JWT_BEARER_GRANT, 'assertion' => $o['assertion'] ?? '',
            'resource' => $o['resource'] ?? null, 'scope' => self::scopeText($o['scope'] ?? null),
            'client_id' => $secret ? null : ($o['clientId'] ?? ''),
        ], $secret ? [$o['clientId'] ?? '', $secret] : null, $dpopKey)[0];
    }
}
