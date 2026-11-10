<?php

namespace TouchQue;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Exceptions\TouchQueSecurityEventException;

/**
 * Shared Signals (OpenID Shared Signals Framework 1.0): Security Event Tokens
 * (SETs, RFC 8417) an identity provider sends when something happens to a
 * person's account after sign-in: CAEP session-revoked, credential-change,
 * device-compliance-change; RISC account-disabled, credential-compromise.
 * TouchQue SSO sends them for an organization's members to the receivers its
 * admin adds (Organization > Continuous access). Your app ends the person's
 * sessions or asks them to sign in again.
 *
 * Push delivery (RFC 8935), the SET is the request body (application/secevent+jwt):
 *
 *   $v = new SecurityEventVerifier(['issuer' => 'https://sso.touchque.com', 'audience' => 'https://app.example.com']);
 *   try {
 *       $event = $v->verify(file_get_contents('php://input'));
 *   } catch (TouchQueSecurityEventException $e) {
 *       http_response_code(400);
 *       echo json_encode(['err' => $e->error, 'description' => $e->getMessage()]);
 *       exit;
 *   }
 *   if ($event['name'] === 'session-revoked') { endSessionsOf($event['subject']['email'] ?? null); }
 *   http_response_code(202);
 *
 * Poll delivery (RFC 8936): SecurityEventVerifier::poll($url, $token, ['ack' => [...]]).
 *
 * Options: issuer, audience, jwksUri? (else found from the issuer's
 * /.well-known/ssf-configuration), jwks? (fixed keys), clockSkew? (300).
 * A SET does not expire: it says what happened. Keep the jtis you handled
 * and skip a repeat. Needs ext-openssl.
 */
class SecurityEventVerifier
{
    public const TYPES = [
        'session-revoked' => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'credential-change' => 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
        'device-compliance-change' => 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
        'account-disabled' => 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
        'credential-compromise' => 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
        'verification' => 'https://schemas.openid.net/secevent/ssf/event-type/verification',
        'stream-updated' => 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
    ];
    private const NAMESPACE = '#^https://schemas\.openid\.net/secevent/(caep|risc|ssf)/event-type/([a-z0-9-]+)$#';

    private string $issuer;
    private string $audience;
    private ?string $jwksUri;
    private int $skew;
    private bool $pinned;
    /** @var callable */
    private $fetch;
    private array $keys = [];
    private int $keysAt = 0;
    private int $triedAt = 0;

    public function __construct(array $options)
    {
        if (empty($options['issuer']) || empty($options['audience'])) {
            throw new TouchQueConfigException("SecurityEventVerifier needs issuer (the transmitter) and audience (your stream's aud)");
        }
        $this->issuer = $options['issuer'];
        $this->audience = $options['audience'];
        $this->jwksUri = $options['jwksUri'] ?? null;
        $this->skew = (int)($options['clockSkew'] ?? 300);
        $this->fetch = $options['fetch'] ?? [McpAuth::class, 'getJson'];
        $this->pinned = isset($options['jwks']);
        if ($this->pinned) {
            $this->setKeys($options['jwks']);
        }
    }

    private function setKeys(array $jwks): void
    {
        $keys = [];
        foreach (($jwks['keys'] ?? []) as $jwk) {
            if (!empty($jwk['kid'])) {
                $keys[$jwk['kid']] = $jwk;
            }
        }
        $this->keys = $keys;
        $this->keysAt = time();
    }

    private function loadKeys(): void
    {
        if (!$this->jwksUri) {
            $meta = ($this->fetch)(rtrim($this->issuer, '/') . '/.well-known/ssf-configuration');
            if (($meta['issuer'] ?? null) !== $this->issuer || !is_string($meta['jwks_uri'] ?? null)) {
                throw new \UnexpectedValueException("the transmitter's metadata does not match its issuer");
            }
            $this->jwksUri = $meta['jwks_uri'];
        }
        // Discovered or configured: never keys over plain http (http only on this machine, for tests).
        if (!CrossAppAccess::safeUrl($this->jwksUri)) {
            throw new \UnexpectedValueException("{$this->jwksUri} must be an https URL");
        }
        $this->setKeys(($this->fetch)($this->jwksUri));
    }

    private function keyFor(string $kid): ?array
    {
        if ($this->pinned) {
            return $this->keys[$kid] ?? null;
        }
        if (!$this->keysAt || time() - $this->keysAt > 3600) {
            $this->loadKeys();
        }
        if (!isset($this->keys[$kid]) && time() - $this->triedAt > 300) {
            $this->triedAt = time();
            $this->loadKeys();
        }
        return $this->keys[$kid] ?? null;
    }

    /**
     * The SET, checked (signature RS256 with the issuer's keys, typ, issuer,
     * audience, one event): ['jti', 'issuer', 'audience' (list), 'issuedAt',
     * 'txn' (TouchQue's case code), 'subject' (sub_id), 'type' (URI), 'name'
     * (short name, or null), 'claims' (the event's own)], or
     * TouchQueSecurityEventException.
     */
    public function verify(string $token): array
    {
        $bad = static fn (string $m) => new TouchQueSecurityEventException('invalid_request', $m);
        $parts = explode('.', trim($token));
        if (count($parts) !== 3) {
            throw $bad('not a JWT');
        }
        $head = json_decode(AgentKeys::b64urlDecode($parts[0]), true);
        $c = json_decode(AgentKeys::b64urlDecode($parts[1]), true);
        if (!is_array($head) || !is_array($c)) {
            throw $bad('not a JWT');
        }
        if (strtolower((string)($head['typ'] ?? '')) !== 'secevent+jwt') {
            throw $bad('not a Security Event Token (typ secevent+jwt)');
        }
        if (($head['alg'] ?? null) !== 'RS256' || !is_string($head['kid'] ?? null)) {
            throw new TouchQueSecurityEventException('invalid_key', 'unsupported signature');
        }
        try {
            $jwk = $this->keyFor($head['kid']);
        } catch (\Throwable $e) {
            throw new TouchQueSecurityEventException('temporarily_unavailable', "the transmitter's keys could not be read: " . $e->getMessage());
        }
        if ($jwk === null || !McpAuth::verifySignature($parts[0] . '.' . $parts[1], AgentKeys::b64urlDecode($parts[2]), 'RS256', $jwk)) {
            throw new TouchQueSecurityEventException('invalid_key', 'signature does not verify');
        }
        if (($c['iss'] ?? null) !== $this->issuer) {
            throw new TouchQueSecurityEventException('invalid_issuer', 'another issuer');
        }
        $aud = array_values(array_filter(is_array($c['aud'] ?? null) ? $c['aud'] : [$c['aud'] ?? null], 'is_string'));
        if (!in_array($this->audience, $aud, true)) {
            throw new TouchQueSecurityEventException('invalid_audience', 'not for this receiver');
        }
        if (!is_string($c['jti'] ?? null) || !is_int($c['iat'] ?? null)) {
            throw $bad('jti and iat are required');
        }
        if ($c['iat'] - $this->skew > time()) {
            throw $bad('issued in the future');
        }
        $events = $c['events'] ?? null;
        if (!is_array($events) || count($events) !== 1 || !is_string(array_key_first($events))) {
            throw $bad('a SET carries exactly one event');
        }
        $type = (string)array_key_first($events);
        $claims = $events[$type];
        return [
            'jti' => $c['jti'], 'issuer' => $c['iss'], 'audience' => $aud, 'issuedAt' => $c['iat'],
            'txn' => is_string($c['txn'] ?? null) ? $c['txn'] : null,
            'subject' => is_array($c['sub_id'] ?? null) ? $c['sub_id'] : [],
            'type' => $type, 'name' => preg_match(self::NAMESPACE, $type, $m) ? $m[2] : null,
            'claims' => is_array($claims) ? $claims : [],
        ];
    }

    /**
     * One poll (RFC 8936): acknowledges what you handled and returns
     * ['sets' => [jti => token], 'moreAvailable' => bool]. Options: ack,
     * setErrs, maxEvents, returnImmediately.
     */
    public static function poll(string $url, string $token, array $options = []): array
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);
        if ($scheme !== 'https' && !($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true))) {
            throw new TouchQueConfigException("{$url} must be an https URL");
        }
        if ($token === '') {
            throw new TouchQueConfigException("poll needs the stream's token");
        }
        $body = [];
        foreach (['ack', 'setErrs', 'maxEvents', 'returnImmediately'] as $k) {
            if (array_key_exists($k, $options)) {
                $body[$k] = $options[$k];
            }
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_FOLLOWLOCATION => false, CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode((object)$body),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json', "Authorization: Bearer {$token}"],
        ]);
        $raw = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $data = json_decode((string)$raw, true) ?? [];
        if ($raw === false || $status !== 200) {
            throw new TouchQueSecurityEventException((string)($data['error'] ?? 'server_error'), "{$url} answered {$status}");
        }
        return ['sets' => is_array($data['sets'] ?? null) ? $data['sets'] : [], 'moreAvailable' => ($data['moreAvailable'] ?? false) === true];
    }
}
