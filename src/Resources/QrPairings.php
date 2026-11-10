<?php

namespace TouchQue\Resources;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Http\HttpClient;

/**
 * Pairing a browser by QR code: your page shows a QR code, the person scans it
 * with the TouchQue app, and the phone that scanned is the one asked to approve.
 *
 * 1. Your page gets the thumbprint of its browser key (`@touchque/web`
 *    `browserKey.thumbprint()`) and sends it to your server.
 * 2. `create($keyThumbprint, ['clientIp' => ..., 'userAgent' => ...])` registers
 *    a pairing and returns `uri` (touchque://pair-browser?...): show it as a QR
 *    code. It can be scanned once, for `ttlSeconds` (default 120). The nonce in
 *    it never leaves your server and the QR: TouchQue keeps only its hash.
 * 3. Poll `get($pairingId)`: `scanned` once a phone holding one of your users'
 *    accounts read it (`externalUsername`, `proximity`), `confirmed` once the
 *    person went on, `reported` when they said someone told them to scan it
 *    (their 2FA freezes).
 * 4. `$tq->login->request($user, ..., qrPairing: $pairingId)` asks that phone,
 *    once, with number matching; the browser key's fingerprint is one of the
 *    rows the phone signs. When your own checks say no, `refuse($pairingId,
 *    $reason, $message)` and the phone shows why.
 */
class QrPairings
{
    /** What `refuse()` may tell the phone. */
    public const REFUSAL_REASONS = ['policy', 'device_not_approved', 'too_many_browsers', 'rate_limited', 'no_account', 'other'];

    private const CREATE_OPTIONS = ['clientIp', 'userAgent', 'browser', 'os', 'ttlSeconds'];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /** What the QR code says: `touchque://pair-browser?v=1&p=<pairing>&n=<nonce>&k=<key thumbprint>`. */
    public static function uri(string $pairingId, string $nonce, string $keyThumbprint): string
    {
        return 'touchque://pair-browser?v=1&p=' . rawurlencode($pairingId) . '&n=' . rawurlencode($nonce) . '&k=' . rawurlencode($keyThumbprint);
    }

    /**
     * Registers a pairing for one browser: `['pairingId', 'expiresAt', 'nonce', 'uri']`; show `uri` as a QR code.
     *
     * @param array $options clientIp, userAgent, browser ("Chrome 155"), os ("macOS 15"), ttlSeconds (30 to 300)
     */
    public function create(string $keyThumbprint, array $options = []): array
    {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $keyThumbprint)) {
            throw new TouchQueConfigException('qrPairings->create() needs the keyThumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters).');
        }
        $unknown = array_diff(array_keys($options), self::CREATE_OPTIONS);
        if ($unknown) {
            throw new TouchQueConfigException('qrPairings->create(): unknown option ' . implode(', ', $unknown) . '.');
        }
        $ttl = $options['ttlSeconds'] ?? null;
        if ($ttl !== null && (!is_int($ttl) || $ttl < 30 || $ttl > 300)) {
            throw new TouchQueConfigException('qrPairings->create(): ttlSeconds must be 30 to 300.');
        }
        $nonce = self::b64url(random_bytes(32));
        $body = ['nonceHash' => self::b64url(hash('sha256', $nonce, true)), 'keyThumbprint' => $keyThumbprint];
        foreach (self::CREATE_OPTIONS as $key) {
            if (isset($options[$key]) && $options[$key] !== '') {
                $body[$key] = $options[$key];
            }
        }
        $created = $this->http->post('/qr-pairings', $body);
        return $created + ['nonce' => $nonce, 'uri' => self::uri($created['pairingId'], $nonce, $keyThumbprint)];
    }

    /** Where a pairing stands; once scanned, who scanned it and how near the phone was. */
    public function get(string $pairingId): array
    {
        return $this->http->get('/qr-pairings/' . self::id($pairingId, 'get'));
    }

    /**
     * Your own checks refused a scanned pairing; the phone shows `$message`.
     * Only a `scanned` or `confirmed` pairing can be refused (409 `not_open`).
     */
    public function refuse(string $pairingId, string $reason, string $message, ?string $caseCode = null, ?string $deviceCode = null): array
    {
        if (!in_array($reason, self::REFUSAL_REASONS, true)) {
            throw new TouchQueConfigException('qrPairings->refuse(): reason must be one of ' . implode(', ', self::REFUSAL_REASONS) . '.');
        }
        if (trim($message) === '') {
            throw new TouchQueConfigException('qrPairings->refuse() needs the message: what the phone shows (up to 300 characters).');
        }
        $body = ['reason' => $reason, 'message' => $message];
        if ($caseCode !== null && $caseCode !== '') {
            $body['caseCode'] = $caseCode;
        }
        if ($deviceCode !== null && $deviceCode !== '') {
            $body['deviceCode'] = $deviceCode;
        }
        return $this->http->post('/qr-pairings/' . self::id($pairingId, 'refuse') . '/outcome', $body);
    }

    private static function id(string $pairingId, string $method): string
    {
        if ($pairingId === '') {
            throw new TouchQueConfigException("qrPairings->{$method}() needs the pairingId.");
        }
        return rawurlencode($pairingId);
    }

    private static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
