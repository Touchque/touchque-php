<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;

class Auth
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Generate a new setup secret for a user: the first-time linking QR.
     *
     * `$clientIp` and `$userAgent`: the browser that asks for the QR, as you send
     * them with `login->request()`. Touchque records them with the secret (never in
     * the QR), and the phone shows where the QR was asked for (city, device) before
     * it links, so someone tricked into scanning another person's QR sees that
     * person's place and device. Each is sent only when it is not null or empty, as
     * given (a User-Agent that is not valid UTF-8 with U+FFFD in place of its invalid
     * bytes); Touchque keeps what it can use and never refuses the request over them.
     *
     *     $qr = $tq->auth->generateSecret($user, $request->ip(), $request->userAgent());
     */
    public function generateSecret(string $externalUsername, ?string $clientIp = null, ?string $userAgent = null): array
    {
        return $this->http->post('/auth/generate-secret', self::secretBody($externalUsername, $clientIp, $userAgent));
    }


    /**
     * Reset (regenerate) a user's secret. `$clientIp` and `$userAgent`: the browser
     * that asks for the new QR, sent like generateSecret()'s. Touchque records them
     * for the new QR; a reset without them leaves it with none (setupContext null).
     */
    public function resetSecret(string $externalUsername, ?string $clientIp = null, ?string $userAgent = null): array
    {
        return $this->http->post('/auth/secret/reset', self::secretBody($externalUsername, $clientIp, $userAgent));
    }

    /** The user, plus the browser's IP and User-Agent when given (null or '' is left out). */
    private static function secretBody(string $externalUsername, ?string $clientIp, ?string $userAgent): array
    {
        $body = ['externalUsername' => $externalUsername];
        if ($clientIp !== null && $clientIp !== '') {
            $body['clientIp'] = $clientIp;
        }
        if ($userAgent !== null && $userAgent !== '') {
            $body['userAgent'] = $userAgent;
        }
        return $body;
    }

    /**
     * Validate a setup secret code.
     * Mirrors the Node/Python/Go SDKs' `validateSecret`/`validate_secret`/`ValidateSecret`.
     *
     * The answer always has `setupContext`: where the QR was asked for, as Touchque
     * recorded it from the QR request (parseSetupContext()), or null (an older QR, a
     * QR asked for without an IP or User-Agent, or a server without setup context).
     *
     * This is the phone's call, public on the API, made after scanning: `farFromPhone`
     * compares where the QR was asked for with the IP address of whoever calls it.
     * Called from your server, it compares with your server, not with the phone.
     *
     * @return array{
     *     valid: bool,
     *     externalUsername?: string,
     *     integrationId?: string,
     *     integration?: array,
     *     setupContext: array{
     *         ip: string|null,
     *         location: array{city: string|null, country: string|null, countryCode: string|null}|null,
     *         device: array{browser: string|null, os: string|null, model: string|null}|null,
     *         requestedAt: string|null,
     *         farFromPhone: bool|null,
     *     }|null,
     * }
     */
    public function validateSecret(string $secret): array
    {
        $res = $this->http->post('/auth/secret/validate', [
            'secret' => $secret
        ]);
        $res['setupContext'] = self::parseSetupContext($res['setupContext'] ?? null);
        return $res;
    }

    /**
     * Reads the `setupContext` of a validate answer: where the first-time QR was asked
     * for. Lenient: a field that is missing, null or not of its type is null, never an
     * exception, and fields it does not know are dropped. Null when `$raw` is null or
     * not a JSON object.
     *
     * - `ip`: the address that asked for the QR, or null.
     * - `location`: from that address (GeoIP): `city`, `country`, `countryCode`, or null.
     * - `device`: from the User-Agent: `browser`, `os`, `model`, or null.
     * - `requestedAt`: when the QR was asked for (ISO 8601), as Touchque sent it.
     * - `farFromPhone`: whether that place is far from whoever called validate (the
     *   phone, on the phone's call; your server, on yours); null when unknown.
     *
     * @param mixed $raw the answer's `setupContext`, as decoded from JSON
     * @return array{
     *     ip: string|null,
     *     location: array{city: string|null, country: string|null, countryCode: string|null}|null,
     *     device: array{browser: string|null, os: string|null, model: string|null}|null,
     *     requestedAt: string|null,
     *     farFromPhone: bool|null,
     * }|null
     */
    public static function parseSetupContext($raw): ?array
    {
        $context = self::jsonObject($raw);
        if ($context === null) {
            return null;
        }
        $location = self::jsonObject($context['location'] ?? null);
        $device = self::jsonObject($context['device'] ?? null);
        return [
            'ip' => self::stringField($context, 'ip'),
            'location' => $location === null ? null : [
                'city' => self::stringField($location, 'city'),
                'country' => self::stringField($location, 'country'),
                'countryCode' => self::stringField($location, 'countryCode'),
            ],
            'device' => $device === null ? null : [
                'browser' => self::stringField($device, 'browser'),
                'os' => self::stringField($device, 'os'),
                'model' => self::stringField($device, 'model'),
            ],
            'requestedAt' => self::stringField($context, 'requestedAt'),
            'farFromPhone' => is_bool($context['farFromPhone'] ?? null) ? $context['farFromPhone'] : null,
        ];
    }

    /**
     * A decoded JSON object, else null. json_decode() gives `{}` and `[]` alike as an
     * empty array, which counts as an object; a list with items does not.
     *
     * @param mixed $value
     */
    private static function jsonObject($value): ?array
    {
        if (!is_array($value)) {
            return null;
        }
        if ($value !== [] && array_keys($value) === range(0, count($value) - 1)) {
            return null;
        }
        return $value;
    }

    private static function stringField(array $object, string $key): ?string
    {
        $value = $object[$key] ?? null;
        return is_string($value) ? $value : null;
    }

    /**
     * Look up a user's link status without sending a push — `used` flips true
     * and `deviceId` is set once the mobile app scans the setup secret.
     * Returns `{ externalUsername, deviceId, used, frozen, createdAt, expireAt, device }`.
     * Throws TouchqueAPIException (404) if the user is unknown.
     *
     * `device` is the linked phone's posture for device trust, or `null` before a phone is linked:
     * `{ platform ('ios'|'android'|null), model, osVersion, securityPatch (Android, YYYY-MM-DD),
     * appVersion, screenLock, biometrics, jailbroken, compromised, hardwareKey,
     * attestation ('apple-appattest'|'android-key'|null), signed (the latest report was signed by the
     * phone's hardware key), reportedAt, lastSeenAt, linkedAt,
     * state ('healthy'|'at_risk'|'compromised'|'unknown'), issues (string[]: jailbroken, tampered,
     * integrity_failed, no_report, stale_report, no_screen_lock, keys_lost, no_hardware_key, debugger,
     * developer_mode) }`. It is self-reported by the app.
     *
     * @return array{
     *     externalUsername: string,
     *     deviceId: string|null,
     *     used: bool,
     *     frozen: bool,
     *     createdAt: string,
     *     expireAt: string|null,
     *     device: array{
     *         platform: 'ios'|'android'|null,
     *         model?: string|null,
     *         osVersion: string|null,
     *         securityPatch?: string|null,
     *         appVersion: string|null,
     *         screenLock: bool|null,
     *         biometrics?: 'face'|'touch'|'fingerprint'|'iris'|'none'|null,
     *         jailbroken: bool,
     *         compromised: bool,
     *         hardwareKey: bool,
     *         attestation: 'apple-appattest'|'android-key'|null,
     *         signed: bool,
     *         reportedAt: string|null,
     *         lastSeenAt: string|null,
     *         linkedAt?: string|null,
     *         state: 'healthy'|'at_risk'|'compromised'|'unknown',
     *         issues: string[],
     *     }|null,
     * }
     */
    public function getUser(string $externalUsername): array
    {
        return $this->http->get('/users/' . rawurlencode($externalUsername));
    }
}
