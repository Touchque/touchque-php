<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;

class Auth
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Generate a new setup secret for a user.
     */
    public function generateSecret(string $externalUsername): array
    {
        return $this->http->post('/auth/generate-secret', [
            'externalUsername' => $externalUsername
        ]);
    }


    /**
     * Reset (regenerate) a user's secret.
     */
    public function resetSecret(string $externalUsername): array
    {
        return $this->http->post('/auth/secret/reset', [
            'externalUsername' => $externalUsername
        ]);
    }

    /**
     * Validate a setup secret code.
     * Mirrors the Node/Python/Go SDKs' `validateSecret`/`validate_secret`/`ValidateSecret`.
     */
    public function validateSecret(string $secret): array
    {
        return $this->http->post('/auth/secret/validate', [
            'secret' => $secret
        ]);
    }

    /**
     * Look up a user's link status without sending a push — `used` flips true
     * and `deviceId` is set once the mobile app scans the setup secret.
     * Returns `{ externalUsername, deviceId, used, frozen, createdAt, expireAt, device }`.
     * Throws TouchQueAPIException (404) if the user is unknown.
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
