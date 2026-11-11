<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;
use Touchque\Exceptions\TouchqueConfigException;

/**
 * Touchque Mobile SDK, your backend's side: your own iOS/Android app is the
 * approver of your users (white-label); they never install the Touchque app.
 *
 * 1. A user signed in to your app turns approvals on: `createEnrollment()`
 *    gives a one-time token; your app hands it to the SDK (`Touchque.enroll`).
 * 2. Ask for approvals as always (`$tq->login->request()`, `start()`, the
 *    middleware...): they reach your app over the SDK's encrypted connection.
 * 3. Touchque holds no push key of your app. For each request it sends you a
 *    signed MOBILE_PUSH webhook: verify it (`$tq->webhook`), then
 *    `Mobile::pushFromWebhook($event)` gives the APNs payload / FCM data to
 *    send with your own credentials.
 *
 *     $e = $tq->mobile->createEnrollment(['externalUsername' => $userId]);
 *     return ['enrollmentToken' => $e['enrollmentToken']];   // the app calls Touchque.enroll(token)
 */
class Mobile
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * A one-time enrollment token for a user you signed in. Whoever spends it
     * becomes the user's approver, so authenticate the user first. Throws
     * TouchqueAPIException `already_enrolled` (pass `replace => true`) or `account_frozen`.
     *
     * @param array $options externalUsername (required), replace, ttlSeconds
     */
    public function createEnrollment(array $options): array
    {
        if (empty($options['externalUsername'])) {
            throw new TouchqueConfigException('mobile->createEnrollment() needs the user (externalUsername)');
        }
        $body = ['externalUsername' => $options['externalUsername']];
        if (!empty($options['replace'])) {
            $body['replace'] = true;
        }
        if (isset($options['ttlSeconds'])) {
            $body['ttlSeconds'] = (int) $options['ttlSeconds'];
        }
        return $this->http->post('/mobile/enrollments', $body);
    }

    /**
     * The devices inside your app (default: active ones), newest first: ['devices' => [...], 'nextCursor' => ?string].
     *
     * @param array $options externalUsername, status (active | revoked | all), limit, cursor
     */
    public function listDevices(array $options = []): array
    {
        $params = array_filter(
            array_intersect_key($options, array_flip(['externalUsername', 'status', 'limit', 'cursor'])),
            static fn ($v) => $v !== null && $v !== ''
        );
        return $this->http->get('/mobile/devices', $params);
    }

    public function getDevice(string $deviceId): array
    {
        if ($deviceId === '') {
            throw new TouchqueConfigException('mobile->getDevice() needs the device id');
        }
        return $this->http->get('/mobile/devices/' . rawurlencode($deviceId))['device'];
    }

    /** Stops a device from approving (the user has no approver until you enrol again). */
    public function removeDevice(string $deviceId): array
    {
        if ($deviceId === '') {
            throw new TouchqueConfigException('mobile->removeDevice() needs the device id');
        }
        return $this->http->delete('/mobile/devices/' . rawurlencode($deviceId));
    }

    /**
     * A harmless push to the device, the way a request would reach it: via 'touchque' (your key for its
     * platform) or 'webhook' (MOBILE_PUSH, kind 'test'); ok: APNs / FCM accepted it.
     */
    public function testPush(string $deviceId): array
    {
        if ($deviceId === '') {
            throw new TouchqueConfigException('mobile->testPush() needs the device id');
        }
        return $this->http->post('/mobile/devices/' . rawurlencode($deviceId) . '/test-push', []);
    }

    public function settings(): array
    {
        return $this->http->get('/mobile/settings')['settings'];
    }

    /**
     * Which apps may enrol, whether they must prove themselves, and your push keys. Only the keys given change.
     *
     * @param array $changes iosAppIds, androidPackages, androidCerts ([package => [SHA-256 of its signing
     *                       certificate]]), attestation (off | optional | required), enrollTtlSeconds,
     *                       apns (['keyId', 'teamId', 'topic', 'key' => the .p8 text, 'production']: Touchque then
     *                       sends the iOS push itself), fcm (['serviceAccount' => the JSON]: the Android push);
     *                       null removes a key. The keys are never shown back (settings()['push']).
     */
    public function updateSettings(array $changes): array
    {
        $unknown = array_diff(array_keys($changes), ['iosAppIds', 'androidPackages', 'androidCerts', 'attestation', 'enrollTtlSeconds', 'apns', 'fcm']);
        if ($unknown) {
            throw new TouchqueConfigException('mobile->updateSettings(): unknown setting ' . implode(', ', $unknown));
        }
        return $this->http->put('/mobile/settings', $changes)['settings'];
    }

    /**
     * The push to send for a verified MOBILE_PUSH webhook, or null for any other
     * event: deviceId, externalUsername, platform, pushToken (null: send by your
     * own user → device mapping), requestId, expiresAt, kind, alert (English,
     * translate it), apns (the APNs payload: alert + the custom key `touchque`)
     * and fcmData (the FCM data map). No secret, no details, no number.
     */
    public static function pushFromWebhook(?array $event): ?array
    {
        if (!$event || ($event['event'] ?? null) !== 'MOBILE_PUSH') {
            return null;
        }
        $data = $event['data'] ?? [];
        $touchque = is_string($data['touchque'] ?? null) ? $data['touchque'] : json_encode($data['touchque'] ?? new \stdClass());
        $alert = $event['alert'] ?? null;
        $aps = ['sound' => 'default', 'interruption-level' => 'time-sensitive'];
        if ($alert) {
            $aps['alert'] = $alert;
        }
        return [
            'deviceId' => $event['deviceId'] ?? null,
            'externalUsername' => $event['externalUsername'] ?? null,
            'platform' => ($event['platform'] ?? '') === 'android' ? 'android' : 'ios',
            'pushToken' => is_string($event['pushToken'] ?? null) ? $event['pushToken'] : null,
            'requestId' => $event['requestId'] ?? null,
            'expiresAt' => $event['expiresAt'] ?? null,
            // test: a test push sent from the dashboard
            'kind' => in_array($event['kind'] ?? '', ['notice', 'test'], true) ? $event['kind'] : 'approval',
            'alert' => $alert,
            'apns' => ['aps' => $aps, 'touchque' => $touchque],
            'fcmData' => ['touchque' => $touchque],
        ];
    }

    /** True once a push is past its request's expiry (don't send it any more). */
    public static function isPushExpired(array $push, ?\DateTimeInterface $now = null): bool
    {
        if (empty($push['expiresAt'])) {
            return false;
        }
        $now = $now ?? new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        return new \DateTimeImmutable($push['expiresAt']) <= $now;
    }
}
