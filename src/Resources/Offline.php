<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;
use Touchque\Exceptions\TouchqueAPIException;

/** Offline Sign — QR challenge / typed code approvals that work with the
 * phone offline (no internet on the device). */
class Offline
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Issues an offline QR challenge. Returns
     * `{ challengeId, qr, qrDataUrl, expiresAt, expiresInSeconds, totpAvailable }`
     * (+ `challengeCode` when number matching applies: print it under the QR; the phone
     * offers it among two decoys and the user taps the match).
     * `$details` is REQUIRED for critical action types.
     *
     * `$requestId` is the push this QR is a fallback for: once the phone REJECTS it the QR is
     * dead (no new QR is issued, a code for the old one is refused with `request_rejected`), and a
     * push with number matching makes the QR show the same number. Always pass it when the QR
     * follows a push.
     */
    public function challenge(
        string $externalUsername,
        string $type = 'LOGIN',
        ?array $details = null,
        ?string $clientIp = null,
        ?string $userAgent = null,
        ?int $ttlSeconds = null,
        bool $includeQrImage = true,
        ?string $requestId = null,
        bool $requireNumberMatch = false
    ): array {
        $body = ['externalUsername' => $externalUsername, 'type' => $type];
        if ($details !== null) {
            $body['details'] = $details;
        }
        if ($clientIp !== null) {
            $body['clientIp'] = $clientIp;
        }
        if ($userAgent !== null) {
            $body['userAgent'] = $userAgent;
        }
        if ($ttlSeconds !== null) {
            $body['ttlSeconds'] = $ttlSeconds;
        }
        if (!$includeQrImage) {
            $body['includeQrImage'] = false;
        }
        if ($requestId !== null) {
            $body['requestId'] = $requestId;
        }
        if ($requireNumberMatch) {
            $body['requireNumberMatch'] = true;
        }
        return $this->http->post('/offline/challenge', $body);
    }

    /**
     * Verifies the 7-character code shown on the phone. Never throws for a
     * wrong/expired/used code — check `approved`; `reason` is one of
     * invalid_code | locked | expired | used | unknown_challenge |
     * request_rejected | too_many_failures | device_not_enrolled.
     */
    public function verify(string $challengeId, string $code): array
    {
        return $this->notApprovedAsResult(fn () => $this->http->post('/offline/verify', [
            'challengeId' => $challengeId,
            'code' => $code,
        ]));
    }

    /**
     * Verifies the rolling time-based code (no QR scan needed). Refused for critical action types.
     * `$requestId`: the push this sign-in belongs to — a code is refused (`request_rejected`) once the phone rejected it.
     */
    public function verifyTotp(string $externalUsername, string $code, string $type = 'LOGIN', ?string $clientIp = null, ?string $requestId = null): array
    {
        $body = ['externalUsername' => $externalUsername, 'code' => $code, 'type' => $type];
        if ($clientIp !== null) {
            $body['clientIp'] = $clientIp;
        }
        if ($requestId !== null) {
            $body['requestId'] = $requestId;
        }
        return $this->notApprovedAsResult(fn () => $this->http->post('/offline/totp/verify', $body));
    }

    /**
     * For checking typed time-based codes while your server cannot reach Touchque (an outage):
     * salted, slow digests of each user's next codes, never a key. Up to 1,000 users and 24,000 user-steps a call; `$steps` 1-480
     * (default 480, four hours) from `$fromStep` (default: the current 30-second step). Returns
     * `{ stepSeconds, fromStep, steps, notAfterStep, kdf, users: [{ externalUsername, fromStep, salt, digests }] }`
     * with only the users who can use time-based codes now. Check a typed code with
     * `matchTotpVerifier()`. Requires the workspace policies `offlineTotpEnabled` and
     * `outageVerifiersEnabled`. Fetch again every few minutes: removed and frozen users fall out.
     */
    public function totpVerifiers(array $externalUsernames, ?int $fromStep = null, ?int $steps = null): array
    {
        $body = ['externalUsernames' => array_values($externalUsernames)];
        if ($fromStep !== null) {
            $body['fromStep'] = $fromStep;
        }
        if ($steps !== null) {
            $body['steps'] = $steps;
        }
        return $this->http->post('/offline/totp/verifiers', $body);
    }

    /**
     * Checks a typed code against one user's digests from `totpVerifiers()` without calling
     * Touchque. Returns the step the code belongs to (the current one or one either side), or
     * null. Accept each step once: remember the step you accepted for the user and refuse codes
     * for it or an older one. `$at`: Unix time (default now).
     */
    public static function matchTotpVerifier(array $verifiers, array $user, string $code, ?int $at = null): ?int
    {
        $given = str_replace([' ', '-', "\t"], '', strtoupper($code));
        if (strlen($given) !== 7 || strspn($given, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') !== 7) {
            return null;
        }
        $now = intdiv($at ?? time(), (int) $verifiers['stepSeconds']);
        $salt = base64_decode($user['salt'], true);
        if ($salt === false) {
            return null;
        }
        $digests = base64_decode($user['digests'], true);
        $length = (int) $verifiers['kdf']['length'];
        if ($digests === false || $length <= 0) {
            return null;
        }
        foreach ([$now, $now - 1, $now + 1] as $step) {
            if ($step < $user['fromStep'] || $step > $verifiers['notAfterStep']) {
                continue;
            }
            $i = ($step - $user['fromStep']) * 2 * $length;
            if ($i + 2 * $length > strlen($digests)) {
                continue;
            }
            $got = hash_pbkdf2('sha256', $given, $salt . ':' . $step, (int) $verifiers['kdf']['iterations'], $length, true);
            if (hash_equals(substr($digests, $i, $length), $got) || hash_equals(substr($digests, $i + $length, $length), $got)) {
                return $step;
            }
        }
        return null;
    }

    private function notApprovedAsResult(callable $call): array
    {
        try {
            return $call();
        } catch (TouchqueAPIException $err) {
            if ($err->getStatus() < 500) {
                return [
                    'approved' => false,
                    'reason' => $err->getReason() ?? $err->getErrorCode() ?? ($err->getData()['error'] ?? null),
                    'attemptsLeft' => $err->getAttemptsLeft(),
                ];
            }
            throw $err;
        }
    }
}
