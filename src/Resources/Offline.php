<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;
use TouchQue\Exceptions\TouchQueAPIException;

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
     * `{ challengeId, qr, qrDataUrl, expiresAt, expiresInSeconds, totpAvailable }`.
     * `$details` is REQUIRED for critical action types.
     */
    public function challenge(
        string $externalUsername,
        string $type = 'LOGIN',
        ?array $details = null,
        ?string $clientIp = null,
        ?string $userAgent = null,
        ?int $ttlSeconds = null,
        bool $includeQrImage = true
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
        return $this->http->post('/offline/challenge', $body);
    }

    /**
     * Verifies the 7-character code shown on the phone. Never throws for a
     * wrong/expired/used code — check `approved`; `reason` is one of
     * invalid_code | locked | expired | used | unknown_challenge |
     * too_many_failures | device_not_enrolled.
     */
    public function verify(string $challengeId, string $code): array
    {
        return $this->notApprovedAsResult(fn () => $this->http->post('/offline/verify', [
            'challengeId' => $challengeId,
            'code' => $code,
        ]));
    }

    /** Verifies the rolling time-based code (no QR scan needed). Refused for critical action types. */
    public function verifyTotp(string $externalUsername, string $code, string $type = 'LOGIN', ?string $clientIp = null): array
    {
        $body = ['externalUsername' => $externalUsername, 'code' => $code, 'type' => $type];
        if ($clientIp !== null) {
            $body['clientIp'] = $clientIp;
        }
        return $this->notApprovedAsResult(fn () => $this->http->post('/offline/totp/verify', $body));
    }

    private function notApprovedAsResult(callable $call): array
    {
        try {
            return $call();
        } catch (TouchQueAPIException $err) {
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
