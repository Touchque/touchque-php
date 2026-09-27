<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;
use TouchQue\Exceptions\TouchQueTimeoutException;
use TouchQue\Exceptions\TouchQueRejectedException;
use TouchQue\Exceptions\TouchQuePasskeyRequiredError;

class Login
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Request a 2FA login/approval from the user's mobile device.
     *
     * When the integration has behavioral biometrics enabled
     * (`TenantPolicy.behavioralBiometricsEnabled`), the response also contains
     * `telemetryToken` — pass it plus `requestId` to your frontend to
     * initialize the `@touchque/web` behavioral widget
     * (`tq.behavioral.attach(...)`). There is no widget in this server SDK.
     *
     * `$details` is transaction context shown on the approval screen, e.g.
     * ['Amount' => '1,250.00 USD', 'Recipient' => 'Jane Doe'] (shown in
     * order), or a list of ['label' => ..., 'value' => ...]. At most 8
     * entries, labels <= 40 and values <= 120 characters; the API rejects
     * (never truncates) anything outside those limits. Build it from
     * server-side state, never from browser input.
     */
    public function request(
        string $externalUsername,
        string $type = 'LOGIN',
        ?string $referenceId = null,
        ?string $clientIp = null,
        ?string $userAgent = null,
        bool $requireBiometric = false,
        bool $requireNumberMatch = false,
        ?array $details = null
    ): array {
        $payload = [
            'externalUsername' => $externalUsername,
            'type' => $type
        ];

        if ($referenceId !== null) {
            $payload['referenceId'] = $referenceId;
        }
        if ($clientIp !== null) {
            $payload['clientIp'] = $clientIp;
        }
        if ($userAgent !== null) {
            $payload['userAgent'] = $userAgent;
        }
        if ($requireBiometric) {
            $payload['requireBiometric'] = true;
        }
        if ($requireNumberMatch) {
            $payload['requireNumberMatch'] = true;
        }
        if ($details !== null && count($details) > 0) {
            $payload['details'] = $details;
        }

        return $this->http->post('/login/request', $payload);
    }

    /**
     * Check the current status of a login request.
     */
    public function status(string $requestId): array
    {
        return $this->http->get('/login/status/' . rawurlencode($requestId));
    }

    /**
     * Request a login and wait (poll) until the user approves or rejects it.
     *
     * @throws TouchQuePasskeyRequiredError when a phishing-resistant policy
     *   requires the request to be approved with a passkey (no push sent).
     * @throws TouchQueRejectedException when the user rejects it.
     * @throws TouchQueTimeoutException on timeout or expiry.
     */
    public function verify(
        string $externalUsername,
        string $type = 'LOGIN',
        ?string $referenceId = null,
        int $timeoutMs = 30000,
        ?string $clientIp = null,
        ?string $userAgent = null,
        bool $requireBiometric = false,
        bool $requireNumberMatch = false,
        ?array $details = null
    ): array {
        $requestResult = $this->request($externalUsername, $type, $referenceId, $clientIp, $userAgent, $requireBiometric, $requireNumberMatch, $details);
        $requestId = $requestResult['requestId'];
        if (!empty($requestResult['requiresPasskey'])) {
            throw new TouchQuePasskeyRequiredError($requestId);
        }

        $startTime = microtime(true) * 1000;
        $pollInterval = 400;

        while (true) {
            $statusResult = $this->status($requestId);
            $status = $statusResult['status'];

            if ($status === 'CONFIRMED') {
                return [
                    'approved' => true,
                    'status' => $status,
                    'requestId' => $requestId,
                    'challengeCode' => $requestResult['challengeCode'] ?? null,
                    'assurance' => $statusResult['assurance'] ?? null,
                    'confirmedVia' => $statusResult['confirmedVia'] ?? null,
                ];
            }

            if ($status === 'REJECTED') {
                throw new TouchQueRejectedException("Request $requestId was rejected by the user.");
            }

            if ($status === 'EXPIRED') {
                throw new TouchQueTimeoutException("Request $requestId expired before it was approved.");
            }

            $elapsed = (microtime(true) * 1000) - $startTime;
            if ($elapsed > $timeoutMs) {
                throw new TouchQueTimeoutException("Login verification timed out after {$timeoutMs}ms");
            }

            usleep($pollInterval * 1000); // usleep takes microseconds
        }
    }

    /**
     * Approve a pending 2FA request using a Recovery Code (bypasses mobile device).
     * Mirrors the Node/Python/Go SDKs' `approveWithRecoveryCode`/`approve_with_recovery_code`/`ApproveWithRecoveryCode`.
     */
    public function approveWithRecoveryCode(string $requestId, string $code): array
    {
        return $this->http->post('/login/recovery', [
            'requestId' => $requestId,
            'code' => $code
        ]);
    }

    /**
     * Uses an approved request exactly once. The first call on a CONFIRMED
     * request wins atomically; every later call (a replayed token, a retried
     * form post) throws TouchQueAPIException with error code "already_used" (409).
     */
    public function consume(string $requestId): array
    {
        return $this->http->post('/login/' . rawurlencode($requestId) . '/consume', []);
    }
}
