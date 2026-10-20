<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;
use TouchQue\Exceptions\TouchQueTimeoutException;
use TouchQue\Exceptions\TouchQueRejectedException;
use TouchQue\Exceptions\TouchQuePasskeyRequiredError;
use TouchQue\Exceptions\TouchQueConfigException;

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
     *
     * `$browserProof` (silent sign-ins): the browser's device-bound key proof,
     * exactly as the browser sent it (`X-TouchQue-Browser` header, made by
     * `@touchque/web` with `browserKey: true`). When the user approves this
     * request on the phone (or with a passkey), TouchQue remembers the
     * browser, so a later `$tq->risk->check()` can let the same browser in
     * without asking. Pass it through untouched; an invalid proof only means
     * "a browser TouchQue does not know".
     */
    public function request(
        string $externalUsername,
        string $type = 'LOGIN',
        ?string $referenceId = null,
        ?string $clientIp = null,
        ?string $userAgent = null,
        bool $requireBiometric = false,
        bool $requireNumberMatch = false,
        ?array $details = null,
        ?string $browserProof = null,
        ?array $context = null
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
        if ($browserProof !== null && $browserProof !== '') {
            $payload['browserProof'] = $browserProof;
        }
        // For your TouchQue Actions only (event.context); never shown on the phone.
        if ($context !== null && count($context) > 0) {
            $payload['context'] = $context;
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
     * With number matching (your `$requireNumberMatch`, a workspace policy or the
     * risk engine can turn it on) the user must pick a number on the phone.
     * `$onChallenge` is called once, right after the request is created and before
     * any waiting, with `['requestId', 'challengeCode', 'expiresAt', 'reasons',
     * 'caseCode']`: show `challengeCode` to the user now; the phone asks for it. An
     * exception it throws is logged and ignored (verify keeps waiting). It is not
     * called when only a passkey can approve.
     *
     *     $tq->login->verify($user, 'SEND_MONEY', null, 30000, $ip, $ua, false, false, null, null,
     *         function (array $c) { if (isset($c['challengeCode'])) show("Pick {$c['challengeCode']} on your phone"); });
     *     // PHP 8: verify($user, 'SEND_MONEY', onChallenge: function (array $c) { ... })
     *
     * @throws TouchQuePasskeyRequiredError when a phishing-resistant policy
     *   requires the request to be approved with a passkey (no push sent, `reason` policy), or the user
     *   tapped Approve during a call and the request now waits for a passkey (`reason` step_up).
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
        ?array $details = null,
        ?string $browserProof = null,
        ?callable $onChallenge = null,
        ?array $context = null
    ): array {
        $requestResult = $this->request($externalUsername, $type, $referenceId, $clientIp, $userAgent, $requireBiometric, $requireNumberMatch, $details, $browserProof, $context);
        $requestId = $requestResult['requestId'];
        if (!empty($requestResult['requiresPasskey'])) {
            throw new TouchQuePasskeyRequiredError($requestId);
        }

        // The number to show, before waiting: the phone asks the user for it.
        if ($onChallenge !== null) {
            $challenge = ['requestId' => $requestId, 'expiresAt' => $requestResult['expiresAt'] ?? null];
            foreach (['challengeCode', 'reasons', 'caseCode'] as $key) {
                if (!empty($requestResult[$key])) {
                    $challenge[$key] = $requestResult[$key];
                }
            }
            try {
                $onChallenge($challenge);
            } catch (\Throwable $e) {
                // The caller's callback must not stop the wait.
                error_log('[TouchQue] onChallenge failed: ' . $e->getMessage());
            }
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
                    // Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
                    'provisional' => !empty($statusResult['provisional']),
                ];
            }

            if ($status === 'REJECTED') {
                throw new TouchQueRejectedException("Request $requestId was rejected by the user.");
            }

            if ($status === 'EXPIRED') {
                throw new TouchQueTimeoutException("Request $requestId expired before it was approved.");
            }

            // Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if ($status === 'PENDING' && !empty($statusResult['requiresPasskey'])) {
                throw new TouchQuePasskeyRequiredError($requestId, 'step_up');
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

    /** Reasons accepted by reportFraud(). */
    public const FRAUD_REASONS = ['chargeback', 'account_takeover', 'social_engineering', 'other'];

    /**
     * Reports a request you later learned was fraud — a chargeback, a
     * confirmed account takeover, a scam the user was talked into. TouchQue's
     * risk engine learns from it (it is the strongest signal it gets) and the
     * report is kept in your audit log. The request's status does not change.
     * Safe to call more than once: a repeat answers `alreadyReported => true`.
     *
     * @param string|null $reason one of self::FRAUD_REASONS (default 'other')
     * @param string|null $note   free text for your audit log, at most 500 characters
     * @return array{reported: bool, alreadyReported: bool, requestId: string}
     */
    public function reportFraud(string $requestId, ?string $reason = null, ?string $note = null): array
    {
        if ($requestId === '') {
            throw new TouchQueConfigException('reportFraud() needs the request id');
        }
        $payload = [];
        if ($reason !== null && $reason !== '') {
            $payload['reason'] = $reason;
        }
        if ($note !== null && $note !== '') {
            $payload['note'] = $note;
        }
        return $this->http->post('/login/' . rawurlencode($requestId) . '/report-fraud', $payload);
    }
}
