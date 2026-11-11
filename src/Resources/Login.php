<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;
use Touchque\Exceptions\TouchqueTimeoutException;
use Touchque\Exceptions\TouchqueRejectedException;
use Touchque\Exceptions\TouchquePasskeyRequiredError;
use Touchque\Exceptions\TouchqueConfigException;

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
     * exactly as the browser sent it (`X-Touchque-Browser` header, made by
     * `@touchque/web` with `browserKey: true`). When the user approves this
     * request on the phone (or with a passkey), Touchque remembers the
     * browser, so a later `$tq->risk->check()` can let the same browser in
     * without asking. Pass it through untouched; an invalid proof only means
     * "a browser Touchque does not know".
     *
     * `$securityChanges`: when the user's sign-in security last changed in your
     * system, ['password' | 'mfa' | 'device' | 'email' | 'phone' => DateTimeInterface,
     * ISO 8601 string or epoch milliseconds]. Touchque adds what it saw itself;
     * access rules and Actions read the minutes since each
     * (`minutesSince.mfaChange`, `.deviceChange`, ...), e.g. refuse
     * `PAYOUT_CHANGE` within 24 hours of a 2FA change.
     *
     * `$destination`: where the action sends money or value,
     * ['kind' => 'iban' | 'account' | 'wallet' | 'address' | 'payee', 'value' => ..., 'known' => [...]].
     * The phone shows it in full in groups of four, with a warning when it
     * looks like one the user used before but is not the same; the answer's
     * `destination` is ['known' => bool, 'lookalike' => [...]]. Do not repeat
     * it in `$details`. `$locale` ('tr' default, or 'en') is the language of those rows.
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
        ?array $context = null,
        ?int $challengeDigits = null,
        ?int $expiresIn = null,
        ?string $clientSignals = null,
        ?array $securityChanges = null,
        ?array $destination = null,
        ?string $locale = null,
        ?string $qrPairing = null,
        ?string $deviceRisk = null,
        ?string $deviceRiskRequestId = null,
        ?array $reply = null
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
        if ($challengeDigits === 2 || $challengeDigits === 3) {
            $payload['challengeDigits'] = $challengeDigits;
        }
        // How long the push waits for the person: 30 (default) to 300 seconds.
        if ($expiresIn !== null) {
            $payload['expiresIn'] = $expiresIn;
        }
        // A browser pairing by QR code ($tq->qrPairings), confirmed on the phone: only that phone is asked, once.
        if ($qrPairing !== null && $qrPairing !== '') {
            $payload['qrPairing'] = $qrPairing;
        }
        // Ask the person to type back on the phone a sign-in code another service sent them:
        // ['kind' => 'code', 'key' => CodeReply::newKey()['publicKey'], 'channel' => 'sms', 'target' => '+**********26'].
        // status()['reply']['ct'] holds only the ciphertext: \Touchque\CodeReply::open() opens it. Not with $qrPairing.
        if ($reply !== null) {
            $payload['reply'] = $reply;
        }
        // The end user's page check from @touchque/web: a browser driven by software asks with number matching.
        if ($clientSignals !== null && $clientSignals !== '') {
            $payload['clientSignals'] = $clientSignals;
        }
        // The page's device report from @touchque/web (deviceRisk.collect), when the workspace turned Device risk on:
        // its signals only ever ask for more.
        if ($deviceRisk !== null && $deviceRisk !== '') {
            $payload['deviceRisk'] = $deviceRisk;
        }
        // Or the page's identification (deviceRisk.identify), for this account only.
        if ($deviceRiskRequestId !== null && $deviceRiskRequestId !== '') {
            $payload['deviceRiskRequestId'] = $deviceRiskRequestId;
        }
        if ($details !== null && count($details) > 0) {
            $payload['details'] = $details;
        }
        if ($browserProof !== null && $browserProof !== '') {
            $payload['browserProof'] = $browserProof;
        }
        // For your Touchque Actions only (event.context); never shown on the phone.
        if ($context !== null && count($context) > 0) {
            $payload['context'] = $context;
        }
        if ($securityChanges !== null && count($securityChanges) > 0) {
            $payload['securityChanges'] = self::securityChangesBody($securityChanges);
        }
        if ($destination !== null && count($destination) > 0) {
            $payload['destination'] = $destination;
        }
        if ($locale !== null && $locale !== '') {
            $payload['locale'] = $locale;
        }

        return $this->http->post('/login/request', $payload);
    }

    /** Dates go out as ISO 8601; strings and epoch milliseconds as given. */
    private static function securityChangesBody(array $changes): array
    {
        $out = [];
        foreach ($changes as $kind => $at) {
            if ($at === null) {
                continue;
            }
            $out[$kind] = $at instanceof \DateTimeInterface ? $at->format(\DateTimeInterface::ATOM) : $at;
        }
        return $out;
    }

    /**
     * Check the current status of a login request.
     */
    public function status(string $requestId): array
    {
        return $this->http->get('/login/status/' . rawurlencode($requestId));
    }

    /**
     * Wait (poll) until the user approves or rejects a request you sent with
     * `request()`: `verify()` without the request, for when you show the
     * number (`challengeCode`) or store the request id first. Mirrors the
     * Node SDK's `login.waitForApproval`.
     *
     *     $sent = $tq->login->request($user, 'SEND_MONEY');
     *     show($sent['challengeCode'] ?? null);
     *     $result = $tq->login->waitForApproval($sent['requestId'], 30000);
     *
     * @return array{approved: bool, status: string, requestId: string, assurance: ?string, confirmedVia: ?string, provisional: bool}
     * @throws TouchquePasskeyRequiredError when the user tapped Approve during a call and the
     *   request now waits for a passkey (`reason` step_up).
     * @throws TouchqueRejectedException when the user rejects it.
     * @throws TouchqueTimeoutException when it expired or `$timeoutMs` (default 30 seconds) ran out.
     */
    public function waitForApproval(string $requestId, int $timeoutMs = 30000, int $pollIntervalMs = 400): array
    {
        if ($requestId === '') {
            throw new TouchqueConfigException('waitForApproval() needs the request id');
        }
        $start = microtime(true);
        while (true) {
            $statusResult = $this->status($requestId);
            $status = $statusResult['status'] ?? null;
            if ($status === 'CONFIRMED') {
                return [
                    'approved' => true,
                    'status' => $status,
                    'requestId' => $requestId,
                    'assurance' => $statusResult['assurance'] ?? null,
                    'confirmedVia' => $statusResult['confirmedVia'] ?? null,
                    // Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
                    'provisional' => !empty($statusResult['provisional']),
                ];
            }
            if ($status === 'REJECTED') {
                throw new TouchqueRejectedException("Request $requestId was rejected by the user.");
            }
            if ($status === 'EXPIRED') {
                throw new TouchqueTimeoutException("Request $requestId expired before it was approved.");
            }
            // Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if ($status === 'PENDING' && !empty($statusResult['requiresPasskey'])) {
                throw new TouchquePasskeyRequiredError($requestId, 'step_up');
            }
            if ((microtime(true) - $start) * 1000 > $timeoutMs) {
                throw new TouchqueTimeoutException("Request $requestId was not approved within {$timeoutMs}ms");
            }
            usleep(max(0, $pollIntervalMs) * 1000);
        }
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
     * @throws TouchquePasskeyRequiredError when a phishing-resistant policy
     *   requires the request to be approved with a passkey (no push sent, `reason` policy), or the user
     *   tapped Approve during a call and the request now waits for a passkey (`reason` step_up).
     * @throws TouchqueRejectedException when the user rejects it.
     * @throws TouchqueTimeoutException on timeout or expiry.
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
        ?array $context = null,
        ?int $challengeDigits = null,
        ?array $securityChanges = null,
        ?array $destination = null,
        ?string $locale = null
    ): array {
        $requestResult = $this->request($externalUsername, $type, $referenceId, $clientIp, $userAgent, $requireBiometric, $requireNumberMatch, $details, $browserProof, $context, $challengeDigits, null, null, $securityChanges, $destination, $locale);
        $requestId = $requestResult['requestId'];
        if (!empty($requestResult['requiresPasskey'])) {
            throw new TouchquePasskeyRequiredError($requestId);
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
                $this->http->log('warning', '[Touchque] onChallenge failed: ' . \Touchque\Config::describe($e));
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
                throw new TouchqueRejectedException("Request $requestId was rejected by the user.");
            }

            if ($status === 'EXPIRED') {
                throw new TouchqueTimeoutException("Request $requestId expired before it was approved.");
            }

            // Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if ($status === 'PENDING' && !empty($statusResult['requiresPasskey'])) {
                throw new TouchquePasskeyRequiredError($requestId, 'step_up');
            }

            $elapsed = (microtime(true) * 1000) - $startTime;
            if ($elapsed > $timeoutMs) {
                throw new TouchqueTimeoutException("Login verification timed out after {$timeoutMs}ms");
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
     * form post) throws TouchqueAPIException with error code "already_used" (409).
     */
    public function consume(string $requestId): array
    {
        return $this->http->post('/login/' . rawurlencode($requestId) . '/consume', []);
    }

    /** Reasons accepted by reportFraud(). */
    public const FRAUD_REASONS = ['chargeback', 'account_takeover', 'social_engineering', 'other'];

    /**
     * Reports a request you later learned was fraud — a chargeback, a
     * confirmed account takeover, a scam the user was talked into. Touchque's
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
            throw new TouchqueConfigException('reportFraud() needs the request id');
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
