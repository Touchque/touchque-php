<?php

namespace TouchQue\Relay;

use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQuePasskeyRequiredError;
use TouchQue\Exceptions\TouchQueRejectedException;
use TouchQue\Exceptions\TouchQueTimeoutException;
use TouchQue\Guard;
use TouchQue\TouchQue;

/**
 * Framework-agnostic relay: the routes a frontend (`@touchque/web`) needs for
 * classic push 2FA, offline codes and passkeys, so you don't hand-write them.
 * Same routes and behaviour as the Node SDK's `touchqueRouter`. For Laravel
 * use `TouchQue\Laravel\TouchQueRelay`; anywhere else call handle() with the
 * path relative to where you mount it and send the RelayResponse.
 *
 *   POST   /enroll/start                    (auth required) -> generateSecret response
 *   GET    /enroll/status                   (auth required) -> { linked, used, deviceId }
 *   POST   /login                           (pre-auth) -> 202 { touchque: step, token } until approved (same contract as Guard)
 *   POST   /offline/challenge               (pre-auth, body.externalUsername) -> QR for a phone with no internet
 *   POST   /offline/verify                  (pre-auth, body.challengeId/code)
 *   POST   /offline/totp                    (pre-auth, body.externalUsername/code) -> time-based code fallback
 *   POST   /passkey/authenticate/options    (pre-auth, body.email)
 *   POST   /passkey/authenticate/verify     (pre-auth, body.attemptId/response)
 *   POST   /passkey/login/options           (pre-auth, body.requestId — approve a pending 2FA request)
 *   POST   /passkey/login/verify            (pre-auth, body.requestId/response)
 *   POST   /passkey/register/options        (auth required)
 *   POST   /passkey/register/verify         (auth required)
 *   GET    /passkey/credentials             (auth required)
 *   DELETE /passkey/credentials/{id}        (auth required)
 *
 * "auth required" routes answer 401 UNAUTHORIZED_FOR_2FA when `getUserId`
 * returns nothing. Pre-auth routes are rate limited per IP and per username
 * (`rateLimit`). Set `getLoginUser` so POST /login and the offline routes only
 * work for the user who already passed YOUR first factor (password step);
 * the offline routes stay off (403) until you do, or until you explicitly opt
 * out with `allowOfflineWithoutFirstFactor`.
 *
 * Options (callables receive the `$nativeRequest` given to handle()):
 *   getUserId       (required) fn($req): ?string — the signed-in user, for the auth-required routes.
 *   getLoginUser    fn($req): ?string — the user who passed your first factor. STRONGLY RECOMMENDED.
 *                   When set, /login and the offline routes act for this user and ignore any
 *                   username in the body (401 FIRST_FACTOR_REQUIRED when it returns nothing).
 *   rateLimit       array|false — ['windowMs' => 60000, 'perIp' => 20, 'perUser' => 5,
 *                   'store' => RateLimitStore]; false if you rate limit in front of the relay.
 *                   Under PHP-FPM pass a shared store (see RateLimitStore).
 *   allowOfflineWithoutFirstFactor  bool — let the offline routes trust the body username.
 *   actionType      string — action type for /login and the offline routes. Default 'LOGIN'.
 *   getDetails      fn($req): ?array — transaction context for the approval screen. Build it from
 *                   server-side state; the request body is attacker-controlled.
 *   onAuthenticated fn($req, RelayResponse $response, array $info): void — called right before a
 *                   success response is returned: open your session here. $info is
 *                   ['externalUsername' => string, 'requestId' => ?string, 'via' => 'login'|'passkey'|'offline'|'offline-totp']
 *                   ('requestId' is absent for 'offline-totp'). Mutate $response (headers, status);
 *                   the handler sets the body.
 */
class RelayHandler
{
    private TouchQue $tq;
    /** @var callable */
    private $getUserId;
    /** @var callable|null */
    private $getLoginUser;
    /** @var callable|null */
    private $getDetails;
    /** @var callable|null */
    private $onAuthenticated;
    private ?FixedWindowLimiter $limiter;
    private bool $offlineEnabled;
    private string $actionType;

    private static bool $warnedPreAuth = false;

    /** A 1.5 s poll for a 2-minute push is 80 requests: one attempt's worth of polls. */
    private const POLLS_PER_ATTEMPT = 10;
    /** Reserved action: the approval on the phone that unlocks adding a passkey. */
    private const PASSKEY_ENROLL_ACTION = 'PASSKEY_ENROLL';

    private const ROUTES = [
        'POST /enroll/start' => 'enrollStart',
        'GET /enroll/status' => 'enrollStatus',
        'POST /login' => 'login',
        'POST /offline/challenge' => 'offlineChallenge',
        'POST /offline/verify' => 'offlineVerify',
        'POST /offline/totp' => 'offlineTotp',
        'POST /passkey/authenticate/options' => 'passkeyAuthenticateOptions',
        'POST /passkey/authenticate/verify' => 'passkeyAuthenticateVerify',
        'POST /passkey/login/options' => 'passkeyLoginOptions',
        'POST /passkey/login/verify' => 'passkeyLoginVerify',
        'POST /passkey/register/options' => 'passkeyRegisterOptions',
        'POST /passkey/register/verify' => 'passkeyRegisterVerify',
        'GET /passkey/credentials' => 'passkeyCredentials',
    ];

    public function __construct(TouchQue $tq, array $options)
    {
        if (!isset($options['getUserId']) || !is_callable($options['getUserId'])) {
            throw new \InvalidArgumentException('RelayHandler: the "getUserId" option is required and must be callable.');
        }
        foreach (['getLoginUser', 'getDetails', 'onAuthenticated'] as $name) {
            if (isset($options[$name]) && !is_callable($options[$name])) {
                throw new \InvalidArgumentException("RelayHandler: the \"$name\" option must be callable.");
            }
        }
        $rateLimit = $options['rateLimit'] ?? [];
        if ($rateLimit !== false && !is_array($rateLimit)) {
            throw new \InvalidArgumentException('RelayHandler: "rateLimit" must be an array of options or false.');
        }

        $this->tq = $tq;
        $this->getUserId = $options['getUserId'];
        $this->getLoginUser = $options['getLoginUser'] ?? null;
        $this->getDetails = $options['getDetails'] ?? null;
        $this->onAuthenticated = $options['onAuthenticated'] ?? null;
        $this->actionType = (string)($options['actionType'] ?? 'LOGIN');
        $this->limiter = $rateLimit === false ? null : new FixedWindowLimiter($rateLimit);
        $this->offlineEnabled = $this->getLoginUser !== null || ($options['allowOfflineWithoutFirstFactor'] ?? false) === true;

        if ($this->getLoginUser === null && !self::$warnedPreAuth) {
            self::$warnedPreAuth = true;
            error_log('[TouchQue] RelayHandler: POST /login takes the username from the request body'
                . ($this->offlineEnabled ? ', and so do the offline routes' : '; the offline routes are disabled until you set it')
                . '. Set "getLoginUser" to bind them to your first factor (password step) so they cannot be used against arbitrary users.');
        }
    }

    /**
     * Handles one relay request.
     *
     * @param string   $method        HTTP method (HEAD is treated as GET).
     * @param string   $path          Path relative to where the relay is mounted, e.g. "/login".
     * @param array    $body          The decoded JSON request body.
     * @param string   $ip            The real client IP ('' if unknown). Behind a proxy, resolve it
     *                                from trusted proxy headers first.
     * @param callable $header        fn(string $name): ?string — case-insensitive request header getter.
     * @param mixed    $nativeRequest Your framework's request, passed to the option callbacks.
     * @return RelayResponse|null     null when no relay route matches (let your app answer 404).
     */
    public function handle(string $method, string $path, array $body, string $ip, ?string $userAgent, callable $header, $nativeRequest = null): ?RelayResponse
    {
        $method = strtoupper($method);
        if ($method === 'HEAD') {
            $method = 'GET';
        }
        $path = (string)strtok($path, '?');
        $path = '/' . trim($path, '/');

        $ctx = ['body' => $body, 'ip' => $ip, 'userAgent' => $userAgent, 'header' => $header, 'req' => $nativeRequest];

        $route = self::ROUTES[$method . ' ' . strtolower($path)] ?? null;
        if ($route !== null) {
            return $this->{$route}($ctx);
        }
        if ($method === 'DELETE' && preg_match('#^/passkey/credentials/([^/]+)$#i', $path, $m)) {
            return $this->deleteCredential($ctx, rawurldecode($m[1]));
        }
        return null;
    }

    // ── Classic push 2FA: enrollment ──────────────────────────────────────

    private function enrollStart(array $ctx): RelayResponse
    {
        $userId = $this->userId($ctx);
        if ($userId === null) {
            return self::unauthorized();
        }
        try {
            return new RelayResponse(200, $this->tq->auth->generateSecret($userId));
        } catch (\Throwable $error) {
            // 409: either a QR was issued and not scanned yet (safe to issue a new
            // one — no phone to lose), or a phone is ALREADY linked. Replacing a
            // linked phone must never happen from a plain session: that is exactly
            // how an attacker with a stolen password would swap in their own phone.
            if ($error instanceof TouchQueAPIException && $error->getStatus() === 409) {
                try {
                    $current = $this->tq->auth->getUser($userId);
                    if (!empty($current['used']) || !empty($current['deviceId'])) {
                        return new RelayResponse(409, ['error' => 'already_linked', 'message' => 'A phone is already linked to this account.']);
                    }
                    return new RelayResponse(200, $this->tq->auth->resetSecret($userId));
                } catch (\Throwable $retryError) {
                    return self::relayError($retryError);
                }
            }
            return self::relayError($error);
        }
    }

    private function enrollStatus(array $ctx): RelayResponse
    {
        $userId = $this->userId($ctx);
        if ($userId === null) {
            return self::unauthorized();
        }
        try {
            $u = $this->tq->auth->getUser($userId);
            $out = ['linked' => !empty($u['used']) && !empty($u['deviceId'])];
            return new RelayResponse(200, $out + self::pick($u, ['used', 'deviceId']));
        } catch (\Throwable $error) {
            if ($error instanceof TouchQueAPIException && $error->getStatus() === 404) {
                return new RelayResponse(200, ['linked' => false, 'used' => false, 'deviceId' => null]);
            }
            return self::relayError($error);
        }
    }

    // ── Classic push 2FA: login ───────────────────────────────────────────

    private function login(array $ctx): RelayResponse
    {
        $user = $this->loginUser($ctx, 'externalUsername');
        if ($user instanceof RelayResponse) {
            return $user;
        }
        // Same two-phase contract as Guard / TouchQueMiddleware: 202 with the step
        // (matching number / first-time QR / offline QR) until approved; the page
        // re-sends with X-TouchQue-Token.
        $input = Guard::inputFromHeaders($ctx['header']);
        $details = $this->getDetails !== null ? ($this->getDetails)($ctx['req']) : null;
        // Polling an approval already sent is not a new attempt: it has its own,
        // larger per-IP budget and never uses the user's push budget.
        $limited = Guard::isStatusPoll($this->tq, $user, $this->actionType, $details, null, $input['token'], $input['offline'], $input['code'])
            ? $this->allow($ctx, 'login-poll', null, self::POLLS_PER_ATTEMPT)
            : $this->allow($ctx, 'login', $user);
        if ($limited !== null) {
            return $limited;
        }
        $result = Guard::run(
            $this->tq,
            $user,
            $this->actionType,
            $details,
            null,
            $ctx['ip'] !== '' ? $ctx['ip'] : null,
            $ctx['userAgent'],
            $input['token'],
            $input['offline'],
            $input['code'],
            $input['codeType'],
            // Pre-auth: a typed username proves nothing, so no linking QR unless
            // getLoginUser ties this route to the password step.
            $this->getLoginUser !== null
        );
        if (!isset($result['approved'])) {
            $res = new RelayResponse($result['status'], $result['body']);
            if (!empty($result['body']['touchque']['retryAfter'])) {
                $res->setHeader('Retry-After', (string)$result['body']['touchque']['retryAfter']);
            }
            return $res->setHeader('Cache-Control', 'no-store');
        }
        $approved = $result['approved'];
        $res = new RelayResponse(200);
        try {
            if ($this->onAuthenticated !== null) {
                $confirmedVia = $approved['confirmedVia'] ?? null;
                $via = $confirmedVia === 'OFFLINE_TOTP' ? 'offline-totp' : ($confirmedVia === 'OFFLINE_CODE' ? 'offline' : 'login');
                ($this->onAuthenticated)($ctx['req'], $res, ['externalUsername' => $user, 'requestId' => $approved['requestId'] ?? null, 'via' => $via]);
            }
            return $res->setBody(['status' => 'success', 'requestId' => $approved['requestId'] ?? null, 'assurance' => $approved['assurance'] ?? null]);
        } catch (\Throwable $error) {
            return self::authResultError($error);
        }
    }

    // ── Offline Sign: QR challenge / typed code ───────────────────────────
    // The username used for onAuthenticated is the one TouchQue returns for the
    // challenge/code, never the one in the request body.

    private function offlineChallenge(array $ctx): RelayResponse
    {
        if (!$this->offlineEnabled) {
            return self::offlineDisabled();
        }
        $user = $this->loginUser($ctx, 'externalUsername');
        if ($user instanceof RelayResponse) {
            return $user;
        }
        $limited = $this->allow($ctx, 'offline-challenge', $user);
        if ($limited !== null) {
            return $limited;
        }
        try {
            // `requestId` (the push this QR follows) makes a phone-side rejection kill the QR and carries the number.
            $c = $this->tq->offline->challenge(
                $user,
                $this->actionType,
                $this->getDetails !== null ? ($this->getDetails)($ctx['req']) : null,
                $ctx['ip'] !== '' ? $ctx['ip'] : null,
                $ctx['userAgent'],
                null,
                true,
                self::bodyRequestId($ctx['body'])
            );
            $out = self::pick($c, ['challengeId', 'qr', 'qrDataUrl', 'expiresAt', 'expiresInSeconds', 'totpAvailable']);
            if (!empty($c['challengeCode'])) {
                $out['challengeCode'] = $c['challengeCode'];
            }
            return new RelayResponse(200, $out);
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function offlineVerify(array $ctx): RelayResponse
    {
        if (!$this->offlineEnabled) {
            return self::offlineDisabled();
        }
        $limited = $this->allow($ctx, 'offline-verify');
        if ($limited !== null) {
            return $limited;
        }
        try {
            $r = $this->tq->offline->verify(self::bodyString($ctx['body'], 'challengeId'), self::bodyString($ctx['body'], 'code'));
            if (empty($r['approved']) || empty($r['externalUsername'])) {
                $status = ($r['reason'] ?? null) === 'invalid_code' ? 401 : 400;
                return new RelayResponse($status, ['approved' => false] + self::withoutNulls(self::pick($r, ['reason', 'attemptsLeft'])));
            }
            // With a first factor, the code must belong to the user who passed it.
            if ($this->getLoginUser !== null) {
                $expected = ($this->getLoginUser)($ctx['req']);
                if (!self::sameUser($expected, $r['externalUsername'])) {
                    return new RelayResponse(401, ['approved' => false, 'reason' => 'invalid_code']);
                }
            }
            $res = new RelayResponse(200);
            if ($this->onAuthenticated !== null) {
                ($this->onAuthenticated)($ctx['req'], $res, ['externalUsername' => (string)$r['externalUsername'], 'requestId' => $r['challengeId'] ?? null, 'via' => 'offline']);
            }
            return $res->setBody(['status' => 'success', 'approved' => true] + self::withoutNulls(['requestId' => $r['challengeId'] ?? null]));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function offlineTotp(array $ctx): RelayResponse
    {
        if (!$this->offlineEnabled) {
            return self::offlineDisabled();
        }
        $user = $this->loginUser($ctx, 'externalUsername');
        if ($user instanceof RelayResponse) {
            return $user;
        }
        $limited = $this->allow($ctx, 'offline-totp', $user);
        if ($limited !== null) {
            return $limited;
        }
        try {
            $r = $this->tq->offline->verifyTotp(
                $user,
                self::bodyString($ctx['body'], 'code'),
                $this->actionType,
                $ctx['ip'] !== '' ? $ctx['ip'] : null,
                self::bodyRequestId($ctx['body'])
            );
            if (empty($r['approved']) || empty($r['externalUsername'])) {
                $status = ($r['reason'] ?? null) === 'invalid_code' ? 401 : 400;
                return new RelayResponse($status, ['approved' => false] + self::withoutNulls(self::pick($r, ['reason'])));
            }
            $res = new RelayResponse(200);
            if ($this->onAuthenticated !== null) {
                ($this->onAuthenticated)($ctx['req'], $res, ['externalUsername' => (string)$r['externalUsername'], 'via' => 'offline-totp']);
            }
            return $res->setBody(['status' => 'success', 'approved' => true]);
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    // ── Passkey: passwordless sign-in ─────────────────────────────────────

    private function passkeyAuthenticateOptions(array $ctx): RelayResponse
    {
        $email = self::lower(self::bodyString($ctx['body'], 'email'));
        $limited = $this->allow($ctx, 'passkey-options', $email !== '' ? $email : null);
        if ($limited !== null) {
            return $limited;
        }
        try {
            return new RelayResponse(200, $this->tq->webauthn->primaryOptions($email));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function passkeyAuthenticateVerify(array $ctx): RelayResponse
    {
        $limited = $this->allow($ctx, 'passkey-verify');
        if ($limited !== null) {
            return $limited;
        }
        try {
            $r = $this->tq->webauthn->primaryVerify(self::bodyString($ctx['body'], 'attemptId'), self::bodyArray($ctx['body'], 'response'));
            if (!empty($r['success'])) {
                $res = new RelayResponse(200);
                if ($this->onAuthenticated !== null) {
                    ($this->onAuthenticated)($ctx['req'], $res, ['externalUsername' => $r['externalUsername'] ?? null, 'requestId' => $r['requestId'] ?? null, 'via' => 'passkey']);
                }
                return $res->setBody(['status' => 'success'] + self::withoutNulls(['requestId' => $r['requestId'] ?? null]));
            }
            if (!empty($r['requiresStepUp'])) {
                return new RelayResponse(200, ['requiresStepUp' => true]);
            }
            return new RelayResponse(401, ['error' => 'verification_failed']);
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    // ── Passkey: approve an already-pending 2FA request (second factor; pair
    //    with `@touchque/web`'s `passkeys.approveLogin({ requestId })`) ──────

    private function passkeyLoginOptions(array $ctx): RelayResponse
    {
        $limited = $this->allow($ctx, 'passkey-approve');
        if ($limited !== null) {
            return $limited;
        }
        try {
            return new RelayResponse(200, $this->tq->webauthn->authenticateOptions(self::bodyString($ctx['body'], 'requestId')));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function passkeyLoginVerify(array $ctx): RelayResponse
    {
        $limited = $this->allow($ctx, 'passkey-approve');
        if ($limited !== null) {
            return $limited;
        }
        try {
            $r = $this->tq->webauthn->authenticateVerify(self::bodyString($ctx['body'], 'requestId'), self::bodyArray($ctx['body'], 'response'));
            $who = $r['externalUsername'] ?? null;
            // Open the session only for the user TouchQue says was approved. A name sent by the
            // browser is never trusted: anyone could approve their own request and claim to be someone else.
            if (!empty($r['success']) && $this->getLoginUser !== null && is_string($who)) {
                $expected = ($this->getLoginUser)($ctx['req']);
                if (!self::sameUser($expected, $who)) {
                    return new RelayResponse(401, ['error' => 'verification_failed']);
                }
            }
            $res = new RelayResponse(200);
            if (!empty($r['success']) && $this->onAuthenticated !== null && is_string($who) && $who !== '') {
                $requestId = !empty($r['requestId']) ? $r['requestId'] : ($ctx['body']['requestId'] ?? null);
                ($this->onAuthenticated)($ctx['req'], $res, ['externalUsername' => $who, 'requestId' => $requestId, 'via' => 'passkey']);
            }
            return $res->setBody($r);
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    // ── Passkey: enrollment / management (auth required) ─────────────────

    /**
     * A user with a linked phone approves adding a passkey there first: a passkey
     * approves requests on its own, so a stolen session of your app must not be able
     * to add one. Same two-phase contract as /login: 202 with the step (and number to
     * show) until approved, then the options.
     */
    private function passkeyRegisterOptions(array $ctx): RelayResponse
    {
        $userId = $this->userId($ctx);
        if ($userId === null) {
            return self::unauthorized();
        }
        $input = Guard::inputFromHeaders($ctx['header']);
        try {
            if (!$input['token']) {
                try {
                    return new RelayResponse(200, $this->tq->webauthn->registerOptions($userId, true));
                } catch (TouchQueAPIException $error) {
                    if ($error->getStatus() !== 403 || $error->getErrorCode() !== 'enrollment_approval_required') {
                        throw $error;
                    }
                }
            }
            $limited = Guard::isStatusPoll($this->tq, $userId, self::PASSKEY_ENROLL_ACTION, null, null, $input['token'], $input['offline'], $input['code'])
                ? $this->allow($ctx, 'login-poll', null, self::POLLS_PER_ATTEMPT)
                : $this->allow($ctx, 'passkey-enroll', $userId);
            if ($limited !== null) {
                return $limited;
            }
            $result = Guard::run(
                $this->tq, $userId, self::PASSKEY_ENROLL_ACTION, null, null,
                $ctx['ip'] !== '' ? $ctx['ip'] : null, $ctx['userAgent'],
                $input['token'], $input['offline'], $input['code'], $input['codeType'], false
            );
            if (!isset($result['approved'])) {
                $res = new RelayResponse($result['status'], $result['body']);
                if (!empty($result['body']['touchque']['retryAfter'])) {
                    $res->setHeader('Retry-After', (string)$result['body']['touchque']['retryAfter']);
                }
                return $res->setHeader('Cache-Control', 'no-store');
            }
            return new RelayResponse(200, $this->tq->webauthn->registerOptions($userId, true, $result['approved']['requestId']));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function passkeyRegisterVerify(array $ctx): RelayResponse
    {
        $userId = $this->userId($ctx);
        if ($userId === null) {
            return self::unauthorized();
        }
        try {
            $label = $ctx['body']['label'] ?? null;
            return new RelayResponse(200, $this->tq->webauthn->registerVerify($userId, self::bodyArray($ctx['body'], 'response'), is_string($label) ? $label : null));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function passkeyCredentials(array $ctx): RelayResponse
    {
        $userId = $this->userId($ctx);
        if ($userId === null) {
            return self::unauthorized();
        }
        try {
            return new RelayResponse(200, $this->tq->webauthn->listCredentials($userId));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    private function deleteCredential(array $ctx, string $id): RelayResponse
    {
        $userId = $this->userId($ctx);
        if ($userId === null) {
            return self::unauthorized();
        }
        try {
            return new RelayResponse(200, $this->tq->webauthn->deleteCredential($id, $userId));
        } catch (\Throwable $error) {
            return self::relayError($error);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private function userId(array $ctx): ?string
    {
        $userId = ($this->getUserId)($ctx['req']);
        if ($userId === null || $userId === false || $userId === '') {
            return null;
        }
        return (string)$userId;
    }

    /**
     * Who a pre-auth route acts for: the first-factor user when configured,
     * otherwise the typed username.
     *
     * @return string|RelayResponse the user, or the error response to send
     */
    private function loginUser(array $ctx, string $bodyField)
    {
        if ($this->getLoginUser !== null) {
            $u = ($this->getLoginUser)($ctx['req']);
            if ($u === null || $u === false || $u === '') {
                return new RelayResponse(401, ['error' => 'FIRST_FACTOR_REQUIRED', 'message' => 'Sign in with your password first.']);
            }
            return self::lower((string)$u);
        }
        $typed = self::lower(self::bodyString($ctx['body'], $bodyField));
        if ($typed === '') {
            return new RelayResponse(400, ['error' => 'externalUsername_required']);
        }
        return $typed;
    }

    /** null when allowed; otherwise the 429 to send (this IP or this user is over the limit for $route). */
    private function allow(array $ctx, string $route, ?string $user = null, int $ipFactor = 1): ?RelayResponse
    {
        if ($this->limiter === null) {
            return null;
        }
        $ipWait = $this->limiter->hit('ip|' . $route . '|' . ($ctx['ip'] !== '' ? $ctx['ip'] : 'unknown'), $this->limiter->perIp() * $ipFactor);
        $userWait = ($user !== null && $user !== '') ? $this->limiter->hit('user|' . $route . '|' . $user, $this->limiter->perUser()) : 0;
        $wait = max($ipWait, $userWait);
        if ($wait === 0) {
            return null;
        }
        return (new RelayResponse(429, ['error' => 'RATE_LIMITED', 'message' => 'Too many attempts. Try again later.', 'retryAfter' => $wait]))
            ->setHeader('Retry-After', (string)$wait);
    }

    private static function unauthorized(): RelayResponse
    {
        return new RelayResponse(401, [
            'error' => 'UNAUTHORIZED_FOR_2FA',
            'message' => 'Could not find user ID in request. Put your own auth middleware in front of this router.',
        ]);
    }

    private static function offlineDisabled(): RelayResponse
    {
        return new RelayResponse(403, [
            'error' => 'OFFLINE_REQUIRES_FIRST_FACTOR',
            'message' => 'Offline sign-in is disabled: configure getLoginUser (or allowOfflineWithoutFirstFactor) on the TouchQue router.',
        ]);
    }

    /** Same status-code mapping as the guard middleware — kept in sync with the Node SDK. */
    private static function authResultError(\Throwable $error): RelayResponse
    {
        if ($error instanceof TouchQueRejectedException) {
            return new RelayResponse(403, ['error' => '2FA_REJECTED', 'message' => 'User rejected the 2FA request on their device.']);
        }
        if ($error instanceof TouchQuePasskeyRequiredError) {
            return new RelayResponse(409, ['error' => 'PASSKEY_REQUIRED', 'requestId' => $error->requestId, 'message' => 'Approve this sign-in with your passkey.']);
        }
        if ($error instanceof TouchQueTimeoutException) {
            return new RelayResponse(408, ['error' => '2FA_TIMEOUT', 'message' => 'User did not respond to the 2FA request in time.']);
        }
        // A client-range TouchQue error (e.g. 404 "no linked device") still carries
        // a useful status + message; only a network failure or an unexpected error is 503.
        if ($error instanceof TouchQueAPIException && $error->getStatus() < 500) {
            $data = $error->getData() ?? [];
            return new RelayResponse($error->getStatus(), [
                'error' => self::firstText([$data['error'] ?? null, $data['message'] ?? null, $error->getMessage()]) ?? 'request_failed',
            ]);
        }
        error_log('[TouchQue Relay Error] ' . get_class($error) . ': ' . $error->getMessage());
        return new RelayResponse(503, ['error' => '2FA_UNAVAILABLE', 'message' => 'The 2FA verification service is temporarily unavailable.']);
    }

    /**
     * For plain relay routes (enroll, offline, passkey): a client-range TouchQue
     * status is forwarded with its machine-readable code only — never TouchQue's
     * internal message text — anything else becomes 502.
     */
    private static function relayError(\Throwable $error): RelayResponse
    {
        if ($error instanceof TouchQueAPIException && $error->getStatus() < 500) {
            $data = $error->getData() ?? [];
            return new RelayResponse($error->getStatus(), [
                'error' => self::firstText([$data['code'] ?? null, $data['error'] ?? null]) ?? 'request_failed',
            ]);
        }
        return new RelayResponse(502, ['error' => 'relay_error']);
    }

    /** The first non-empty scalar, as a string. */
    private static function firstText(array $candidates): ?string
    {
        foreach ($candidates as $c) {
            if (is_scalar($c) && $c !== false && (string)$c !== '') {
                return (string)$c;
            }
        }
        return null;
    }

    private static function sameUser($expected, string $actual): bool
    {
        if ($expected === null || $expected === false || $expected === '') {
            return false;
        }
        return self::lower((string)$expected) === self::lower($actual);
    }

    /** A body field as a string ('' when missing, empty or not a scalar). */
    private static function bodyString(array $body, string $field): string
    {
        $v = $body[$field] ?? null;
        if (!is_scalar($v) || $v === false) {
            return '';
        }
        return (string)$v;
    }

    private static function bodyArray(array $body, string $field): array
    {
        $v = $body[$field] ?? null;
        return is_array($v) ? $v : [];
    }

    private static function bodyRequestId(array $body): ?string
    {
        $v = $body['requestId'] ?? null;
        return is_string($v) && $v !== '' ? $v : null;
    }

    /** Copies the keys present in $src (like JSON.stringify dropping undefined, keeping null). */
    private static function pick(array $src, array $keys): array
    {
        $out = [];
        foreach ($keys as $k) {
            if (array_key_exists($k, $src)) {
                $out[$k] = $src[$k];
            }
        }
        return $out;
    }

    private static function withoutNulls(array $a): array
    {
        return array_filter($a, static function ($v): bool {
            return $v !== null;
        });
    }

    private static function lower(string $s): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    }
}
