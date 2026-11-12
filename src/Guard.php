<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueNetworkException;

/**
 * Framework-agnostic step-up guard. `Touchque\Laravel\TouchqueMiddleware` is
 * a thin wrapper over `Guard::run()`.
 *
 * Contract (same in every Touchque server SDK):
 *   1st request            -> 202 {"touchque": step, "token": ...}   show the step in your UI
 *   repeat with the token   -> 202 while waiting (each answer carries the request's live `expiresAt`),
 *                              then the protected action runs once
 *   refused                 -> 403 / 408 / 423 / 429 {"touchque": {"state": ..., ...}}
 *   first-time QR up        -> 202 {"touchque": {"state": "enroll", "expiresAt": ...}} with no
 *                              `enroll`: keep showing the QR; about 15 s before it expires a new
 *                              one comes with `enroll.qrCodeDataUrl` and new recovery codes
 *   no phone, `$enroll` off -> 202 {"touchque": {"state": "enroll", "reason": "enrollment_off"}}: final
 *
 * `run(null, ...)` uses defaultClient() (setDefaultClient() replaces it);
 * `response()` turns a result into the status, headers and body to send.
 *
 * Request headers the browser sends back:
 *   X-Touchque-Token         the token from the last response
 *   X-Touchque-Offline: 1    switch to offline approval (phone has no internet)
 *   X-Touchque-Code          the code from the phone (offline QR code, or with
 *   X-Touchque-Code-Type: totp   the rolling time-based code)
 *   X-Touchque-Browser       the browser's device-bound key proof (silent sign-ins,
 *                            read only when the adapter's `silentSignIn` option is on)
 */
class Guard
{
    public const TOKEN_HEADER = 'x-touchque-token';
    public const OFFLINE_HEADER = 'x-touchque-offline';
    public const CODE_HEADER = 'x-touchque-code';
    public const CODE_TYPE_HEADER = 'x-touchque-code-type';
    public const BROWSER_HEADER = 'x-touchque-browser';

    private const TOKEN_TTL_MS = 10 * 60 * 1000;
    /** A real proof is a few hundred characters; anything far larger is not one. */
    private const MAX_BROWSER_PROOF = 4096;

    private const STATUS = [
        'waiting' => 202, 'enroll' => 202, 'passkey_required' => 202, 'offline' => 202,
        'approved' => 200, 'rejected' => 403, 'blocked' => 403, 'expired' => 408, 'frozen' => 423, 'rate_limited' => 429,
    ];

    /** A first-time QR this close to its expiry is replaced instead of kept on screen. */
    private const ENROLL_MARGIN_MS = 15000;

    /** Steps whose token carries the request's expiry (claim `rx`): every poll answers an expiresAt. */
    private const EXPIRING = ['waiting', 'passkey_required'];

    /** The client given to setDefaultClient(): it wins over a container binding and the environment. */
    private static ?Touchque $defaultClient = null;

    /** The client built from the environment for `run(null, ...)`: built on first use, kept once built. */
    private static ?Touchque $environmentClient = null;

    /** The default client could not be built: logged once per process. */
    private static bool $loggedUnconfigured = false;

    /** The refusal `message` for a state when the guard set none (anything else: "The approval was refused."). */
    private const REFUSAL_MESSAGES = [
        'rejected' => 'The approval was rejected.',
        'expired' => 'The approval expired. Try again.',
        'frozen' => 'Too many rejected approvals. Try again later.',
        'rate_limited' => 'Too many attempts. Try again later.',
    ];

    /**
     * Reads the guard headers from any case-insensitive header getter
     * (`fn(string $name): ?string`).
     */
    public static function inputFromHeaders(callable $get): array
    {
        $offline = $get(self::OFFLINE_HEADER);
        return [
            'token' => $get(self::TOKEN_HEADER) ?: null,
            'offline' => in_array($offline, ['1', 'true'], true),
            'code' => $get(self::CODE_HEADER) ?: null,
            'codeType' => $get(self::CODE_TYPE_HEADER) ?: null,
        ];
    }

    /**
     * The guard input an adapter adds for silent sign-ins: the
     * `X-Touchque-Browser` header, read only when the option is on.
     * Returns `['silentSignIn' => bool|array, 'browserProof' => ?string]`.
     *
     * @param bool|array|null $option the adapter's `silentSignIn` option
     */
    public static function silentInputFromHeaders($option, callable $get): array
    {
        if (!self::silentOn($option)) {
            return ['silentSignIn' => false, 'browserProof' => null];
        }
        $proof = $get(self::BROWSER_HEADER);
        return ['silentSignIn' => $option, 'browserProof' => is_string($proof) && $proof !== '' ? $proof : null];
    }

    /**
     * Checks an adapter's `silentSignIn` option: `false` (default), `true`, or
     * `['maxAgeSeconds' => int >= 0]`.
     *
     * @param mixed $option
     * @throws \InvalidArgumentException
     */
    public static function assertSilentSignInOption($option, string $who): void
    {
        if ($option === null || is_bool($option)) {
            return;
        }
        if (is_array($option) && array_diff(array_keys($option), ['maxAgeSeconds']) === []
            && (!isset($option['maxAgeSeconds']) || (is_int($option['maxAgeSeconds']) && $option['maxAgeSeconds'] >= 0))) {
            return;
        }
        throw new \InvalidArgumentException("$who: \"silentSignIn\" must be true, false or ['maxAgeSeconds' => int >= 0].");
    }

    /** @param mixed $option */
    private static function silentOn($option): bool
    {
        return $option === true || is_array($option);
    }

    /**
     * True when this request only polls an approval that is already on its way:
     * a valid token bound to this user/action/details, still waiting, or showing
     * the first-time QR while it is up (more than 15 s before it expires), and no
     * offline switch or typed code. Relays do not count it against the per-user
     * push limit (with a 1.5 s poll the 6th poll was refused after 7.5 s). Such an
     * enroll poll can still start (the user linked, or the QR is gone): relays
     * charge that through run()'s `$beforeStart`. Renewing an expiring QR counts.
     * `$client`: as run()'s; null is the default client, and false while it
     * cannot be built.
     */
    public static function isStatusPoll(
        ?Touchque $client,
        ?string $user,
        string $action,
        ?array $details = null,
        ?string $referenceId = null,
        ?string $token = null,
        bool $offline = false,
        ?string $code = null
    ): bool {
        if (!$user || !$token || $offline || $code) {
            return false;
        }
        $client = $client ?? self::defaultClientOrNull();
        if ($client === null) {
            return false;
        }
        $claims = Steps::verifyGuardToken($client->getApiSecret(), $token);
        if (!$claims || $claims['u'] !== $user || $claims['a'] !== $action
            || $claims['d'] !== Steps::detailsDigest($details) || $claims['r'] !== $referenceId) {
            return false;
        }
        $st = $claims['st'] ?? null;
        if ($st === 'enroll') {
            return is_int($claims['ee'] ?? null) && microtime(true) * 1000 < $claims['ee'] - self::ENROLL_MARGIN_MS;
        }
        return !empty($claims['rid']) && in_array($st, ['waiting', 'passkey_required', 'offline'], true);
    }

    /**
     * The headers for a result that is not an approval: `Cache-Control: no-store`,
     * `Retry-After` when the step has one (423, 429) and, for status >= 400,
     * `X-Touchque-State` plus `X-Touchque-Reason` when the step has a reason.
     * `@touchque/web` rebuilds the step from them when a body has no `touchque`
     * key; cross-origin pages need them in Access-Control-Expose-Headers.
     */
    public static function headers(array $result): array
    {
        $step = $result['body']['touchque'] ?? [];
        $headers = ['Cache-Control' => 'no-store'];
        if (!empty($step['retryAfter'])) {
            $headers['Retry-After'] = (string)$step['retryAfter'];
        }
        if (($result['status'] ?? 0) >= 400 && self::isCode($step['state'] ?? null)) {
            $headers['X-Touchque-State'] = $step['state'];
            if (self::isCode($step['reason'] ?? null)) {
                $headers['X-Touchque-Reason'] = $step['reason'];
            }
        }
        return $headers;
    }

    /** A state or reason code that is safe as a header value. */
    private static function isCode($value): bool
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9_.:-]{1,100}$/', $value) === 1;
    }

    /** The 401 for a request without a signed-in user. */
    public static function unauthenticated(): array
    {
        return ['status' => 401, 'body' => [
            'touchque' => ['state' => 'blocked', 'reason' => 'unauthenticated'],
            'error' => ['code' => 'unauthenticated', 'message' => 'Sign in first.'],
        ]];
    }

    /** The 500 for a setup error: missing keys, an undefined action type. */
    public static function misconfigured(): array
    {
        return ['status' => 500, 'body' => [
            'touchque' => ['state' => 'blocked', 'reason' => 'misconfigured'],
            'error' => ['code' => 'misconfigured', 'message' => 'Two-factor approval is not configured correctly.'],
        ]];
    }

    /**
     * What an `errorBody` callback gets for a result with status >= 400:
     * `['status' => int, 'code' => string, 'message' => string, 'touchque' => array]`.
     * `code` is the error's code, else the step's reason, else its state;
     * `message` is the error's message, else one for the state ("The approval
     * was rejected.", "The approval expired. Try again." …); `touchque` is the
     * step as it would be sent.
     */
    public static function refusal(array $result): array
    {
        $step = $result['body']['touchque'] ?? [];
        $error = $result['body']['error'] ?? [];
        return [
            'status' => $result['status'],
            'code' => $error['code'] ?? $step['reason'] ?? $step['state'] ?? null,
            'message' => $error['message'] ?? self::REFUSAL_MESSAGES[$step['state'] ?? ''] ?? 'The approval was refused.',
            'touchque' => $step,
        ];
    }

    /**
     * The body to send for a result with status >= 400 in your own error shape:
     * what `$errorBody` returns for `refusal($result)` (a copy of the step: PHP
     * arrays are values). Its json_encode(), as it is, decides (TouchqueMiddleware
     * converts Laravel's Arrayable / Jsonable first): a JSON object (an array with
     * string keys, a stdClass, a JsonSerializable or public properties that encode
     * to one) gets key `touchque` set to the step, replacing yours, so
     * `@touchque/web` still sees the state; anything else (a string, a number, a
     * list, null) is the body as it is. No `token` is added. Throws what the
     * callback throws, and JsonException for a result that cannot be encoded.
     *
     * @return mixed
     */
    public static function errorBody(array $result, callable $errorBody)
    {
        $body = $errorBody(self::refusal($result));
        $json = json_encode($body, JSON_THROW_ON_ERROR);
        if ($json[0] !== '{') {
            return $body;
        }
        $object = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        $object->touchque = $result['body']['touchque'] ?? null;
        return $object;
    }

    /**
     * The HTTP answer for a result of run() that is not an approval, exactly as
     * TouchqueMiddleware and the relay send it:
     * `['status' => int, 'headers' => array, 'body' => mixed]`. Send `body` with
     * your framework's JSON response (encode `null` yourself: Laravel's
     * `JsonResponse(null)` sends `{}`).
     *
     * `headers` are headers(): `Cache-Control: no-store`, `Retry-After` on 423
     * and 429, `X-Touchque-State` and `X-Touchque-Reason` on 400 and above.
     * `body` is the result's body; for 400 and above with `$errorBody`, what
     * errorBody() makes of it. A callable that throws, or a result that cannot
     * be encoded, is logged (`[Touchque] errorBody failed: <message>`) and the
     * default body sent: through `$client`'s logger, else Laravel's logger in a
     * Laravel app, else nowhere.
     *
     * @throws \InvalidArgumentException for an approval: run your action instead
     */
    public static function response(array $result, ?callable $errorBody = null, ?Touchque $client = null): array
    {
        if (isset($result['approved'])) {
            throw new \InvalidArgumentException('Guard::response(): the result is an approval: run your action instead.');
        }
        $body = $result['body'];
        if ($errorBody !== null && $result['status'] >= 400) {
            try {
                $body = self::errorBody($result, $errorBody);
            } catch (\Throwable $err) {
                self::logError($client, '[Touchque] errorBody failed: ' . $err->getMessage());
            }
        }
        return ['status' => $result['status'], 'headers' => self::headers($result), 'body' => $body];
    }

    /**
     * The client `run(null, ...)` and `isStatusPoll(null, ...)` use:
     *   1. the one given to setDefaultClient();
     *   2. else, in a Laravel app with a binding of `Touchque`
     *      (`$app->bind/singleton(Touchque::class, ...)`), the container's, resolved
     *      on each call (the container owns its lifetime); a contextual binding for
     *      TouchqueMiddleware is not used;
     *   3. else one built from TQ_API_KEY / TQ_API_SECRET (and TQ_API_URL) on
     *      first use and kept once built.
     * Call it at startup to fail fast: it throws TouchqueConfigException, naming
     * the problem, while no client can be built (a build that failed is tried
     * again on the next call).
     *
     * @throws TouchqueConfigException
     */
    public static function defaultClient(): Touchque
    {
        if (self::$defaultClient !== null) {
            return self::$defaultClient;
        }
        if (class_exists(\Illuminate\Container\Container::class)) {
            $app = \Illuminate\Container\Container::getInstance();
            if ($app->bound(Touchque::class)) {
                return $app->make(Touchque::class);
            }
        }
        if (self::$environmentClient === null) {
            self::$environmentClient = new Touchque();
        }
        return self::$environmentClient;
    }

    /**
     * Makes `$client` the default client of `run(null, ...)` and
     * `isStatusPoll(null, ...)`, over a container binding and the environment:
     * the way to give them your own Config (a logger, a base URL). null forgets
     * it (and the client built from the environment): the next call uses a
     * Laravel binding of `Touchque`, else builds from the environment.
     */
    public static function setDefaultClient(?Touchque $client): void
    {
        self::$defaultClient = $client;
        self::$environmentClient = null;
    }

    /** defaultClient(), or null while it cannot be built (logged once per process). */
    private static function defaultClientOrNull(): ?Touchque
    {
        try {
            return self::defaultClient();
        } catch (TouchqueConfigException $err) {
            self::logUnconfigured($err);
            return null;
        }
    }

    /**
     * @internal Logs once per process that the default client cannot be built
     * (`run(null, ...)`, TouchqueMiddleware). There is no Config to carry your
     * logger: Laravel's logger in a Laravel app, else nowhere.
     */
    public static function logUnconfigured(TouchqueConfigException $err): void
    {
        if (self::$loggedUnconfigured) {
            return;
        }
        self::$loggedUnconfigured = true;
        self::logError(null, $err->getMessage() === Config::MISSING_KEYS
            ? '[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.'
            : '[Touchque] ' . $err->getMessage());
    }

    /** Through the client's logger; without a client, through Laravel's in a Laravel app, else nowhere. */
    private static function logError(?Touchque $client, string $message): void
    {
        if ($client !== null) {
            $client->log('error', $message);
            return;
        }
        if (!class_exists(\Illuminate\Support\Facades\Log::class)) {
            return;
        }
        try {
            \Illuminate\Support\Facades\Log::error($message);
        } catch (\Throwable $e) {
            // outside a Laravel app; a logger must never break a request
        }
    }

    /**
     * Runs one step of the guard. Returns either
     * `["approved" => [...], "status" => 200]` (run your protected action) or
     * `["status" => <code>, "body" => ["touchque" => step, "token" => ...]]`
     * (send it as response() gives it: that status, `headers()` and that JSON body).
     *
     * `$client`: your Touchque, or null for defaultClient(): the one given to
     * setDefaultClient(), else a Laravel binding of `Touchque`, else one built
     * from TQ_API_KEY / TQ_API_SECRET on first use and kept once built (a
     * failed build is tried again on the next request). While it cannot be
     * built the answer is 500 `misconfigured` (401 `unauthenticated` without a
     * user), logged once per process through Laravel's logger in a Laravel app.
     *
     * `$enroll = false` (a guard that may not show the linking QR): a user with
     * no phone gets 202 `{"state": "enroll", "reason": "enrollment_off"}`.
     *
     * Silent sign-ins: `$browserProof` is the browser's device-bound key proof
     * (`X-Touchque-Browser`), passed through untouched and attached to the
     * push, so its approval makes the browser known. With `$silentSignIn`
     * (`true`, or `['maxAgeSeconds' => int]` for your own limit on the age of
     * the last phone approval; default `false`), a new attempt that carries a
     * proof first asks Touchque (`$tq->risk->check()`): when it answers exactly
     * `prompt: false` the guard approves at once with no push (`assurance.method`
     * `silent`, `confirmedVia` `SILENT`, `requestId` `silent`, `reasons`).
     * Otherwise, and on any error, the usual push starts.
     *
     * `$beforeStart` (for rate limiters): called at most once, only for a poll
     * with a first-time QR token, right before it would start instead of keeping
     * the QR (the user linked: the silent check or the push; the QR expired, is
     * about to, or is gone: a new QR). Return null to go on, or a result
     * (`['status' => int, 'body' => array]`) to answer instead; anything else
     * throws InvalidArgumentException, so nothing starts. A relay charges the
     * user's budget there, since isStatusPoll() exempted that poll.
     */
    public static function run(
        ?Touchque $client,
        ?string $user,
        string $action,
        ?array $details = null,
        ?string $referenceId = null,
        ?string $ip = null,
        ?string $userAgent = null,
        ?string $token = null,
        bool $offline = false,
        ?string $code = null,
        ?string $codeType = null,
        bool $enroll = true,
        ?string $browserProof = null,
        $silentSignIn = false,
        ?array $context = null,
        ?callable $beforeStart = null
    ): array {
        if (!$user) {
            return self::unauthenticated();
        }
        $client = $client ?? self::defaultClientOrNull();
        if ($client === null) {
            return self::misconfigured();
        }

        $norm = Steps::normalizeDetails($details);
        $base = ['u' => $user, 'a' => $action, 'd' => Steps::detailsDigest($details), 'r' => $referenceId];
        $secret = $client->getApiSecret();

        $issue = function (array $step, array $extra = []) use ($norm, $base, $secret): array {
            if ($norm && empty($step['details']) && ($step['state'] ?? null) !== 'blocked') {
                $step['details'] = $norm;
            }
            // A first-time QR: its token carries when the QR expires (ee), so polls keep it on screen.
            $ee = ($step['state'] ?? null) === 'enroll' && !empty($step['enroll']['qrCodeDataUrl'])
                ? Steps::isoMs($step['enroll']['expiresAt'] ?? null) : null;
            // A push or passkey: its token carries when the request expires (rx), for polls without a live expiry.
            $rx = in_array($step['state'] ?? null, self::EXPIRING, true) ? Steps::isoMs($step['expiresAt'] ?? null) : null;
            $claims = array_merge($base, [
                'st' => $step['state'], 'rid' => $step['requestId'] ?? null, 'n' => $step['number'] ?? null,
                'oc' => $step['offline']['challengeId'] ?? null, 'exp' => (int)(microtime(true) * 1000) + self::TOKEN_TTL_MS,
            ], isset($step['caseCode']) ? ['cc' => $step['caseCode']] : [], $ee !== null ? ['ee' => $ee] : [],
                $rx !== null ? ['rx' => $rx] : [], $extra);
            return ['status' => self::STATUS[$step['state']], 'body' => ['touchque' => $step, 'token' => Steps::signGuardToken($secret, $claims)]];
        };

        try {
            $claims = Steps::verifyGuardToken($secret, $token);
            $bound = ($claims && $claims['u'] === $base['u'] && $claims['a'] === $base['a']
                && $claims['d'] === $base['d'] && $claims['r'] === $base['r']) ? $claims : null;
            // The request's expiry (rx) stays with it: waiting / passkey answers carry it as expiresAt (the
            // live one from Touchque's status answer when there is one), and the offline steps carry it on.
            $rx = is_int($bound['rx'] ?? null) ? $bound['rx'] : null;
            $keepRx = $rx !== null ? ['rx' => $rx] : [];
            $expiring = fn (array $step, ?int $live = null): array => ($live ?? $rx) !== null
                ? $step + ['expiresAt' => Steps::isoOf($live ?? $rx)] : $step;

            // Offline: the user typed the code from the phone.
            if ($bound && $code && (($bound['st'] ?? null) === 'offline' || $codeType === 'totp')) {
                $isTotp = $codeType === 'totp';
                $res = $isTotp
                    ? $client->offline->verifyTotp($user, $code, $action, $ip, $bound['rid'] ?? null)
                    : $client->offline->verify((string)($bound['oc'] ?? ''), $code);
                $forThis = (empty($res['externalUsername']) || strtolower($res['externalUsername']) === strtolower($user))
                    && (empty($res['type']) || $res['type'] === $action);
                if (!empty($res['approved']) && $forThis) {
                    $method = $isTotp ? 'offline_totp' : 'offline_code';
                    return ['status' => 200, 'approved' => [
                        'requestId' => $bound['oc'] ?? 'offline-totp', 'user' => $user, 'action' => $action,
                        'assurance' => ['phishingResistant' => false, 'method' => $method],
                        'confirmedVia' => $isTotp ? 'OFFLINE_TOTP' : 'OFFLINE_CODE', 'approvalProof' => null,
                    ]];
                }
                if (($res['reason'] ?? null) === 'invalid_code' && !$isTotp) {
                    return $issue(['state' => 'offline', 'offline' => ['challengeId' => (string)($bound['oc'] ?? ''), 'attemptsLeft' => $res['attemptsLeft'] ?? null]], ['oc' => $bound['oc'] ?? null, 'rid' => $bound['rid'] ?? null, 'n' => $bound['n'] ?? null] + $keepRx);
                }
                if (($res['reason'] ?? null) === 'invalid_code') {
                    return $issue(['state' => 'offline', 'reason' => 'invalid_code'], ['oc' => $bound['oc'] ?? null, 'rid' => $bound['rid'] ?? null, 'n' => $bound['n'] ?? null] + $keepRx);
                }
                // The phone rejected the push this QR belongs to: the whole sign-in is over.
                if (($res['reason'] ?? null) === 'request_rejected') {
                    return $issue(['state' => 'rejected', 'requestId' => $bound['rid'] ?? null, 'reason' => 'request_rejected']);
                }
                // The push now waits for a passkey (Vishing Shield): no code may finish it.
                if (($res['reason'] ?? null) === 'passkey_required' && !empty($bound['rid'])) {
                    return $issue($expiring(['state' => 'passkey_required', 'requestId' => $bound['rid'], 'number' => $bound['n'] ?? null]), ['n' => $bound['n'] ?? null]);
                }
                return $issue(['state' => ($res['reason'] ?? null) === 'expired' ? 'expired' : 'blocked', 'reason' => $res['reason'] ?? 'offline_failed']);
            }

            if ($offline) {
                try {
                    // Link the QR to the push it follows: a phone-side rejection kills it, and a push that asked
                    // for number matching makes the QR ask for the same number.
                    $rid = $bound['rid'] ?? null;
                    $ch = $client->offline->challenge($user, $action, $norm ?: null, $ip, $userAgent, null, true, $rid);
                    $offlineStep = [
                        'challengeId' => $ch['challengeId'] ?? null, 'qrDataUrl' => $ch['qrDataUrl'] ?? null,
                        'expiresAt' => $ch['expiresAt'] ?? null, 'totpAvailable' => $ch['totpAvailable'] ?? null,
                    ];
                    if (!empty($ch['challengeCode'])) {
                        $offlineStep['challengeCode'] = $ch['challengeCode'];
                    }
                    return $issue(['state' => 'offline', 'offline' => $offlineStep], ['rid' => $rid, 'n' => $ch['challengeCode'] ?? ($bound['n'] ?? null)] + $keepRx);
                } catch (TouchqueAPIException $err) {
                    if ($err->getStatus() === 409 && ($err->getErrorCode() ?? ($err->getData()['error'] ?? null)) === 'request_rejected') {
                        return $issue(['state' => 'rejected', 'requestId' => $bound['rid'] ?? null, 'reason' => 'request_rejected']);
                    }
                    // The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey.
                    if (!empty($bound['rid']) && ($err->getErrorCode() ?? ($err->getData()['error'] ?? null)) === 'passkey_required') {
                        return $issue($expiring(['state' => 'passkey_required', 'requestId' => $bound['rid'], 'number' => $bound['n'] ?? null]), ['n' => $bound['n'] ?? null]);
                    }
                    if ($err->getStatus() < 500) {
                        return $issue(['state' => 'blocked', 'reason' => $err->getErrorCode() ?? ($err->getData()['error'] ?? 'offline_unavailable')]);
                    }
                    throw $err;
                }
            }

            // Waiting on a push / passkey — or showing the offline QR next to a push that is still open: poll, and run
            // the action once approved. While the QR is up a phone-side REJECT ends the attempt at once.
            if ($bound && !empty($bound['rid']) && in_array($bound['st'] ?? null, ['waiting', 'passkey_required', 'offline'], true)) {
                $now = Steps::check($client, $bound['rid']);
                // The live expiry: a switch to a passkey during a call extends it. The new token keeps it (rx).
                $live = Steps::isoMs($now['expiresAt'] ?? null);
                if ($now['state'] === 'approved') {
                    try {
                        return ['status' => 200, 'approved' => Steps::complete($client, $bound['rid'], $user, $action, $details, $referenceId)];
                    } catch (TouchqueAPIException $err) {
                        if ($err->getStatus() === 409) {
                            return $issue(['state' => 'expired', 'reason' => $err->getErrorCode() ?? 'already_used']);
                        }
                        throw $err;
                    }
                }
                // The push behind the QR was moved to a passkey after a tap during a call (Vishing Shield):
                // the QR's code would be refused now, so switch to the passkey.
                if (($bound['st'] ?? null) === 'offline' && $now['state'] === 'passkey_required') {
                    return $issue($expiring(['state' => 'passkey_required', 'requestId' => $bound['rid'], 'number' => $bound['n'] ?? null], $live), ['n' => $bound['n'] ?? null]);
                }
                if (($bound['st'] ?? null) === 'offline' && in_array($now['state'], ['waiting', 'expired'], true)) {
                    // Still (or no longer) pending: nothing changed for the user — keep showing the QR they have.
                    return $issue(['state' => 'offline', 'offline' => ['challengeId' => (string)($bound['oc'] ?? '')]], ['oc' => $bound['oc'] ?? null, 'rid' => $bound['rid'], 'n' => $bound['n'] ?? null]
                        + ($live !== null ? ['rx' => $live] : $keepRx));
                }
                if (in_array($now['state'], ['waiting', 'passkey_required'], true)) {
                    // "Why?": the case code stays on screen while it waits, and so does when the request expires.
                    $waiting = $expiring(['state' => $now['state'], 'requestId' => $bound['rid'], 'number' => $bound['n'] ?? null], $live)
                        + (isset($bound['cc']) ? ['caseCode' => $bound['cc']] : []);
                    return $issue($waiting, ['n' => $bound['n'] ?? null]);
                }
                return $issue(['state' => $now['state'], 'requestId' => $bound['rid']]);
            }

            // The first-time QR is up: while the phone is not linked and the QR lives, keep it on screen (no new
            // secret, no push); the page keeps the QR and recovery codes it shows. Linked, expiring or gone: start.
            if ($bound && ($bound['st'] ?? null) === 'enroll' && is_int($bound['ee'] ?? null)) {
                $linked = self::linkState($client, $user);
                if ($linked === false && microtime(true) * 1000 < $bound['ee'] - self::ENROLL_MARGIN_MS) {
                    return $issue(['state' => 'enroll', 'expiresAt' => Steps::isoOf($bound['ee'])], ['ee' => $bound['ee']]);
                }
                // This poll starts after all (a push, or a new QR): the caller may charge or refuse it first.
                // Anything it returns is the answer; what is not a result fails closed.
                $instead = $beforeStart !== null ? $beforeStart() : null;
                if ($instead !== null) {
                    if (!is_array($instead) || !is_int($instead['status'] ?? null) || !is_array($instead['body'] ?? null)) {
                        throw new \InvalidArgumentException('Guard::run(): $beforeStart must return null to go on, or a result [\'status\' => int, \'body\' => array] to answer.');
                    }
                    return $instead;
                }
            }

            // Anything else (no/foreign token, enrollment finished, new attempt): start.
            $proof = $browserProof !== null && $browserProof !== '' && strlen($browserProof) <= self::MAX_BROWSER_PROOF ? $browserProof : null;
            if ($proof !== null && self::silentOn($silentSignIn)) {
                $silent = self::silentApproval($client, $user, $action, $proof, $ip, $userAgent, $silentSignIn, $context);
                if ($silent !== null) {
                    return ['status' => 200, 'approved' => $silent];
                }
            }
            return $issue(Steps::start($client, $action, $user, $norm ?: null, $referenceId, $ip, $userAgent, $enroll, $proof, $context));
        } catch (TouchqueConfigException $err) {
            $client->log('error', '[Touchque] ' . $err->getMessage());
            return self::misconfigured();
        } catch (TouchqueNetworkException | TouchqueAPIException $err) {
            $client->log('error', '[Touchque] approval failed: ' . Config::describe($err));
            return ['status' => 503, 'body' => [
                'touchque' => ['state' => 'blocked', 'reason' => 'unavailable'],
                'error' => ['code' => 'unavailable', 'message' => 'Two-factor approval is temporarily unavailable.'],
            ]];
        }
    }

    /**
     * Whether a phone is linked to the user (`used`, or a `deviceId`); null when
     * Touchque does not know the user (404: the QR is gone). Other errors throw.
     */
    private static function linkState(Touchque $client, string $user): ?bool
    {
        try {
            $current = $client->auth->getUser($user);
        } catch (TouchqueAPIException $err) {
            if ($err->getStatus() === 404) {
                return null;
            }
            throw $err;
        }
        return !empty($current['used']) || !empty($current['deviceId']);
    }

    /**
     * Asks Touchque whether this known browser may sign in without the phone.
     * Fails closed: only an answer of exactly `prompt: false` approves; any
     * error (network, 4xx, 5xx, a server without silent sign-ins, a bad
     * option) means "ask as usual".
     *
     * @param bool|array $silentSignIn
     */
    private static function silentApproval(Touchque $client, string $user, string $action, string $proof, ?string $ip, ?string $userAgent, $silentSignIn, ?array $context = null): ?array
    {
        try {
            $options = ['externalUsername' => $user, 'type' => $action, 'clientIp' => $ip, 'userAgent' => $userAgent, 'browserProof' => $proof];
            if ($context) {
                $options['context'] = $context;
            }
            if (is_array($silentSignIn) && isset($silentSignIn['maxAgeSeconds'])) {
                $options['maxAgeSeconds'] = $silentSignIn['maxAgeSeconds'];
            }
            $res = $client->risk->check($options);
            if (($res['prompt'] ?? true) !== false) {
                return null;
            }
            return [
                'requestId' => 'silent', 'user' => $user, 'action' => $action,
                'assurance' => ['phishingResistant' => false, 'method' => 'silent'],
                'confirmedVia' => 'SILENT', 'approvalProof' => null,
                // Nothing was sent to the phone; why Touchque let this known browser in.
                'reasons' => is_array($res['reasons'] ?? null) ? $res['reasons'] : [],
            ];
        } catch (\Throwable $err) {
            $client->log('warning', '[Touchque] silent sign-in check failed, asking the phone: ' . Config::describe($err));
            return null;
        }
    }
}
