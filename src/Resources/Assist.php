<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;
use Touchque\Exceptions\TouchqueConfigException;

/**
 * Help desk: IT working on a person's account in the open.
 *
 * 1. Before your help desk acts on someone's account: `open()` with the person
 *    and the signed-in agent. The person's phone gets a calm notice ("<agent>
 *    from IT is working on your account now"); while the session is open,
 *    their "someone says they're from IT" button shows this agent, and with
 *    none open it tells them to hang up (webhook ASSIST_CLAIM_UNVERIFIED).
 * 2. Before a sensitive action (a factor or password reset, an activation or
 *    recovery link, an unlock, a new phone, removing a passkey): `verify()`.
 *    Show `challengeCode` to the agent only; they read it to the person, who
 *    types it on their phone and approves with Face ID. Default deny.
 * 3. Right before the action: `spend()` (a passed check, for that action, at
 *    most ten minutes old, once). `unfreeze()` lifts a freeze the same way.
 *
 * No phone (error code `no_phone`, `route` `never_locked_out` in the data):
 * the person moves to a new phone with Never Locked Out; the help desk cannot.
 */
class Assist
{
    private const OPEN_OPTIONS = ['externalUsername', 'agent', 'reason', 'ttlMinutes', 'notify'];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Starts helping a person. A session of the same agent for the same person
     * is replaced.
     *
     * @param array $options
     *   - externalUsername (string, required)
     *   - agent (array, required): ['name' => string, 'title' => string, 'ref' => your id for the agent]
     *   - reason (string), ttlMinutes (int 5–120, default 30), notify (bool, default true)
     */
    public function open(array $options): array
    {
        $unknown = array_diff(array_map('strval', array_keys($options)), self::OPEN_OPTIONS);
        if ($unknown) {
            throw new TouchqueConfigException('assist->open(): unknown option(s) ' . implode(', ', $unknown)
                . ' (options are camelCase: ' . implode(', ', self::OPEN_OPTIONS) . ')');
        }
        if (empty($options['externalUsername']) || empty($options['agent']['name'])) {
            throw new TouchqueConfigException('assist->open() needs externalUsername and agent.name');
        }
        return $this->http->post('/assist', $options);
    }

    /** The session and its checks. Poll it while a check is `pending`. */
    public function get(string $id): array
    {
        self::requireNonEmpty('get', 'the session id', $id);
        return $this->http->get(self::path($id));
    }

    /**
     * A person's sessions, or every open one, newest first.
     *
     * @param array $options ['externalUsername' => string] and/or ['open' => true]
     */
    public function list(array $options): array
    {
        if (empty($options['externalUsername']) && empty($options['open'])) {
            throw new TouchqueConfigException('assist->list() needs externalUsername or open => true');
        }
        $params = [];
        if (!empty($options['externalUsername'])) {
            $params['externalUsername'] = $options['externalUsername'];
        }
        if (!empty($options['open'])) {
            $params['open'] = 'true';
        }
        $res = $this->http->get('/assist', $params);
        return $res['sessions'] ?? [];
    }

    /**
     * Asks the person's phone to confirm `$action` (`reset_2fa`, `reset_password`,
     * `activation_link`, `recovery_link`, `unlock`, `new_phone`, `remove_passkey`
     * or your own). Returns `requestId` and `challengeCode` (for the agent only).
     * Throws TouchqueAPIException `no_phone`, `assist_not_open` or `rate_limited`.
     */
    public function verify(string $id, string $action, ?string $actionText = null, ?array $details = null): array
    {
        self::requireNonEmpty('verify', 'the session id and an action', $id, $action);
        $body = ['action' => $action];
        if ($actionText !== null && $actionText !== '') {
            $body['actionText'] = $actionText;
        }
        if ($details) {
            $body['details'] = $details;
        }
        return $this->http->post(self::path($id, '/verify'), $body);
    }

    /** Uses a passed check for its action, right before you take it; `check_required` (428) otherwise. */
    public function spend(string $id, string $requestId, string $action): array
    {
        self::requireNonEmpty('spend', 'the session id, requestId and action', $id, $requestId, $action);
        return $this->http->post(self::path($id, '/spend'), ['requestId' => $requestId, 'action' => $action]);
    }

    /** Lifts the person's approval freeze with a passed check for `unlock`: ['unfrozen' => bool, 'session' => array]. */
    public function unfreeze(string $id, string $requestId): array
    {
        self::requireNonEmpty('unfreeze', 'the session id and requestId', $id, $requestId);
        return $this->http->post(self::path($id, '/unfreeze'), ['requestId' => $requestId]);
    }

    /** Stops helping; checks still waiting on the phone expire. */
    public function end(string $id, ?string $by = null, ?string $reason = null): array
    {
        self::requireNonEmpty('end', 'the session id', $id);
        $body = [];
        if ($by !== null && $by !== '') {
            $body['by'] = $by;
        }
        if ($reason !== null && $reason !== '') {
            $body['reason'] = $reason;
        }
        return $this->http->post(self::path($id, '/end'), $body);
    }

    /** The check of `$requestId` passed on the person's phone and was not used yet. */
    public static function checkPassed(array $session, string $requestId): bool
    {
        foreach ($session['checks'] ?? [] as $check) {
            if (($check['requestId'] ?? null) === $requestId) {
                return ($check['outcome'] ?? null) === 'verified' && empty($check['spentAt']);
            }
        }
        return false;
    }

    private static function path(string $id, string $rest = ''): string
    {
        return '/assist/' . rawurlencode($id) . $rest;
    }

    private static function requireNonEmpty(string $method, string $what, string ...$values): void
    {
        foreach ($values as $value) {
            if ($value === '') {
                throw new TouchqueConfigException("assist->$method() needs $what");
            }
        }
    }
}
