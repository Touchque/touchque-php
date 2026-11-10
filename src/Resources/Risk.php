<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;
use TouchQue\Exceptions\TouchQueConfigException;

/**
 * Silent sign-ins: ask TouchQue's risk engine whether a sign-in needs the
 * phone at all, and manage the browsers it knows for a user.
 *
 * A browser becomes known when the user approves a request on the phone (or
 * with a passkey) that carried the browser's device-bound key proof
 * (`$tq->login->request(..., $browserProof)`). Later, `check()` with a fresh
 * proof from the same browser answers `prompt => false` when nothing about the
 * sign-in is new. `check()` sends nothing to the phone.
 *
 * Options are arrays with camelCase keys, like the API:
 *
 *     $risk = $tq->risk->check(['externalUsername' => $user, 'browserProof' => $proof, 'clientIp' => $ip]);
 *     if ($risk['prompt'] === false) { signIn($user); }   // known browser, nothing new
 */
class Risk
{
    private const ASSURANCE = ['high', 'normal', 'low'];
    private const CHECK_OPTIONS = ['externalUsername', 'type', 'clientIp', 'userAgent', 'browserProof', 'clientSignals', 'deviceRisk', 'deviceRiskRequestId', 'maxAgeSeconds', 'context'];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Reads a `POST /risk/check` answer, failing closed: `prompt` is false ONLY
     * when the answer says exactly `prompt: false` (a boolean). Malformed
     * `reasons` become `[]`, and an unknown or missing `assurance` is `normal`.
     *
     * @param mixed $raw the decoded JSON answer
     * @return array{prompt: bool, reasons: array<int, array{code: string, text: string}>, assurance: string, silentMode: string}
     */
    public static function parseCheck($raw): array
    {
        $body = is_array($raw) && !self::isList($raw) ? $raw : [];
        $reasons = [];
        if (isset($body['reasons']) && is_array($body['reasons']) && self::isList($body['reasons'])) {
            foreach ($body['reasons'] as $r) {
                if (is_array($r) && isset($r['code']) && is_string($r['code'])) {
                    $reasons[] = ['code' => $r['code'], 'text' => isset($r['text']) && is_string($r['text']) ? $r['text'] : ''];
                }
            }
        }
        $assurance = $body['assurance'] ?? null;
        $out = [
            'prompt' => !(array_key_exists('prompt', $body) && $body['prompt'] === false),
            'reasons' => $reasons,
            'assurance' => is_string($assurance) && in_array($assurance, self::ASSURANCE, true) ? $assurance : 'normal',
            'silentMode' => ($body['silentMode'] ?? null) === 'shadow' ? 'shadow' : 'enforce',
        ];
        // "Why?": the check's case code (K7P-2QX), to show the user.
        if (isset($body['caseCode']) && is_string($body['caseCode'])) {
            $out['caseCode'] = $body['caseCode'];
        }
        return $out;
    }

    /**
     * Should this sign-in ask the phone? Sends nothing to the phone.
     * Skip the push only when `prompt` is `false`; on any error, ask as usual.
     *
     * @param array $options
     *   - externalUsername (string, required) the user in YOUR system
     *   - type             (string) the action the user is about to do (default 'LOGIN'); a critical action always asks
     *   - clientIp         (string) the end user's IP, compared with the networks of earlier approved sign-ins
     *   - userAgent        (string)
     *   - browserProof     (string) the browser's device-bound key proof (`X-TouchQue-Browser`), passed through untouched
     *   - clientSignals    (string) the end user's page check from @touchque/web (startClientSignals()->encode()): software driving the browser is never silent
     *   - deviceRisk       (string) the page's device report from @touchque/web (deviceRisk.collect): a device signal is never silent
     *   - deviceRiskRequestId (string) the page's identification (deviceRisk.identify), preferred over deviceRisk
     *   - maxAgeSeconds    (int >= 0) your own limit on how long ago the last phone approval in this browser may be;
     *                      0 = always ask. TouchQue never goes beyond its own limit (7 days).
     *   - context          (array) for your TouchQue Actions only (`event.context`)
     * @return array{prompt: bool, reasons: array<int, array{code: string, text: string}>, assurance: string, silentMode: string}
     *   `reasons` codes: known_browser, recent_approval, same_phone, familiar_network, no_risk_signal (silent);
     *   no_browser_key, new_browser, approval_too_old, critical_action, risk_signal, silent_mode_shadow, … (asked).
     *   `silentMode` 'shadow': silent sign-ins are only measured, so `prompt` is always true.
     *
     * @throws TouchQueConfigException when `externalUsername` is missing or an option is unknown or invalid.
     */
    public function check(array $options): array
    {
        self::rejectUnknown('check', $options, self::CHECK_OPTIONS);
        $user = self::requireUser('check', $options);
        $body = ['externalUsername' => $user];
        foreach (['type', 'clientIp', 'userAgent', 'browserProof', 'clientSignals', 'deviceRisk', 'deviceRiskRequestId'] as $key) {
            if (!isset($options[$key])) {
                continue;
            }
            if (!is_string($options[$key])) {
                throw new TouchQueConfigException("risk->check(): \"$key\" must be a string");
            }
            if ($options[$key] !== '') {
                $body[$key] = $options[$key];
            }
        }
        if (isset($options['maxAgeSeconds'])) {
            if (!is_int($options['maxAgeSeconds']) || $options['maxAgeSeconds'] < 0) {
                throw new TouchQueConfigException('risk->check(): "maxAgeSeconds" must be an integer >= 0 (0 = always ask)');
            }
            $body['maxAgeSeconds'] = $options['maxAgeSeconds'];
        }
        if (isset($options['context'])) {
            if (!is_array($options['context'])) {
                throw new TouchQueConfigException('risk->check(): "context" must be an array');
            }
            if ($options['context'] !== []) {
                $body['context'] = $options['context'];
            }
        }
        return self::parseCheck($this->http->post('/risk/check', $body));
    }

    /**
     * The browsers TouchQue knows for a user (for an "approved browsers" list in
     * your settings page): `['browsers' => [['thumbprint', 'label', 'createdAt',
     * 'lastMfaAt', 'lastMfaMethod', 'lastSeenAt', 'lastSilentAt'], ...]]`.
     *
     * @param array $options ['externalUsername' => string]
     */
    public function browsers(array $options): array
    {
        self::rejectUnknown('browsers', $options, ['externalUsername']);
        $user = self::requireUser('browsers', $options);
        $res = $this->http->get('/risk/browsers', ['externalUsername' => $user]);
        return ['browsers' => isset($res['browsers']) && is_array($res['browsers']) ? array_values($res['browsers']) : []];
    }

    /**
     * Forgets one browser (`thumbprint`) or all of a user's browsers: their next
     * sign-in asks the phone again. Call it after a password reset or when the
     * user signs out everywhere. Returns `['forgotten' => n]`.
     *
     * @param array $options ['externalUsername' => string, 'thumbprint' => ?string (leave out for all)]
     */
    public function forgetBrowsers(array $options): array
    {
        self::rejectUnknown('forgetBrowsers', $options, ['externalUsername', 'thumbprint']);
        $user = self::requireUser('forgetBrowsers', $options);
        $body = ['externalUsername' => $user];
        if (isset($options['thumbprint'])) {
            if (!is_string($options['thumbprint'])) {
                throw new TouchQueConfigException('risk->forgetBrowsers(): "thumbprint" must be a string');
            }
            if ($options['thumbprint'] !== '') {
                $body['thumbprint'] = $options['thumbprint'];
            }
        }
        return $this->http->post('/risk/browsers/forget', $body);
    }

    private static function requireUser(string $method, array $options): string
    {
        $user = $options['externalUsername'] ?? null;
        if (!is_string($user) || $user === '') {
            throw new TouchQueConfigException("risk->$method() needs the user (externalUsername)");
        }
        return $user;
    }

    /** A misspelt key (e.g. snake_case) would silently be dropped: refuse it instead. */
    private static function rejectUnknown(string $method, array $options, array $known): void
    {
        $unknown = array_diff(array_map('strval', array_keys($options)), $known);
        if ($unknown) {
            throw new TouchQueConfigException("risk->$method(): unknown option(s) " . implode(', ', $unknown)
                . ' (options are camelCase: ' . implode(', ', $known) . ')');
        }
    }

    /** array_is_list() polyfill (this SDK supports PHP 7.4+). */
    private static function isList(array $arr): bool
    {
        return $arr === [] || array_keys($arr) === range(0, count($arr) - 1);
    }
}
