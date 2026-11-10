<?php

namespace TouchQue\Resources;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Http\HttpClient;

/**
 * Device risk (a paid add-on, off until your workspace turns it on): a visitor
 * ID for every browser on your sign-up, password-reset, sign-in or approval page.
 *
 * The page identifies with `@touchque/web` (`deviceRisk.identify({ siteKey, purpose })`
 * gives `{ visitorId, requestId, confidence }`) and sends you the requestId.
 * Never trust the page's copy: read the identification here (`getEvent`) or
 * check it for an account (`check`). TouchQue keeps keyed hashes only, with a
 * key of your workspace alone, and its risk engine decides.
 *
 * Every signal only ever asks for more: `stepUp` means an extra check on this
 * page (an emailed code, a passkey, a number-matched approval), never a
 * refusal. For sign-ins, pass the requestId as `deviceRiskRequestId` to
 * `login->request` / `risk->check` instead. Collect it only on these pages and
 * name it in your privacy notice.
 *
 * With the script tag (device.js), the form arrives with `touchque_request_id`:
 *
 *     $r = $tq->deviceRisk->check($_POST['touchque_request_id'] ?? null, 'sign_in', $email);
 *
 * Pass it as it came. Missing, empty, made up or expired, it is still a
 * verdict (`report`: missing, unknown, expired; the signal
 * device_identification_missing), never an exception: a page without the tag,
 * or with it blocked, only gets the visitor a step-up.
 */
class DeviceRisk
{
    /** The pages a device report may come from. */
    public const EVENTS = ['sign_in', 'sign_up', 'password_reset', 'approval'];
    /** What the page had sent: ok, replayed, or no usable identification. */
    public const REPORTS = ['ok', 'replayed', 'missing', 'unknown', 'expired', 'invalid'];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    private const REQUEST_ID = '/^dre_[A-Za-z0-9_-]{22}$/';

    /**
     * Checks the page's identification for an account: binds it (one account
     * per identification, 15 minutes) and asks the risk engine. Pass the form
     * field as it came: null, empty or made up is still a verdict (`report`:
     * missing, unknown), never an exception. 409 `device_risk_off` until your
     * workspace turns Device risk on.
     *
     *     $r = $tq->deviceRisk->check($_POST['touchque_request_id'] ?? null, 'sign_up', $email, $_SERVER['REMOTE_ADDR']);
     *     if ($r['stepUp']) { askForEmailCode(); }   // never refuse on it alone
     *
     * @param mixed   $requestId  the touchque_request_id form field (the script tag) or deviceRisk.identify's requestId, as it came
     * @param ?string $deviceRisk instead of $requestId: the page's report (deviceRisk.collect), relayed untouched
     * @throws TouchQueConfigException when the event is unknown (a bug in your code, not the page).
     */
    public function check($requestId, string $event = 'sign_in', ?string $externalUsername = null, ?string $clientIp = null, ?string $deviceRisk = null): array
    {
        if (!in_array($event, self::EVENTS, true)) {
            throw new TouchQueConfigException('deviceRisk->check(): event must be one of ' . implode(', ', self::EVENTS));
        }
        $body = [];
        if (is_string($requestId) && $requestId !== '') {
            $body['requestId'] = substr($requestId, 0, 64);
        } elseif ($deviceRisk !== null && $deviceRisk !== '') {
            $body['deviceRisk'] = $deviceRisk;
        }
        $body['event'] = $event;
        if ($externalUsername !== null && $externalUsername !== '') {
            $body['externalUsername'] = $externalUsername;
        }
        if ($clientIp !== null && $clientIp !== '') {
            $body['clientIp'] = $clientIp;
        }
        return self::parse($this->http->post('/device-risk/check', $body));
    }

    /**
     * Your workspace's identifications, newest first, one page at a time: a date range
     * (`from`/`to`: YYYY-MM-DD or ISO times; 7 days by default, at most 90, within your
     * retention) and any of `signal`, `stepUp`, `kind`, `origin`, `ip` (an address or a
     * CIDR range, never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100)
     * and the opaque `cursor`. Pass `nextCursor` back as `cursor` until it is null; do not
     * page by moving the dates. A search that would read too much is a 422
     * `search_too_broad`: narrow the range or add a filter.
     * Returns `['events' => [...], 'nextCursor' => ?string, 'from' => string, 'to' => string]`.
     */
    public function searchEvents(array $options = []): array
    {
        $params = [];
        foreach (['from', 'to', 'signal', 'kind', 'origin', 'ip', 'account', 'visitorId', 'requestId', 'cursor'] as $k) {
            if (isset($options[$k]) && is_string($options[$k]) && $options[$k] !== '') {
                $params[$k] = $options[$k];
            }
        }
        if (isset($options['stepUp']) && is_bool($options['stepUp'])) {
            $params['stepUp'] = $options['stepUp'] ? 'true' : 'false';
        }
        if (array_key_exists('limit', $options)) {
            $limit = $options['limit'];
            if (!is_int($limit) || $limit < 1 || $limit > 100) {
                throw new TouchQueConfigException('deviceRisk->searchEvents() limit must be 1 to 100');
            }
            $params['limit'] = $limit;
        }
        $raw = $this->http->get('/device-risk/events', $params);
        $next = $raw['nextCursor'] ?? null;
        return [
            'events' => isset($raw['events']) && is_array($raw['events']) ? $raw['events'] : [],
            'nextCursor' => is_string($next) && $next !== '' ? $next : null,
            'from' => is_string($raw['from'] ?? null) ? $raw['from'] : '',
            'to' => is_string($raw['to'] ?? null) ? $raw['to'] : '',
        ];
    }

    /** The trusted identification behind a requestId: the visitor, how sure, what the page showed, the engine's verdict. */
    public function getEvent(string $requestId): array
    {
        if (!preg_match(self::REQUEST_ID, $requestId)) {
            throw new TouchQueConfigException('deviceRisk->getEvent() needs a requestId (dre_...)');
        }
        return $this->http->get('/device-risk/events/' . rawurlencode($requestId));
    }

    /** Reads an answer, failing toward asking: `stepUp` is true unless it says exactly false; junk signals are dropped. */
    public static function parse($raw): array
    {
        $body = is_array($raw) ? $raw : [];
        $signals = [];
        foreach (is_array($body['signals'] ?? null) ? $body['signals'] : [] as $s) {
            if (!is_array($s) || !is_string($s['code'] ?? null)) {
                continue;
            }
            $item = [
                'code' => $s['code'],
                'text' => is_string($s['text'] ?? null) ? $s['text'] : '',
                'strength' => in_array($s['strength'] ?? null, ['passkey', 'none'], true) ? $s['strength'] : 'number_match',
            ];
            if (is_bool($s['enforced'] ?? null)) {
                $item['enforced'] = $s['enforced'];
            }
            if (is_array($s['evidence'] ?? null)) {
                $item['evidence'] = $s['evidence'];
            }
            $signals[] = $item;
        }
        $out = [
            'report' => in_array($body['report'] ?? null, self::REPORTS, true) ? $body['report'] : 'invalid',
            'requestId' => is_string($body['requestId'] ?? null) ? $body['requestId'] : null,
            'visitorId' => is_string($body['visitorId'] ?? null) ? $body['visitorId'] : null,
            'confidence' => is_int($body['confidence'] ?? null) || is_float($body['confidence'] ?? null) ? $body['confidence'] : null,
            'visitor' => is_array($body['visitor'] ?? null) ? $body['visitor'] : null,
            'counts' => is_array($body['counts'] ?? null) ? $body['counts'] : null,
            // The address (never coordinates), the visitor's counts, one answer to "a bot?" (detected | suspected | not_detected).
            'network' => is_array($body['network'] ?? null) ? $body['network'] : null,
            'velocity' => is_array($body['velocity'] ?? null) ? $body['velocity'] : null,
            'bot' => is_array($body['bot'] ?? null) ? $body['bot'] : null,
            'signals' => $signals,
            'stepUp' => ($body['stepUp'] ?? null) !== false,
            'wouldStepUp' => ($body['wouldStepUp'] ?? null) === true,
            'requires' => in_array($body['requires'] ?? null, ['number_match', 'passkey'], true) ? $body['requires'] : 'none',
            'mode' => ($body['mode'] ?? null) === 'enforce' ? 'enforce' : 'shadow',
            // The engine's state for this check; 'unavailable' when the risk engine could not be reached and the verdict is a safe default.
            'engine' => is_string($body['engine'] ?? null) ? $body['engine'] : null,
        ];
        if (is_string($body['caseCode'] ?? null)) {
            $out['caseCode'] = $body['caseCode'];
        }
        return $out;
    }
}
