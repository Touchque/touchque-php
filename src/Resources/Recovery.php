<?php

namespace TouchQue\Resources;

use TouchQue\Http\HttpClient;
use TouchQue\Exceptions\TouchQueConfigException;

/**
 * Never Locked Out: move a user whose phone is lost, dead or replaced to a
 * new phone without a help desk.
 *
 * 1. Let users name colleagues who can vouch for them (`setVouchers()`),
 *    behind an approval on their phone.
 * 2. When the phone is gone, after the password (or your IdP): `start()`.
 *    Show `bindUri` as a QR for the TouchQue app on the new phone, then poll
 *    `status()` and show each voucher's `code`: the user reads it to the
 *    colleague on a call, who types it on their own phone.
 * 3. After the cooling-off nobody vetoed, the account is on the new phone
 *    (`status === 'COMPLETED'`); critical actions wait 24 h (probation).
 *
 * Admins can stop a running recovery with `veto()`. Options are arrays with
 * camelCase keys, like the API:
 *
 *     $r = $tq->recovery->start(['externalUsername' => $user, 'clientIp' => $ip, 'displayName' => 'Ada']);
 *     showQr($r['bindUri']);   // the new phone scans it
 */
class Recovery
{
    public const OPEN_STATUSES = ['AWAITING_DEVICE', 'VOUCHING', 'COOLING'];
    private const START_OPTIONS = ['externalUsername', 'clientIp', 'userAgent', 'displayName', 'fallbackVouchers', 'required', 'coolOffMinutes', 'details', 'noticeDetails'];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /** A recovery still waiting for the new phone, the vouchers or the cooling-off. */
    public static function isOpen(array $recovery): bool
    {
        return in_array($recovery['status'] ?? null, self::OPEN_STATUSES, true);
    }

    /** The colleagues a user named, and whether each can vouch today. */
    public function vouchers(string $externalUsername): array
    {
        self::requireNonEmpty('vouchers', 'externalUsername', $externalUsername);
        return $this->http->get('/recovery/vouchers', ['externalUsername' => $externalUsername]);
    }

    /**
     * Replaces the user's vouchers (at most 5 are kept). Ask for the user's
     * phone first: whoever sets them chooses who may move the account.
     *
     * @param string[] $vouchers other users of your workspace
     */
    public function setVouchers(string $externalUsername, array $vouchers): array
    {
        self::requireNonEmpty('setVouchers', 'externalUsername', $externalUsername);
        foreach ($vouchers as $v) {
            if (!is_string($v)) {
                throw new TouchQueConfigException('recovery->setVouchers(): every voucher must be a string');
            }
        }
        return $this->http->post('/recovery/vouchers', ['externalUsername' => $externalUsername, 'vouchers' => array_values($vouchers)]);
    }

    /**
     * Starts moving the user to a new phone. Call it only after the first
     * factor. Throws TouchQueAPIException with error code `not_enough_vouchers`,
     * `recovery_in_progress`, `blocked`, `frozen` or `rate_limited`.
     *
     * @param array $options
     *   - externalUsername (string, required)
     *   - clientIp, userAgent, displayName (string)
     *   - fallbackVouchers (string[]) fill up a short named list, e.g. the organization's admins
     *   - required (int >= 2), coolOffMinutes (int >= 1): raise the floors (2 vouchers, 15 minutes)
     *   - details (array of ['label' => string, 'value' => string]) what the vouchers' phones show
     *   - noticeDetails (same shape) what the old phone shows (approve to move now, reject to stop)
     */
    public function start(array $options): array
    {
        $unknown = array_diff(array_map('strval', array_keys($options)), self::START_OPTIONS);
        if ($unknown) {
            throw new TouchQueConfigException('recovery->start(): unknown option(s) ' . implode(', ', $unknown)
                . ' (options are camelCase: ' . implode(', ', self::START_OPTIONS) . ')');
        }
        $user = $options['externalUsername'] ?? null;
        if (!is_string($user) || $user === '') {
            throw new TouchQueConfigException('recovery->start() needs the user (externalUsername)');
        }
        $body = ['externalUsername' => $user];
        foreach (['clientIp', 'userAgent', 'displayName'] as $key) {
            if (isset($options[$key]) && $options[$key] !== '') {
                $body[$key] = (string)$options[$key];
            }
        }
        if (!empty($options['fallbackVouchers'])) {
            $body['fallbackVouchers'] = array_values($options['fallbackVouchers']);
        }
        foreach (['required', 'coolOffMinutes'] as $key) {
            if (isset($options[$key])) {
                if (!is_int($options[$key]) || $options[$key] < 1) {
                    throw new TouchQueConfigException("recovery->start(): \"$key\" must be a positive integer");
                }
                $body[$key] = $options[$key];
            }
        }
        foreach (['details', 'noticeDetails'] as $key) {
            if (!empty($options[$key])) {
                $body[$key] = array_values($options[$key]);
            }
        }
        return $this->http->post('/recovery/start', $body);
    }

    /** The recovery now, with its receipt chain. Poll it while the user waits. */
    public function status(string $recoveryId): array
    {
        self::requireNonEmpty('status', 'recoveryId', $recoveryId);
        return $this->http->get('/recovery/' . rawurlencode($recoveryId));
    }

    /**
     * A user's recoveries, or (`open => true`) every running one of your workspace.
     *
     * @param array $options ['externalUsername' => ?string, 'open' => ?bool]
     */
    public function list(array $options): array
    {
        $params = [];
        if (!empty($options['externalUsername'])) {
            $params['externalUsername'] = (string)$options['externalUsername'];
        }
        if (!empty($options['open'])) {
            $params['open'] = 'true';
        }
        if (!$params) {
            throw new TouchQueConfigException('recovery->list() needs externalUsername or open => true');
        }
        $res = $this->http->get('/recovery', $params);
        return isset($res['recoveries']) && is_array($res['recoveries']) ? array_values($res['recoveries']) : [];
    }

    /** Stops a running recovery (e.g. an admin who does not believe it). Does not freeze the user. */
    public function veto(string $recoveryId, ?string $by = null, ?string $reason = null): array
    {
        self::requireNonEmpty('veto', 'recoveryId', $recoveryId);
        $body = [];
        if ($by !== null && $by !== '') {
            $body['by'] = $by;
        }
        if ($reason !== null && $reason !== '') {
            $body['reason'] = $reason;
        }
        return $this->http->post('/recovery/' . rawurlencode($recoveryId) . '/veto', $body);
    }

    private static function requireNonEmpty(string $method, string $name, string $value): void
    {
        if ($value === '') {
            throw new TouchQueConfigException("recovery->$method() needs $name");
        }
    }
}
