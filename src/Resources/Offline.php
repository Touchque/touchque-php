<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;
use Touchque\Exceptions\TouchqueAPIException;

/** Offline Sign — QR challenge / typed code approvals that work with the
 * phone offline (no internet on the device). */
class Offline
{
    private const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    private const DEVICE_CODE_LENGTH = 10;

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Issues an offline QR challenge. Returns
     * `{ challengeId, qr, qrFormat, qrDataUrl, expiresAt, expiresInSeconds, totpAvailable }`
     * (+ `challengeCode` when number matching applies: print it under the QR; the phone
     * offers it among two decoys and the user taps the match).
     * `$details` is REQUIRED for critical action types.
     *
     * `$requestId` is the push this QR is a fallback for: once the phone REJECTS it the QR is
     * dead (no new QR is issued, a code for the old one is refused with `request_rejected`), and a
     * push with number matching makes the QR show the same number. Always pass it when the QR
     * follows a push.
     *
     * `$qrFormat = 'compact'`: a smaller QR (`qr` starts with `TQ3:`) for terminals and small
     * screens, the same challenge and the same 7-character code; it carries no location block, so
     * put what the phone should show in `$details`. The default is `'standard'` (`TQ2.`); the
     * answer's `qrFormat` says which format `qr` is. `$includeQrTerminal = true` adds `qrTerminal`:
     * the QR drawn with Unicode half blocks (lines separated by "\n"), ready to print in a terminal
     * (null when it could not be drawn).
     */
    public function challenge(
        string $externalUsername,
        string $type = 'LOGIN',
        ?array $details = null,
        ?string $clientIp = null,
        ?string $userAgent = null,
        ?int $ttlSeconds = null,
        bool $includeQrImage = true,
        ?string $requestId = null,
        bool $requireNumberMatch = false,
        ?string $qrFormat = null,
        bool $includeQrTerminal = false
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
        if ($requestId !== null) {
            $body['requestId'] = $requestId;
        }
        if ($requireNumberMatch) {
            $body['requireNumberMatch'] = true;
        }
        if ($qrFormat !== null) {
            $body['qrFormat'] = $qrFormat;
        }
        if ($includeQrTerminal) {
            $body['includeQrTerminal'] = true;
        }
        return $this->http->post('/offline/challenge', $body);
    }

    /**
     * Verifies the 7-character code shown on the phone. Never throws for a
     * wrong/expired/used code — check `approved`; `reason` is one of
     * invalid_code | locked | expired | used | unknown_challenge |
     * request_rejected | too_many_failures | device_not_enrolled.
     */
    public function verify(string $challengeId, string $code): array
    {
        return $this->notApprovedAsResult(fn () => $this->http->post('/offline/verify', [
            'challengeId' => $challengeId,
            'code' => $code,
        ]));
    }

    /**
     * Verifies the rolling time-based code (no QR scan needed). Refused for critical action types.
     * `$requestId`: the push this sign-in belongs to — a code is refused (`request_rejected`) once the phone rejected it.
     */
    public function verifyTotp(string $externalUsername, string $code, string $type = 'LOGIN', ?string $clientIp = null, ?string $requestId = null): array
    {
        $body = ['externalUsername' => $externalUsername, 'code' => $code, 'type' => $type];
        if ($clientIp !== null) {
            $body['clientIp'] = $clientIp;
        }
        if ($requestId !== null) {
            $body['requestId'] = $requestId;
        }
        return $this->notApprovedAsResult(fn () => $this->http->post('/offline/totp/verify', $body));
    }

    /**
     * For checking typed codes while your server cannot reach Touchque (an outage): salted, slow
     * digests of each user's next OUTAGE codes for one scope, never a key. Outage codes are not the
     * normal time-based code: each scope (an organization, or your own outage server) has its own,
     * the user's phone shows them under the normal code ("<name>: code for when Touchque can't be
     * reached") once a call has named the scope for the user, and `verifyTotp()` never accepts them.
     *
     * `$scope` is required: `['id' => ..., 'name' => ...]`, `id` 1-64 characters of a-z, 0-9, ".", "_",
     * "-" (compared in lower case), `name` 1-80 characters shown on the phone. Up to 1,000 users and
     * 24,000 user-steps a call; `$steps` 1-480 (default 480, four hours) from `$fromStep` (default:
     * the current 30-second step). Returns
     * `{ stepSeconds, fromStep, steps, notAfterStep, scope, digestsPerStep, kdf, users: [{ externalUsername, fromStep, salt, digests }] }`
     * with only the users who can use time-based codes now and whose phone shows this scope. Check a
     * typed code with `matchTotpVerifier()`. Requires the workspace policies `offlineTotpEnabled` and
     * `outageVerifiersEnabled`. Fetch again every few minutes from the step you have: removed and
     * frozen users fall out. Quotas are per scope (429 `scope_quota_exceeded`) and per workspace. A
     * call without a scope is refused with 400 `scope_required`.
     *
     * @param array{id: string, name: string} $scope
     */
    public function totpVerifiers(array $externalUsernames, array $scope, ?int $fromStep = null, ?int $steps = null): array
    {
        $body = ['externalUsernames' => array_values($externalUsernames), 'scope' => ['id' => $scope['id'], 'name' => $scope['name']]];
        if ($fromStep !== null) {
            $body['fromStep'] = $fromStep;
        }
        if ($steps !== null) {
            $body['steps'] = $steps;
        }
        return $this->http->post('/offline/totp/verifiers', $body);
    }

    /**
     * Checks a typed code against one user's digests from `totpVerifiers()` without calling
     * Touchque. Returns the step the code belongs to (the current one or one either side), or
     * null. Accept each step once: remember the step you accepted for the user and refuse codes
     * for it or an older one. `$at`: Unix time (default now).
     */
    public static function matchTotpVerifier(array $verifiers, array $user, string $code, ?int $at = null): ?int
    {
        $given = str_replace([' ', '-', "\t"], '', strtoupper($code));
        if (strlen($given) !== 7 || strspn($given, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') !== 7) {
            return null;
        }
        $now = intdiv($at ?? time(), (int) $verifiers['stepSeconds']);
        $salt = base64_decode($user['salt'], true);
        if ($salt === false) {
            return null;
        }
        $digests = base64_decode($user['digests'], true);
        $length = (int) $verifiers['kdf']['length'];
        $per = (int) ($verifiers['digestsPerStep'] ?? 0) ?: 2;
        if ($digests === false || $length <= 0) {
            return null;
        }
        foreach ([$now, $now - 1, $now + 1] as $step) {
            if ($step < $user['fromStep'] || $step > $verifiers['notAfterStep']) {
                continue;
            }
            $i = ($step - $user['fromStep']) * $per * $length;
            if ($i + $per * $length > strlen($digests)) {
                continue;
            }
            $got = hash_pbkdf2('sha256', $given, $salt . ':' . $step, (int) $verifiers['kdf']['iterations'], $length, true);
            for ($k = 0; $k < $per; $k++) {
                if (hash_equals(substr($digests, $i + $k * $length, $length), $got)) {
                    return $step;
                }
            }
        }
        return null;
    }

    /**
     * The next offline sign-ins of a person on one device (a laptop, a kiosk, a field tablet) that
     * must sign them in with no network. Ask only right after a sign-in the person approved on the
     * phone at that device itself, never for a remote session.
     *
     * `$scope` is the device: `['id' => ..., 'name' => ...]`, `id` 1-64 characters of a-z, 0-9, ".",
     * "_", "-" starting with a letter or a digit (compared in lower case; one id per device install),
     * `name` 1-80 characters shown on the phone. `$account` (1-255 characters, shown on the phone) is
     * the account the person signs in to there. `$count` 1-20 slots (default 10), valid `$validDays`
     * 1-30 days (default 14). Returns
     * `{ scope: { id, name, epoch }, account, validUntil, codeLength, kdf: { name, iterations, length }, slots: [{ index, salt, digest, qr, qrTerminal }] }`:
     * per slot the slow digest of a 10-character code and a QR (`TQ4:`) only the person's phone
     * opens; nothing in it can produce a code. Offline, the device shows the lowest unused slot's QR,
     * the person scans it with the Touchque app, approves and types the code (XXXXX-XXXXX); check it
     * with `Offline::verifyDeviceCode()`. Indexes continue from the device's last pack and are never
     * issued twice.
     *
     * Requires the workspace policies `offlineSignEnabled` and `offlineDevicePacksEnabled` (403
     * `offline_device_packs_disabled`); refused under a passkey-only policy (403
     * `phishing_resistant_required`), for a phone not enrolled for offline sign (409
     * `device_not_enrolled_for_offline`), for a revoked device (409 `scope_revoked`) and after 12
     * packs an hour per person and device (429 `too_many_packs`).
     *
     * @param array{id: string, name: string} $scope
     */
    public function issueDevicePack(string $externalUsername, array $scope, string $account, ?int $count = null, ?int $validDays = null): array
    {
        $body = [
            'externalUsername' => $externalUsername,
            'scope' => ['id' => $scope['id'], 'name' => $scope['name']],
            'account' => $account,
        ];
        if ($count !== null) {
            $body['count'] = $count;
        }
        if ($validDays !== null) {
            $body['validDays'] = $validDays;
        }
        return $this->http->post('/offline/device-packs', $body);
    }

    /**
     * A device's offline sign-ins stop (lost, stolen, reinstalled): it gets no more packs, and the
     * person's phone refuses its codes once it has the list. Without `$externalUsername`, every
     * person's packs on that device. `$reason`: up to 64 characters (default `revoked`). Returns
     * `{ revoked }`, how many packs were revoked. A reinstalled device needs a new scope id.
     */
    public function revokeDeviceScope(string $scopeId, ?string $externalUsername = null, ?string $reason = null): array
    {
        $body = ['scopeId' => $scopeId];
        if ($externalUsername !== null) {
            $body['externalUsername'] = $externalUsername;
        }
        if ($reason !== null) {
            $body['reason'] = $reason;
        }
        return $this->http->post('/offline/device-packs/revoke', $body);
    }

    /**
     * The slots a device accepted while it had no network, sent once it is back online: `$used` is
     * 1-100 `['index' => ..., 'at' => ...]` (`at`: a DateTimeInterface or an ISO 8601 string, within
     * the last 60 days). Touchque writes one log row per slot with the time it happened. Returns
     * `{ recorded, ignored }` (an index never issued or repeated, or a time out of range, is
     * ignored); 404 `unknown_scope` when the device has no pack for that person.
     *
     * @param array<int, array{index: int, at: \DateTimeInterface|string}> $used
     */
    public function reportDevicePackUse(string $scopeId, string $externalUsername, array $used): array
    {
        $entries = [];
        foreach ($used as $u) {
            $at = $u['at'];
            if ($at instanceof \DateTimeInterface) {
                $utc = $at instanceof \DateTime ? \DateTimeImmutable::createFromMutable($at) : $at;
                $at = $utc->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\\TH:i:s.v\\Z');
            }
            $entries[] = ['index' => $u['index'], 'at' => $at];
        }
        return $this->http->post('/offline/device-packs/report', [
            'scopeId' => $scopeId,
            'externalUsername' => $externalUsername,
            'used' => $entries,
        ]);
    }

    /**
     * A typed offline sign-in code in its canonical form: upper case, without spaces or dashes. Null
     * unless it is exactly 10 characters of the codes' alphabet (A-Z and 2-9 without I and O).
     */
    public static function normalizeDeviceCode(string $code): ?string
    {
        $given = strtr(str_replace([' ', "\t", "\n", "\r", "\f", "\v", '-'], '', $code), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
        if (strlen($given) !== self::DEVICE_CODE_LENGTH || strspn($given, self::CODE_ALPHABET) !== self::DEVICE_CODE_LENGTH) {
            return null;
        }
        return $given;
    }

    /** An offline sign-in code the way the phone shows it, `XXXXX-XXXXX`; null unless `normalizeDeviceCode()` accepts it. */
    public static function formatDeviceCode(string $code): ?string
    {
        $given = self::normalizeDeviceCode($code);
        return $given === null ? null : substr($given, 0, 5) . '-' . substr($given, 5);
    }

    /**
     * Checks the code a person typed against one slot of an offline sign-in pack (the pack's `kdf`
     * and one of its `slots`), on the device and with no network: PBKDF2-SHA256(code, salt || ":" ||
     * index, kdf iterations, kdf length) compared in constant time with the slot's digest. Case,
     * spaces and dashes are ignored; anything that is not 10 characters of the codes' alphabet is
     * false without computing the digest, and so is a KDF other than pbkdf2-sha256. Check the lowest
     * unused slot only. The digest takes a moment by design (600,000 iterations).
     *
     * @param array{name?: string, iterations: int, length: int} $kdf
     * @param array{index: int, salt: string, digest: string} $slot
     */
    public static function verifyDeviceCode(array $kdf, array $slot, string $code): bool
    {
        $given = self::normalizeDeviceCode($code);
        $name = $kdf['name'] ?? null;
        if ($given === null || ($name !== null && $name !== '' && $name !== 'pbkdf2-sha256')) {
            return false;
        }
        $iterations = $kdf['iterations'] ?? null;
        $length = $kdf['length'] ?? null;
        $index = $slot['index'] ?? null;
        if (!is_int($iterations) || !is_int($length) || !is_int($index)
            || $iterations < 1 || $iterations > 0x7fffffff || $length < 1 || $index < 1) {
            return false;
        }
        $salt = is_string($slot['salt'] ?? null) ? base64_decode($slot['salt'], true) : false;
        $digest = is_string($slot['digest'] ?? null) ? base64_decode($slot['digest'], true) : false;
        if ($salt === false || $digest === false || strlen($digest) !== $length) {
            return false;
        }
        return hash_equals($digest, hash_pbkdf2('sha256', $given, $salt . ':' . $index, $iterations, $length, true));
    }

    private function notApprovedAsResult(callable $call): array
    {
        try {
            return $call();
        } catch (TouchqueAPIException $err) {
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
