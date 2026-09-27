<?php

namespace TouchQue;

use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Exceptions\TouchQueNetworkException;

/**
 * Framework-agnostic step-up guard. `TouchQue\Laravel\TouchQueMiddleware` is
 * a thin wrapper over `Guard::run()`.
 *
 * Contract (same in every TouchQue server SDK):
 *   1st request            -> 202 {"touchque": step, "token": ...}   show the step in your UI
 *   repeat with the token   -> 202 while waiting, then the protected action runs once
 *   refused                 -> 403 / 408 / 423 / 429 {"touchque": {"state": ..., ...}}
 *
 * Request headers the browser sends back:
 *   X-TouchQue-Token         the token from the last response
 *   X-TouchQue-Offline: 1    switch to offline approval (phone has no internet)
 *   X-TouchQue-Code          the code from the phone (offline QR code, or with
 *   X-TouchQue-Code-Type: totp   the rolling time-based code)
 */
class Guard
{
    public const TOKEN_HEADER = 'x-touchque-token';
    public const OFFLINE_HEADER = 'x-touchque-offline';
    public const CODE_HEADER = 'x-touchque-code';
    public const CODE_TYPE_HEADER = 'x-touchque-code-type';

    private const TOKEN_TTL_MS = 10 * 60 * 1000;

    private const STATUS = [
        'waiting' => 202, 'enroll' => 202, 'passkey_required' => 202, 'offline' => 202,
        'approved' => 200, 'rejected' => 403, 'blocked' => 403, 'expired' => 408, 'frozen' => 423, 'rate_limited' => 429,
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
     * Runs one step of the guard. Returns either
     * `["approved" => [...], "status" => 200]` (run your protected action) or
     * `["status" => <code>, "body" => ["touchque" => step, "token" => ...]]`
     * (send that JSON body with that status code).
     */
    public static function run(
        TouchQue $client,
        ?string $user,
        string $action,
        ?array $details = null,
        ?string $referenceId = null,
        ?string $ip = null,
        ?string $userAgent = null,
        ?string $token = null,
        bool $offline = false,
        ?string $code = null,
        ?string $codeType = null
    ): array {
        if (!$user) {
            return ['status' => 401, 'body' => [
                'touchque' => ['state' => 'blocked', 'reason' => 'unauthenticated'],
                'error' => ['code' => 'unauthenticated', 'message' => 'Sign in first.'],
            ]];
        }

        $norm = Steps::normalizeDetails($details);
        $base = ['u' => $user, 'a' => $action, 'd' => Steps::detailsDigest($details), 'r' => $referenceId];
        $secret = $client->getApiSecret();

        $issue = function (array $step, array $extra = []) use ($norm, $base, $secret): array {
            if ($norm && empty($step['details']) && ($step['state'] ?? null) !== 'blocked') {
                $step['details'] = $norm;
            }
            $claims = array_merge($base, [
                'st' => $step['state'], 'rid' => $step['requestId'] ?? null, 'n' => $step['number'] ?? null,
                'oc' => $step['offline']['challengeId'] ?? null, 'exp' => (int)(microtime(true) * 1000) + self::TOKEN_TTL_MS,
            ], $extra);
            return ['status' => self::STATUS[$step['state']], 'body' => ['touchque' => $step, 'token' => Steps::signGuardToken($secret, $claims)]];
        };

        try {
            $claims = Steps::verifyGuardToken($secret, $token);
            $bound = ($claims && $claims['u'] === $base['u'] && $claims['a'] === $base['a']
                && $claims['d'] === $base['d'] && $claims['r'] === $base['r']) ? $claims : null;

            // Offline: the user typed the code from the phone.
            if ($bound && $code && (($bound['st'] ?? null) === 'offline' || $codeType === 'totp')) {
                $isTotp = $codeType === 'totp';
                $res = $isTotp
                    ? $client->offline->verifyTotp($user, $code, $action, $ip)
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
                    return $issue(['state' => 'offline', 'offline' => ['challengeId' => (string)($bound['oc'] ?? ''), 'attemptsLeft' => $res['attemptsLeft'] ?? null]], ['oc' => $bound['oc'] ?? null]);
                }
                if (($res['reason'] ?? null) === 'invalid_code') {
                    return $issue(['state' => 'offline', 'reason' => 'invalid_code'], ['oc' => $bound['oc'] ?? null]);
                }
                return $issue(['state' => ($res['reason'] ?? null) === 'expired' ? 'expired' : 'blocked', 'reason' => $res['reason'] ?? 'offline_failed']);
            }

            if ($offline) {
                try {
                    $ch = $client->offline->challenge($user, $action, $norm ?: null, $ip, $userAgent);
                    return $issue(['state' => 'offline', 'offline' => [
                        'challengeId' => $ch['challengeId'] ?? null, 'qrDataUrl' => $ch['qrDataUrl'] ?? null,
                        'expiresAt' => $ch['expiresAt'] ?? null, 'totpAvailable' => $ch['totpAvailable'] ?? null,
                    ]]);
                } catch (TouchQueAPIException $err) {
                    if ($err->getStatus() < 500) {
                        return $issue(['state' => 'blocked', 'reason' => $err->getErrorCode() ?? ($err->getData()['error'] ?? 'offline_unavailable')]);
                    }
                    throw $err;
                }
            }

            // Waiting on a push / passkey: poll, and run the action once approved.
            if ($bound && !empty($bound['rid']) && in_array($bound['st'] ?? null, ['waiting', 'passkey_required'], true)) {
                $now = Steps::check($client, $bound['rid']);
                if ($now['state'] === 'approved') {
                    try {
                        return ['status' => 200, 'approved' => Steps::complete($client, $bound['rid'], $user, $action, $details, $referenceId)];
                    } catch (TouchQueAPIException $err) {
                        if ($err->getStatus() === 409) {
                            return $issue(['state' => 'expired', 'reason' => $err->getErrorCode() ?? 'already_used']);
                        }
                        throw $err;
                    }
                }
                if (in_array($now['state'], ['waiting', 'passkey_required'], true)) {
                    return $issue(['state' => $now['state'], 'requestId' => $bound['rid'], 'number' => $bound['n'] ?? null], ['n' => $bound['n'] ?? null]);
                }
                return $issue(['state' => $now['state'], 'requestId' => $bound['rid']]);
            }

            // Anything else (no/foreign token, enrollment finished, new attempt): start.
            return $issue(Steps::start($client, $action, $user, $norm ?: null, $referenceId, $ip, $userAgent));
        } catch (TouchQueConfigException $err) {
            error_log('[TouchQue] ' . $err->getMessage());
            return ['status' => 500, 'body' => [
                'touchque' => ['state' => 'blocked', 'reason' => 'misconfigured'],
                'error' => ['code' => 'misconfigured', 'message' => 'Two-factor approval is not configured correctly.'],
            ]];
        } catch (TouchQueNetworkException | TouchQueAPIException $err) {
            error_log('[TouchQue] approval failed: ' . $err->getMessage());
            return ['status' => 503, 'body' => [
                'touchque' => ['state' => 'blocked', 'reason' => 'unavailable'],
                'error' => ['code' => 'unavailable', 'message' => 'Two-factor approval is temporarily unavailable.'],
            ]];
        }
    }
}
