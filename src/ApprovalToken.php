<?php

namespace TouchQue;

use TouchQue\Exceptions\TouchQueApprovalMismatchException;

/**
 * What a partner's server checks before executing what an AI agent asked for:
 * the approval token's claims match the transaction (person, action type,
 * authorization details), and, offline, its ES256 signature against
 * TouchQue's keys (GET /agents/jwks.json).
 *
 * Matching rules (fixtures/agent-vectors.json): every expected field must be
 * equal, extra fields are ignored; amounts compare as decimals ("500" =
 * "500.00"), IBANs without spaces and in any case, currencies in any case; an
 * associative array matches a token with exactly one entry, a list matches
 * entry by entry with the same length.
 */
final class ApprovalToken
{
    private static function decimal($value): ?string
    {
        $text = trim((string)$value);
        if (!preg_match('/^\d+(\.\d+)?$/', $text)) {
            return null;
        }
        $parts = explode('.', $text, 2);
        $whole = ltrim($parts[0], '0');
        $whole = $whole === '' ? '0' : $whole;
        $frac = rtrim($parts[1] ?? '', '0');
        return $frac === '' ? $whole : "{$whole}.{$frac}";
    }

    private static function isList($value): bool
    {
        return is_array($value) && ($value === [] || array_keys($value) === range(0, count($value) - 1));
    }

    private static function same(string $key, $actual, $expected): bool
    {
        if (is_array($expected)) {
            return self::partial($actual, $expected);
        }
        if ($key === 'amount') {
            return self::decimal($actual) !== null && self::decimal($actual) === self::decimal($expected);
        }
        if ($key === 'iban' || $key === 'currency') {
            $norm = static fn ($v) => strtoupper(preg_replace('/\s+/', '', (string)$v));
            return is_string($actual) && $norm($actual) === $norm($expected);
        }
        return $actual === $expected;
    }

    private static function partial($actual, array $expected): bool
    {
        if (self::isList($expected)) {
            if (!self::isList($actual) || count($actual) !== count($expected)) {
                return false;
            }
            foreach ($expected as $i => $e) {
                if (!(is_array($e) ? self::partial($actual[$i], $e) : $actual[$i] === $e)) {
                    return false;
                }
            }
            return true;
        }
        if (!is_array($actual) || self::isList($actual)) {
            return false;
        }
        foreach ($expected as $k => $v) {
            if (!array_key_exists($k, $actual) || !self::same((string)$k, $actual[$k], $v)) {
                return false;
            }
        }
        return true;
    }

    /** Does $details (a token's authorization_details) say what $expected says? */
    public static function matches($details, array $expected): bool
    {
        if (!self::isList($details)) {
            return false;
        }
        if (self::isList($expected)) {
            if (count($details) !== count($expected)) {
                return false;
            }
            foreach ($expected as $i => $e) {
                if (!self::partial($details[$i], $e)) {
                    return false;
                }
            }
            return true;
        }
        return count($details) === 1 && self::partial($details[0], $expected);
    }

    /**
     * Throws unless the claims say what you expect.
     * $expect: user, type, authorizationDetails (each optional).
     */
    public static function assertMatches(array $claims, array $expect = []): void
    {
        if (isset($expect['user']) && ($claims['sub'] ?? null) !== $expect['user']) {
            throw new TouchQueApprovalMismatchException('TouchQue: the approval is for another person');
        }
        if (isset($expect['type']) && ($claims['type'] ?? null) !== $expect['type']) {
            throw new TouchQueApprovalMismatchException('TouchQue: the approval is for another action type (' . ($claims['type'] ?? '') . ')');
        }
        if (isset($expect['authorizationDetails']) && !self::matches($claims['authorization_details'] ?? null, $expect['authorizationDetails'])) {
            throw new TouchQueApprovalMismatchException('TouchQue: the approved details differ from what you are about to execute');
        }
    }

    /** ['header' => ..., 'claims' => ...] WITHOUT checking the signature. */
    public static function decode(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TouchQueApprovalMismatchException('TouchQue: not an approval token');
        }
        $header = json_decode(AgentKeys::b64urlDecode($parts[0]), true);
        $claims = json_decode(AgentKeys::b64urlDecode($parts[1]), true);
        if (!is_array($header) || !is_array($claims)) {
            throw new TouchQueApprovalMismatchException('TouchQue: not an approval token');
        }
        return ['header' => $header, 'claims' => $claims];
    }

    /**
     * Verifies an approval token offline: typ touchque-approval+jwt, ES256 by
     * a key of $jwks, not expired (30 s leeway), aud equal to $audience, then
     * $expect. $audience is required: /agents/jwks.json is one key set for
     * every Touchque workspace, so without it a token Touchque signed for
     * another workspace would pass. Pass your own
     * ($tq->agents->approvalAudience(), touchque:workspace:<id>), or use
     * $tq->agents->verifyApprovalToken, which fills it in. Does NOT make it
     * single-use: $tq->agents->redeemApproval does.
     */
    public static function verifyWith(string $token, array $jwks, ?string $audience = null, array $expect = [], ?int $now = null): array
    {
        if ($audience === null || $audience === '') {
            throw new TouchQueApprovalMismatchException("TouchQue: audience is required: your workspace's touchque:workspace:<id> (\$tq->agents->approvalAudience())");
        }
        $decoded = self::decode($token);
        $header = $decoded['header'];
        $claims = $decoded['claims'];
        if (($header['typ'] ?? '') !== 'touchque-approval+jwt' || ($header['alg'] ?? '') !== 'ES256') {
            throw new TouchQueApprovalMismatchException('TouchQue: not an approval token (typ/alg)');
        }
        $jwk = null;
        foreach ($jwks['keys'] ?? [] as $k) {
            if (($k['kid'] ?? null) === ($header['kid'] ?? null) && ($k['kty'] ?? '') === 'EC' && ($k['crv'] ?? '') === 'P-256') {
                $jwk = $k;
            }
        }
        if (!$jwk) {
            throw new TouchQueApprovalMismatchException('TouchQue: signed by an unknown key');
        }
        [$h, $p, $s] = explode('.', $token);
        $sig = AgentKeys::b64urlDecode($s);
        if (strlen($sig) !== 64 || openssl_verify("{$h}.{$p}", AgentKeys::rawToDer($sig), AgentKeys::ecPublicPem(AgentKeys::b64urlDecode($jwk['x']), AgentKeys::b64urlDecode($jwk['y'])), OPENSSL_ALGO_SHA256) !== 1) {
            throw new TouchQueApprovalMismatchException('TouchQue: the signature does not verify');
        }
        $now = $now ?? time();
        if (!is_numeric($claims['exp'] ?? null) || $claims['exp'] + 30 < $now) {
            throw new TouchQueApprovalMismatchException('TouchQue: the approval token expired');
        }
        $aud = $claims['aud'] ?? null;
        if (!is_string($aud) || $aud === '') {
            throw new TouchQueApprovalMismatchException('TouchQue: the approval token names no workspace');
        }
        if ($aud !== $audience) {
            throw new TouchQueApprovalMismatchException('TouchQue: the approval token is for another workspace');
        }
        self::assertMatches($claims, $expect);
        return $claims;
    }
}
