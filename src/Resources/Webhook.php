<?php

namespace Touchque\Resources;

use Touchque\Config;
use Touchque\Exceptions\TouchqueWebhookReplayException;
use Touchque\Exceptions\TouchqueWebhookSignatureException;
use Touchque\Webhook\ReplayCache;

class Webhook
{
    /** Replay window (seconds): reject a callback whose signed `timestamp` is older/newer than this. */
    private const DEFAULT_TOLERANCE_SECONDS = 300;

    // `reason` values of a REJECTED login webhook. Treat a value you do not know as a rejection.
    public const REASON_USER_REJECTED = 'user_rejected';
    /** The user said "this wasn't me": 2FA is frozen. */
    public const REASON_USER_REPORTED_FRAUD = 'user_reported_fraud';
    /** The user said someone on the phone told them to approve: 2FA is frozen; treat it as a takeover in progress. */
    public const REASON_USER_REPORTED_COACHED = 'user_reported_coached';
    /** An AI agent's request: the user said no and blocked the agent from asking them again (no 2FA freeze). */
    public const REASON_USER_BLOCKED_AGENT = 'user_blocked_agent';
    public const REASON_RISK_REVERSED = 'risk_reversed';
    public const REASON_RISK_STEP_UP = 'risk_step_up';
    public const REASON_APPROVAL_SIGNATURE_INVALID = 'approval_signature_invalid';
    public const REASON_DEVICE_INTEGRITY_FAILED = 'device_integrity_failed';
    /** Vishing Shield: approved during a call (or with the screen shared / remote-controlled), critical, no passkey. */
    public const REASON_VISHING_SUSPECTED = 'vishing_suspected';
    /** Mirror Alarm: the sign-in page was not on your site (a real-time phishing proxy). */
    public const REASON_PHISHING_ORIGIN = 'phishing_origin';

    // `event` values of event webhooks. Ignore types you do not know.
    public const EVENT_DEVICE_LINKED = 'DEVICE_LINKED';
    public const EVENT_DEVICE_UNLINKED = 'DEVICE_UNLINKED';
    public const EVENT_PASSKEY_REGISTERED = 'PASSKEY_REGISTERED';
    public const EVENT_PASSKEY_DELETED = 'PASSKEY_DELETED';
    /** After the call, the user confirmed a provisional approval was theirs: critical actions are allowed again. */
    public const EVENT_APPROVAL_RECONFIRMED = 'APPROVAL_RECONFIRMED';
    /** The user took an approval back (`reason` COACHED or UNDO): end the session built on it. */
    public const EVENT_APPROVAL_REVOKED = 'APPROVAL_REVOKED';
    /** Mobile SDK: send this push with your own keys (`Mobile::pushFromWebhook`). */
    public const EVENT_MOBILE_PUSH = 'MOBILE_PUSH';
    // Never Locked Out ($tq->recovery): every step of a recovery. Read `recovery->status()` for the truth.
    /** A recovery started; the new phone has not been bound yet. */
    public const EVENT_RECOVERY_STARTED = 'RECOVERY_STARTED';
    /** The new phone is bound to the recovery; the vouchers are asked next. */
    public const EVENT_RECOVERY_DEVICE_BOUND = 'RECOVERY_DEVICE_BOUND';
    /** The vouchers' quorum was reached: the move happens after the cooling-off unless someone vetoes it. */
    public const EVENT_RECOVERY_COOLING = 'RECOVERY_COOLING';
    /** The account moved to the new phone (followed by DEVICE_LINKED with `via` recovery). */
    public const EVENT_RECOVERY_COMPLETED = 'RECOVERY_COMPLETED';
    /** The recovery was stopped (by the user's old phone, a voucher or an admin). */
    public const EVENT_RECOVERY_VETOED = 'RECOVERY_VETOED';
    public const EVENT_RECOVERY_EXPIRED = 'RECOVERY_EXPIRED';
    public const EVENT_RECOVERY_FAILED = 'RECOVERY_FAILED';
    // Help desk ($tq->assist): IT working on a person's account in the open.
    public const EVENT_ASSIST_OPENED = 'ASSIST_OPENED';
    public const EVENT_ASSIST_ENDED = 'ASSIST_ENDED';
    /** The person typed the check's number on their phone and approved. */
    public const EVENT_ASSIST_CHECK_PASSED = 'ASSIST_CHECK_PASSED';
    /** The check was not passed (wrong number, "not me", coached, declined or expired): page someone. */
    public const EVENT_ASSIST_CHECK_FAILED = 'ASSIST_CHECK_FAILED';
    public const EVENT_ASSIST_UNFROZEN = 'ASSIST_UNFROZEN';
    /** The person checked on their phone that the IT agent is really working on their account. */
    public const EVENT_ASSIST_CLAIM_CONFIRMED = 'ASSIST_CLAIM_CONFIRMED';
    /** The person asked their phone whether IT is working on their account and nobody was (no assistId): page someone. */
    public const EVENT_ASSIST_CLAIM_UNVERIFIED = 'ASSIST_CLAIM_UNVERIFIED';
    // AI agents ($tq->agents): changes partners may act on, and what Touchque noticed.
    /** An AI agent was registered. */
    public const EVENT_AGENT_CREATED = 'AGENT_CREATED';
    /** An AI agent was suspended (through the API or the dashboard): its tokens stopped working. */
    public const EVENT_AGENT_SUSPENDED = 'AGENT_SUSPENDED';
    /** An AI agent may act again. */
    public const EVENT_AGENT_RESUMED = 'AGENT_RESUMED';
    /** An AI agent was revoked for good. */
    public const EVENT_AGENT_REVOKED = 'AGENT_REVOKED';
    /** A key was added to an AI agent. */
    public const EVENT_AGENT_KEY_ADDED = 'AGENT_KEY_ADDED';
    /** A key was removed from an AI agent; tokens bound to it stopped working. */
    public const EVENT_AGENT_KEY_REMOVED = 'AGENT_KEY_REMOVED';
    /** The kill switch stopped every AI agent of the workspace. */
    public const EVENT_AGENTS_PAUSED = 'AGENTS_PAUSED';
    /** The kill switch was turned off. */
    public const EVENT_AGENTS_RESUMED = 'AGENTS_RESUMED';
    /** An AI agent's policy changed. */
    public const EVENT_AGENT_POLICY_CHANGED = 'AGENT_POLICY_CHANGED';
    public const EVENT_AGENT_WORKSPACE_POLICY_CHANGED = 'AGENT_WORKSPACE_POLICY_CHANGED';
    /** An approval token was used. */
    public const EVENT_AGENT_APPROVAL_REDEEMED = 'AGENT_APPROVAL_REDEEMED';
    /** A person stopped an AI agent from asking them ("this wasn't me", coached, or three rejections). */
    public const EVENT_AGENT_BLOCKED_BY_PERSON = 'AGENT_BLOCKED_BY_PERSON';
    /** An admin let an AI agent ask a person again. */
    public const EVENT_AGENT_UNBLOCKED_FOR_PERSON = 'AGENT_UNBLOCKED_FOR_PERSON';
    /** An AI agent sent the same request to the same person three times in 10 minutes. */
    public const EVENT_AGENT_LOOP_DETECTED = 'AGENT_LOOP_DETECTED';
    /** An AI agent asked a person for a mandate. */
    public const EVENT_AGENT_MANDATE_REQUESTED = 'AGENT_MANDATE_REQUESTED';
    /** A mandate was ended. */
    public const EVENT_AGENT_MANDATE_REVOKED = 'AGENT_MANDATE_REVOKED';
    /** An AI agent's text carried an instruction to the model or a link that carries data; the request was refused. */
    public const EVENT_AGENT_INJECTION_SUSPECTED = 'AGENT_INJECTION_SUSPECTED';
    /** An approval came back sooner than a person can answer; it is never usable. */
    public const EVENT_AGENT_INHUMAN_APPROVAL = 'AGENT_INHUMAN_APPROVAL';
    /** A new or renamed AI agent's name read like another agent's; it was refused. */
    public const EVENT_AGENT_LOOKALIKE_NAME = 'AGENT_LOOKALIKE_NAME';

    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Verify the signature of an incoming Touchque webhook and return the decoded payload.
     *
     * @param string      $rawBody           The raw request body, exactly as received.
     * @param string|null $signature         The `x-signature` header value. If null, the
     *                                       `signature` field inside the body is used.
     * @param int         $toleranceSeconds  Reject a callback whose signed `timestamp` is
     *                                       missing, invalid or further than this from now.
     *                                       0 disables the check.
     * @param ReplayCache|null $replayCache  When set, a second delivery of the same `jti`
     *                                       throws TouchqueWebhookReplayException.
     * @return array The decoded payload if the signature is valid. A string with an unpaired
     *               UTF-16 surrogate, which JSON.stringify writes as an escape (`\ud800`) and
     *               PHP cannot decode, comes back with U+FFFD in its place.
     * @throws TouchqueWebhookSignatureException
     * @throws TouchqueWebhookReplayException (a subclass of the above)
     */
    public function verify(
        string $rawBody,
        ?string $signature = null,
        int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS,
        ?ReplayCache $replayCache = null
    ): array {
        // Decode as objects (NOT assoc) so nested objects round-trip as objects:
        // an assoc decode turns `{}` into `[]` and a numeric-keyed object into a
        // JSON array when re-encoded, breaking the canonical form.
        $obj = json_decode($rawBody);
        $canonical = null;
        if (json_last_error() === JSON_ERROR_UTF16) {
            // A string with an unpaired UTF-16 surrogate, written by JSON.stringify as `\ud800` (a user
            // store request forwards the password of a sign-in posted as JSON, whatever it holds). PHP
            // cannot hold one: the signature is checked over the body's own text, and the payload is
            // read with U+FFFD in its place.
            $canonical = self::canonicalFromText($rawBody);
            $rawBody = self::withoutLoneSurrogates($rawBody);
            $obj = json_decode($rawBody);
        }
        if (json_last_error() !== JSON_ERROR_NONE || !($obj instanceof \stdClass) || $canonical === '') {
            throw new TouchqueWebhookSignatureException('Invalid JSON payload');
        }

        $provided = $signature ?? ($obj->signature ?? null);
        if (!is_string($provided) || $provided === '') {
            throw new TouchqueWebhookSignatureException('No signature provided');
        }

        $expected = hash_hmac('sha256', $canonical ?? $this->canonicalize($obj), $this->config->getApiSecret());

        // Do NOT include the expected signature in the exception — a caller that
        // surfaces the message would hand an attacker a signing oracle.
        if (!hash_equals($expected, $provided)) {
            throw new TouchqueWebhookSignatureException('Invalid webhook signature');
        }

        // Touchque always signs a timestamp, so a missing or unparseable one
        // fails closed instead of skipping the freshness check.
        if ($toleranceSeconds > 0) {
            $ts = isset($obj->timestamp) && is_string($obj->timestamp) ? strtotime($obj->timestamp) : false;
            if ($ts === false) {
                throw new TouchqueWebhookSignatureException('Webhook timestamp is missing or invalid');
            }
            if (abs(time() - $ts) > $toleranceSeconds) {
                throw new TouchqueWebhookSignatureException('Webhook timestamp is outside the allowed window');
            }
        }

        if ($replayCache !== null) {
            $jti = $obj->jti ?? null;
            if (!is_string($jti) || $jti === '') {
                throw new TouchqueWebhookSignatureException('Webhook jti is missing');
            }
            // Remember it for twice the window so it outlives any timestamp
            // that could still pass the freshness check.
            if (!$replayCache->checkAndSet($jti, max($toleranceSeconds * 2, 600))) {
                throw new TouchqueWebhookReplayException($jti);
            }
        }

        // Caller-facing shape stays an associative array (unchanged contract).
        return json_decode($rawBody, true);
    }

    /**
     * Reproduce the server's stableStringify: drop the
     * `signature` field, sort ONLY the top-level keys (byte order, matching
     * JS Object.keys().sort()), serialize compact and with slashes/unicode
     * unescaped (JSON.stringify semantics). Nested objects keep their key order.
     * JSON.stringify also leaves U+2028/U+2029 raw and writes a number in its
     * shortest form, whatever php.ini's serialize_precision says.
     */
    private function canonicalize(\stdClass $obj): string
    {
        $clone = clone $obj;
        unset($clone->signature);

        $props = get_object_vars($clone);
        ksort($props, SORT_STRING);

        $sorted = new \stdClass();
        foreach ($props as $key => $value) {
            $sorted->{$key} = $value;
        }

        $precision = ini_get('serialize_precision');
        ini_set('serialize_precision', '-1');
        try {
            return (string)json_encode($sorted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS);
        } finally {
            ini_set('serialize_precision', (string)$precision);
        }
    }

    /**
     * The canonical form from the body's own text, for a body PHP cannot decode: its top-level
     * members as written, without `signature`, sorted by key (byte order, as canonicalize()) and
     * joined. JSON.stringify writes each value the same way alone as inside the body, so for a
     * body Touchque wrote this is what it signed. '' when the body is not a compact JSON object
     * (JSON.stringify writes no whitespace) or a key cannot be read.
     */
    private static function canonicalFromText(string $json): string
    {
        $n = strlen($json);
        if ($n < 2 || $json[0] !== '{' || $json[$n - 1] !== '}') {
            return '';
        }
        $members = [];
        $i = 1;
        $end = $n === 2 ? '}' : '';
        while ($i < $n - 1) {
            // "key":value, up to the ',' or the closing '}' outside any string, object or array.
            $keyStart = $i;
            $keyEnd = self::stringEnd($json, $keyStart);
            if ($keyEnd === null || $keyEnd >= $n || $json[$keyEnd] !== ':') {
                return '';
            }
            $key = json_decode(substr($json, $keyStart, $keyEnd - $keyStart));
            if (!is_string($key)) {
                return '';
            }
            $depth = 0;
            for ($i = $keyEnd + 1; $i < $n; $i++) {
                $c = $json[$i];
                if ($c === '"') {
                    $stringEnd = self::stringEnd($json, $i);
                    if ($stringEnd === null) {
                        return '';
                    }
                    $i = $stringEnd - 1;
                } elseif ($c === '{' || $c === '[') {
                    $depth++;
                } elseif (($c === '}' || $c === ']' || $c === ',') && $depth === 0) {
                    break;
                } elseif ($c === '}' || $c === ']') {
                    $depth--;
                } elseif ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                    return '';
                }
            }
            if ($i === $keyEnd + 1 || $i >= $n || $json[$i] === ']' || ($json[$i] === '}' && $i !== $n - 1)) {
                return '';
            }
            if ($key !== 'signature') {
                $members[] = [$key, substr($json, $keyStart, $i - $keyStart)];
            }
            $end = $json[$i];
            $i++;
        }
        if ($end !== '}') {
            return '';
        }
        usort($members, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));
        return '{' . implode(',', array_column($members, 1)) . '}';
    }

    /** The index just past the JSON string that opens at $i, or null when there is none. */
    private static function stringEnd(string $json, int $i): ?int
    {
        $n = strlen($json);
        if ($i >= $n || $json[$i] !== '"') {
            return null;
        }
        for ($i++; $i < $n; $i++) {
            if ($json[$i] === '\\') {
                $i++;
            } elseif ($json[$i] === '"') {
                return $i + 1;
            }
        }
        return null;
    }

    /**
     * The body with each unpaired UTF-16 surrogate escape in its strings (`\ud800` with no low
     * surrogate after it, or a low one alone) written as the escape of U+FFFD. Pairs and every other
     * escape stay as they are.
     */
    private static function withoutLoneSurrogates(string $json): string
    {
        $out = '';
        $n = strlen($json);
        $inString = false;
        for ($i = 0; $i < $n; $i++) {
            $c = $json[$i];
            if ($c === '"') {
                $inString = !$inString;
            } elseif ($inString && $c === '\\') {
                $escape = substr($json, $i, 6);
                if (preg_match('/^\\\\u[dD][89abAB][0-9a-fA-F]{2}$/', $escape) === 1
                    && preg_match('/^\\\\u[dD][c-fC-F][0-9a-fA-F]{2}$/', substr($json, $i + 6, 6)) === 1) {
                    $out .= substr($json, $i, 12);
                    $i += 11;
                } elseif (preg_match('/^\\\\u[dD][89a-fA-F][0-9a-fA-F]{2}$/', $escape) === 1) {
                    $out .= '\\ufffd';
                    $i += 5;
                } else {
                    $out .= substr($json, $i, 2);
                    $i++;
                }
                continue;
            }
            $out .= $c;
        }
        return $out;
    }
}
