<?php

namespace TouchQue\Resources;

use TouchQue\Config;
use TouchQue\Exceptions\TouchQueWebhookReplayException;
use TouchQue\Exceptions\TouchQueWebhookSignatureException;
use TouchQue\Webhook\ReplayCache;

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

    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Verify the signature of an incoming TouchQue webhook and return the decoded payload.
     *
     * @param string      $rawBody           The raw request body, exactly as received.
     * @param string|null $signature         The `x-signature` header value. If null, the
     *                                       `signature` field inside the body is used.
     * @param int         $toleranceSeconds  Reject a callback whose signed `timestamp` is
     *                                       missing, invalid or further than this from now.
     *                                       0 disables the check.
     * @param ReplayCache|null $replayCache  When set, a second delivery of the same `jti`
     *                                       throws TouchQueWebhookReplayException.
     * @return array The decoded payload if the signature is valid.
     * @throws TouchQueWebhookSignatureException
     * @throws TouchQueWebhookReplayException (a subclass of the above)
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
        if (json_last_error() !== JSON_ERROR_NONE || !($obj instanceof \stdClass)) {
            throw new TouchQueWebhookSignatureException('Invalid JSON payload');
        }

        $provided = $signature ?? ($obj->signature ?? null);
        if (!is_string($provided) || $provided === '') {
            throw new TouchQueWebhookSignatureException('No signature provided');
        }

        $expected = hash_hmac('sha256', $this->canonicalize($obj), $this->config->getApiSecret());

        // Do NOT include the expected signature in the exception — a caller that
        // surfaces the message would hand an attacker a signing oracle.
        if (!hash_equals($expected, $provided)) {
            throw new TouchQueWebhookSignatureException('Invalid webhook signature');
        }

        // TouchQue always signs a timestamp, so a missing or unparseable one
        // fails closed instead of skipping the freshness check.
        if ($toleranceSeconds > 0) {
            $ts = isset($obj->timestamp) && is_string($obj->timestamp) ? strtotime($obj->timestamp) : false;
            if ($ts === false) {
                throw new TouchQueWebhookSignatureException('Webhook timestamp is missing or invalid');
            }
            if (abs(time() - $ts) > $toleranceSeconds) {
                throw new TouchQueWebhookSignatureException('Webhook timestamp is outside the allowed window');
            }
        }

        if ($replayCache !== null) {
            $jti = $obj->jti ?? null;
            if (!is_string($jti) || $jti === '') {
                throw new TouchQueWebhookSignatureException('Webhook jti is missing');
            }
            // Remember it for twice the window so it outlives any timestamp
            // that could still pass the freshness check.
            if (!$replayCache->checkAndSet($jti, max($toleranceSeconds * 2, 600))) {
                throw new TouchQueWebhookReplayException($jti);
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

        return json_encode($sorted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
