<?php

namespace TouchQue\Resources;

use TouchQue\Config;
use TouchQue\Exceptions\TouchQueWebhookSignatureException;

class Webhook
{
    /** Replay window (seconds): reject a callback whose signed `timestamp` is older/newer than this. */
    private const DEFAULT_TOLERANCE_SECONDS = 300;

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
     *                                       further than this from now. 0 disables the check.
     * @return array The decoded payload if the signature is valid.
     * @throws TouchQueWebhookSignatureException
     */
    public function verify(string $rawBody, ?string $signature = null, int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS): array
    {
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

        if ($toleranceSeconds > 0 && isset($obj->timestamp) && is_string($obj->timestamp)) {
            $ts = strtotime($obj->timestamp);
            if ($ts !== false && abs(time() - $ts) > $toleranceSeconds) {
                throw new TouchQueWebhookSignatureException('Webhook timestamp is outside the allowed window');
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
