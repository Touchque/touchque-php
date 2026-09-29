<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Resources\Webhook;
use TouchQue\Exceptions\TouchQueWebhookSignatureException;
use TouchQue\Exceptions\TouchQueWebhookReplayException;
use TouchQue\Webhook\MemoryReplayCache;

class WebhookTest extends TestCase
{
    private const SECRET = 'whsec_test';

    /**
     * Reproduce the API server: sign stableStringify(payload) (top-level
     * keys sorted, no `signature`, compact) and deliver {...payload, signature}.
     */
    private function serverWebhook(array $payload, string $secret = self::SECRET): string
    {
        $canonical = $payload;
        ksort($canonical, SORT_STRING);
        $raw = json_encode($canonical, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $signature = hash_hmac('sha256', $raw, $secret);

        return json_encode(array_merge($payload, ['signature' => $signature]));
    }

    /**
     * Sign a hand-written canonical string (top-level keys already sorted,
     * `signature` absent) exactly as the server does, then deliver the body as
     * {...payload, signature} with `signature` appended last. Used for payloads
     * with nested objects / empty objects that an assoc round-trip would mangle.
     */
    private function serverWebhookRaw(string $canonicalNoSig, string $secret = self::SECRET): string
    {
        $signature = hash_hmac('sha256', $canonicalNoSig, $secret);
        return substr($canonicalNoSig, 0, -1) . ',"signature":"' . $signature . '"}';
    }

    private function freshPayload(array $overrides = []): array
    {
        return array_merge([
            'event' => 'login.confirmed',
            'requestId' => 'req_1',
            'status' => 'SUCCESS',
            'timestamp' => gmdate('c'),
            'jti' => 'jti_1',
        ], $overrides);
    }

    private function makeWebhook(): Webhook
    {
        return new Webhook(new Config('tq_auth_test123', self::SECRET));
    }

    public function testVerifiesGenuineServerSignedCallback(): void
    {
        $rawBody = $this->serverWebhook($this->freshPayload());

        $result = $this->makeWebhook()->verify($rawBody);

        $this->assertSame('req_1', $result['requestId']);
        $this->assertSame('login.confirmed', $result['event']);
    }

    public function testAcceptsTheHeaderSignatureToo(): void
    {
        $payload = $this->freshPayload();
        $rawBody = $this->serverWebhook($payload);
        $headerSig = json_decode($rawBody, true)['signature'];

        $result = $this->makeWebhook()->verify(json_encode($payload), $headerSig);

        $this->assertSame('req_1', $result['requestId']);
    }

    public function testThrowsOnTamperedBody(): void
    {
        $rawBody = str_replace('req_1', 'req_evil', $this->serverWebhook($this->freshPayload()));

        $this->expectException(TouchQueWebhookSignatureException::class);
        $this->makeWebhook()->verify($rawBody);
    }

    public function testThrowsOnWrongSecret(): void
    {
        $rawBody = $this->serverWebhook($this->freshPayload(), 'not_the_secret');

        $this->expectException(TouchQueWebhookSignatureException::class);
        $this->makeWebhook()->verify($rawBody);
    }

    public function testThrowsOnMissingSignature(): void
    {
        $this->expectException(TouchQueWebhookSignatureException::class);
        $this->makeWebhook()->verify(json_encode($this->freshPayload()));
    }

    public function testThrowsOnMalformedJson(): void
    {
        $this->expectException(TouchQueWebhookSignatureException::class);
        $this->makeWebhook()->verify('not json');
    }

    public function testThrowsOnStaleTimestampAsReplay(): void
    {
        $rawBody = $this->serverWebhook($this->freshPayload(['timestamp' => gmdate('c', time() - 3600)]));

        $this->expectException(TouchQueWebhookSignatureException::class);
        $this->makeWebhook()->verify($rawBody);
    }

    public function testReplayCheckCanBeDisabled(): void
    {
        $rawBody = $this->serverWebhook($this->freshPayload(['timestamp' => gmdate('c', time() - 3600)]));

        $result = $this->makeWebhook()->verify($rawBody, null, 0);

        $this->assertSame('req_1', $result['requestId']);
    }

    public function testPreservesNestedObjectKeyOrder(): void
    {
        // Top-level keys already sorted; nested `context` deliberately z-before-a.
        // The server only sorts the top level and re-emits nested values verbatim.
        $canonical = '{"context":{"z":1,"a":2},"event":"login.confirmed","requestId":"req_1","status":"SUCCESS"}';
        $rawBody = $this->serverWebhookRaw($canonical);

        // The hand-written body has no timestamp, so the freshness check is off.
        $result = $this->makeWebhook()->verify($rawBody, null, 0);

        $this->assertSame('req_1', $result['requestId']);
        $this->assertSame(['z' => 1, 'a' => 2], $result['context']);
    }

    public function testPreservesEmptyObjectValue(): void
    {
        // An assoc round-trip turns `{}` into `[]`; the object form must survive.
        $canonical = '{"event":"login.confirmed","meta":{},"requestId":"req_1"}';
        $rawBody = $this->serverWebhookRaw($canonical);

        // The hand-written body has no timestamp, so the freshness check is off.
        $result = $this->makeWebhook()->verify($rawBody, null, 0);

        $this->assertSame('req_1', $result['requestId']);
    }

    public function testErrorNeverLeaksTheExpectedSignature(): void
    {
        $rawBody = $this->serverWebhook($this->freshPayload(), 'wrong');

        try {
            $this->makeWebhook()->verify($rawBody);
            $this->fail('expected a signature exception');
        } catch (TouchQueWebhookSignatureException $e) {
            $this->assertStringNotContainsStringIgnoringCase('expected', $e->getMessage());
        }
    }

    // ── Replay protection (A12) ──

    public function testMissingOrInvalidTimestampFailsClosed(): void
    {
        $noTs = $this->freshPayload();
        unset($noTs['timestamp']);
        foreach ([$this->serverWebhook($noTs), $this->serverWebhook($this->freshPayload(['timestamp' => 'not-a-date']))] as $body) {
            try {
                $this->makeWebhook()->verify($body);
                $this->fail('a webhook without a valid timestamp must be rejected');
            } catch (TouchQueWebhookSignatureException $e) {
                $this->assertStringContainsString('timestamp', $e->getMessage());
            }
        }
    }

    public function testReplayCacheRejectsTheSecondDeliveryOfTheSameJti(): void
    {
        $cache = new MemoryReplayCache();
        $body = $this->serverWebhook($this->freshPayload(['jti' => 'once']));
        $this->assertSame('once', $this->makeWebhook()->verify($body, null, 300, $cache)['jti']);
        try {
            $this->makeWebhook()->verify($body, null, 300, $cache);
            $this->fail('expected a replay exception');
        } catch (TouchQueWebhookReplayException $e) {
            $this->assertSame('once', $e->getJti());
            $this->assertInstanceOf(TouchQueWebhookSignatureException::class, $e);
        }
        $this->makeWebhook()->verify($this->serverWebhook($this->freshPayload(['jti' => 'other'])), null, 300, $cache);

        $noJti = $this->freshPayload();
        unset($noJti['jti']);
        $this->expectException(TouchQueWebhookSignatureException::class);
        $this->makeWebhook()->verify($this->serverWebhook($noJti), null, 300, $cache);
    }

    public function testForgedWebhookDoesNotPoisonTheReplayCache(): void
    {
        $cache = new MemoryReplayCache();
        try {
            $this->makeWebhook()->verify($this->serverWebhook($this->freshPayload(['jti' => 'victim']), 'wrong'), null, 300, $cache);
            $this->fail('forged webhook accepted');
        } catch (TouchQueWebhookSignatureException $e) {
        }
        $result = $this->makeWebhook()->verify($this->serverWebhook($this->freshPayload(['jti' => 'victim'])), null, 300, $cache);
        $this->assertSame('victim', $result['jti']);
    }
}
