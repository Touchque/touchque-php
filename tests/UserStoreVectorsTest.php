<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueWebhookSignatureException;
use Touchque\Resources\Webhook;

/**
 * The shared user store vectors (fixtures/user-store-vectors.json, recorded from the API server's own
 * user store requests and webhook signing): user_store.* requests exactly as Touchque POSTs them,
 * with unpaired surrogates (`\ud800`, which json_decode() refuses), U+2028/U+2029, <>&, NUL and other
 * control characters, quotes and backslashes. $tq->webhook->verify() passes each genuine one with the
 * x-signature header and with the body's own signature, hands back the payload with U+FFFD for each
 * unpaired surrogate, and refuses a tampered body or another secret.
 */
class UserStoreVectorsTest extends TestCase
{
    private static function fixture(): array
    {
        return json_decode((string)file_get_contents(__DIR__ . '/../fixtures/user-store-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    public function vectors(): array
    {
        $out = [];
        foreach (self::fixture()['vectors'] as $vector) {
            $out[$vector['name']] = [$vector];
        }
        return $out;
    }

    public function testTheFixtureHoldsEveryKindOfRequest(): void
    {
        $vectors = self::fixture()['vectors'];
        $this->assertGreaterThanOrEqual(18, count($vectors));
        $events = array_unique(array_column($vectors, 'event'));
        sort($events);
        $this->assertSame(['user_store.get_user', 'user_store.ping', 'user_store.verify_password'], $events);
        $this->assertContains(false, array_column($vectors, 'valid'));
    }

    /** @dataProvider vectors */
    public function testVector(array $v): void
    {
        // The fixture itself: hex HMAC-SHA256 over the canonical text is the signature exactly when valid.
        $this->assertSame($v['valid'], hash_equals(hash_hmac('sha256', $v['canonical'], $v['secret']), $v['x_signature']));
        $this->assertSame($v['canonical'], $this->canonicalAsVerifyBuildsIt($v['body']), 'the canonical form the SDK builds');

        $webhook = new Webhook(new Config('tq_test_key', $v['secret']));
        // Timestamps are fixed in the past: the freshness check is off (0).
        foreach (['the x-signature header' => $v['x_signature'], 'the body\'s signature' => null] as $how => $signature) {
            if ($v['valid']) {
                $payload = $webhook->verify($v['body'], $signature, 0);
                $this->assertSame($v['expected_payload'], $payload, $how);
                $this->assertNotFalse(json_encode($payload), 'the payload is valid UTF-8');
                continue;
            }
            try {
                $webhook->verify($v['body'], $signature, 0);
                $this->fail("accepted with {$how}");
            } catch (TouchqueWebhookSignatureException $e) {
                $this->assertSame('Invalid webhook signature', $e->getMessage(), $how);
            }
        }
    }

    /**
     * The text Webhook::verify() checks the signature over: the body re-encoded (canonicalize()), or, for a
     * body json_decode() cannot hold (an unpaired surrogate), the body's own members (canonicalFromText()).
     */
    private function canonicalAsVerifyBuildsIt(string $body): string
    {
        $decoded = json_decode($body);
        if (json_last_error() === JSON_ERROR_UTF16) {
            $method = new \ReflectionMethod(Webhook::class, 'canonicalFromText');
            if (\PHP_VERSION_ID < 80100) {
                $method->setAccessible(true);
            }
            return $method->invoke(null, $body);
        }
        $this->assertInstanceOf(\stdClass::class, $decoded);
        $method = new \ReflectionMethod(Webhook::class, 'canonicalize');
        if (\PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }
        return $method->invoke(new Webhook(new Config('tq_test_key', 'test_secret')), $decoded);
    }
}
