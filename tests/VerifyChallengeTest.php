<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Touchque;

/**
 * verify()'s onChallenge against the shared fake Touchque API: the number
 * reaches the caller before the wait (the callback approves, so verify() could
 * not finish otherwise), and a callback that throws is logged while verify()
 * keeps waiting. Same scenarios as the Node SDK.
 */
class VerifyChallengeTest extends TestCase
{
    private const USER = 'jane@acme.com';
    private static ?FakeApi $api = null;

    public static function setUpBeforeClass(): void
    {
        exec('which node', $out, $code);
        if ($code !== 0) {
            self::markTestSkipped('node is required for contract tests');
        }
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api?->close();
    }

    protected function setUp(): void
    {
        self::$api->reset();
        self::$api->link(self::USER);
    }

    private function client(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testOnChallengeGetsTheNumberBeforeTheWait(): void
    {
        self::$api->opts(['numberMatch' => true]);
        $seen = [];
        $api = self::$api;
        $result = $this->client()->login->verify(self::USER, 'LOGIN', null, 5000, null, null, false, false, null, null,
            function (array $c) use (&$seen, $api) {
                $seen[] = $c;
                $api->approve($c['requestId']);
            });

        $this->assertTrue($result['approved']);
        $this->assertCount(1, $seen);
        $this->assertSame($result['requestId'], $seen[0]['requestId']);
        $this->assertSame('47', $seen[0]['challengeCode']);
        $this->assertSame('K7P-2QX', $seen[0]['caseCode']);
        $this->assertSame('number_match_requested', $seen[0]['reasons'][0]['code']);
        $this->assertNotEmpty($seen[0]['expiresAt']);
    }

    public function testAThrowingOnChallengeGoesToTheLoggerNeverErrorLogAndVerifyKeepsWaiting(): void
    {
        $log = tempnam(sys_get_temp_dir(), 'tq-log');
        $previous = ini_set('error_log', $log);
        $api = self::$api;
        $lines = [];
        $logger = function (string $level, string $message) use (&$lines): void {
            $lines[] = [$level, $message];
        };
        $throwing = function (array $c) use ($api) {
            $api->approve($c['requestId']);
            throw new \RuntimeException('screen gone');
        };
        try {
            $logged = new Touchque(new Config('tq_test_key', 'test_secret', $api->baseUrl, 10000, $logger));
            $result = $logged->login->verify(self::USER, 'SEND_MONEY', null, 5000, null, null, false, false, null, null, $throwing);
            // Silent by default: the same failure without a logger writes nothing.
            $this->client()->login->verify(self::USER, 'SEND_MONEY', null, 5000, null, null, false, false, null, null, $throwing);
        } finally {
            ini_set('error_log', (string)$previous);
        }

        $this->assertTrue($result['approved']);
        $this->assertSame('47', $result['challengeCode']);
        $this->assertSame([['warning', '[Touchque] onChallenge failed: RuntimeException: screen gone']], $lines);
        $this->assertSame('', (string)file_get_contents($log));
        unlink($log);
    }
}
