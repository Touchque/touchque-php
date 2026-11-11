<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Resources\Offline;
use Touchque\Touchque;

/** Codes during a Touchque outage, against the shared fake Touchque API (its code is K7P2QXA at every step). */
class OutageVerifiersTest extends TestCase
{
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

    public function testFetchThenMatchOffline(): void
    {
        self::$api->reset();
        self::$api->link('vpn@example.com');
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
        $now = time();
        $step = intdiv($now, 30);
        $v = $tq->offline->totpVerifiers(['vpn@example.com', 'nobody@example.com'], $step - 1, 4);
        $this->assertSame(['vpn@example.com'], array_column($v['users'], 'externalUsername'));
        $user = $v['users'][0];
        $this->assertSame($step, Offline::matchTotpVerifier($v, $user, 'k7p-2qxa', $now));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'K7P2QXB', $now));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'K7P2QXA', $now + 3600));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'K7P2QX1', $now));

        self::$api->opts(['outageVerifiersDisabled' => true]);
        $this->expectException(TouchqueAPIException::class);
        $tq->offline->totpVerifiers(['vpn@example.com']);
    }
}
