<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Resources\Offline;
use Touchque\Touchque;

/** Codes during a Touchque outage, against the shared fake Touchque API (its outage code is K7P2QXA at every step, one digest a step). */
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

    public function testTwoDigestsPerStepWhenDigestsPerStepIsAbsent(): void
    {
        $salt = str_repeat("\x07", 16);
        $from = 1000;
        $h = fn (string $code, int $step): string => hash_pbkdf2('sha256', $code, $salt . ':' . $step, 10, 4, true);
        $parts = '';
        for ($s = $from; $s < $from + 4; $s++) {
            $parts .= $h('AAAAAA2', $s) . $h('BBBBBB2', $s);
        }
        $v = ['stepSeconds' => 30, 'fromStep' => $from, 'steps' => 4, 'notAfterStep' => $from + 3, 'kdf' => ['name' => 'pbkdf2-sha256', 'iterations' => 10, 'length' => 4]];
        $user = ['externalUsername' => 'a@b.com', 'fromStep' => $from, 'salt' => base64_encode($salt), 'digests' => base64_encode($parts)];
        $at = ($from + 1) * 30 + 5;
        $this->assertSame($from + 1, Offline::matchTotpVerifier($v, $user, 'aaa-aaa2', $at));
        $this->assertSame($from + 1, Offline::matchTotpVerifier($v, $user, 'BBBBBB2', $at));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'CCCCCC2', $at));
    }

    public function testFetchThenMatchOffline(): void
    {
        self::$api->reset();
        self::$api->link('vpn@example.com');
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
        $now = time();
        $step = intdiv($now, 30);
        $v = $tq->offline->totpVerifiers(['vpn@example.com', 'nobody@example.com'], ['id' => 'acme', 'name' => 'Acme'], $step - 1, 4);
        $this->assertSame(1, $v['digestsPerStep']);
        $this->assertSame(['id' => 'acme', 'name' => 'Acme'], $v['scope']);
        $this->assertSame(['vpn@example.com'], array_column($v['users'], 'externalUsername'));
        $user = $v['users'][0];
        $this->assertSame($step, Offline::matchTotpVerifier($v, $user, 'k7p-2qxa', $now));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'K7P2QXB', $now));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'K7P2QXA', $now + 3600));
        $this->assertNull(Offline::matchTotpVerifier($v, $user, 'K7P2QX1', $now));

        self::$api->opts(['outageVerifiersDisabled' => true]);
        $this->expectException(TouchqueAPIException::class);
        $tq->offline->totpVerifiers(['vpn@example.com'], ['id' => 'acme', 'name' => 'Acme']);
    }
}
