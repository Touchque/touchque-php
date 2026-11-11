<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Resources\Recovery;
use Touchque\Touchque;

/**
 * Never Locked Out against the shared fake Touchque API (a real, signed HTTP
 * round trip): vouchers, start, status, list and veto. Same scenarios as the
 * Node SDK's Recovery tests.
 */
class RecoveryTest extends TestCase
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
        if (self::$api) {
            self::$api->close();
        }
    }

    protected function setUp(): void
    {
        self::$api->reset();
        foreach (['ada@acme.com', 'bo@acme.com', 'cy@acme.com'] as $user) {
            self::$api->link($user);
        }
    }

    private function tq(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testVouchersAreNamedAndSayWhoCanVouch(): void
    {
        $out = $this->tq()->recovery->setVouchers('ada@acme.com', ['bo@acme.com', 'zed@acme.com']);
        $this->assertSame([
            ['externalUsername' => 'bo@acme.com', 'eligible' => true],
            ['externalUsername' => 'zed@acme.com', 'eligible' => false, 'reason' => 'no_phone'],
        ], $out['vouchers']);
        $this->assertSame('bo@acme.com', $this->tq()->recovery->vouchers('ada@acme.com')['vouchers'][0]['externalUsername']);
    }

    public function testARecoveryStartsWithAQrForTheNewPhoneAndMovesOn(): void
    {
        $tq = $this->tq();
        $tq->recovery->setVouchers('ada@acme.com', ['bo@acme.com', 'cy@acme.com']);
        $r = $tq->recovery->start(['externalUsername' => 'ada@acme.com', 'clientIp' => '203.0.113.7', 'displayName' => 'Ada', 'coolOffMinutes' => 90]);
        $this->assertSame('AWAITING_DEVICE', $r['status']);
        $this->assertStringStartsWith('touchque://recover?id=', $r['bindUri']);
        $calls = self::$api->calls();
        $this->assertSame(['externalUsername' => 'ada@acme.com', 'clientIp' => '203.0.113.7', 'displayName' => 'Ada', 'coolOffMinutes' => 90], end($calls)['body']);
        self::$api->recovery('VOUCHING');
        $now = $tq->recovery->status($r['recoveryId']);
        $this->assertSame(['11', '12'], array_column($now['vouchers'], 'code'));
        $this->assertTrue(Recovery::isOpen($now));
        self::$api->recovery('COMPLETED');
        $this->assertSame('COMPLETED', $tq->recovery->status($r['recoveryId'])['status']);
        $this->assertSame([$r['recoveryId']], array_column($tq->recovery->list(['externalUsername' => 'ada@acme.com']), 'recoveryId'));
    }

    public function testAnAdminVetoesARunningRecoveryAndTooFewVouchersIsAClearError(): void
    {
        $tq = $this->tq();
        try {
            $tq->recovery->start(['externalUsername' => 'ada@acme.com']);
            $this->fail('expected not_enough_vouchers');
        } catch (TouchqueAPIException $e) {
            $this->assertSame(409, $e->getStatus());
            $this->assertSame('not_enough_vouchers', $e->getErrorCode());
        }
        $r = $tq->recovery->start(['externalUsername' => 'ada@acme.com', 'fallbackVouchers' => ['bo@acme.com', 'cy@acme.com']]);
        $this->assertSame([$r['recoveryId']], array_column($tq->recovery->list(['open' => true]), 'recoveryId'));
        $vetoed = $tq->recovery->veto($r['recoveryId'], 'admin@acme.com');
        $this->assertSame(['VETOED', 'admin@acme.com'], [$vetoed['status'], $vetoed['endedBy']]);
        $this->assertSame([], $tq->recovery->list(['open' => true]));
    }

    public function testBadOptionsFailBeforeAnyRequest(): void
    {
        $tq = $this->tq();
        foreach ([
            fn () => $tq->recovery->start(['external_username' => 'ada@acme.com']),
            fn () => $tq->recovery->start(['externalUsername' => '']),
            fn () => $tq->recovery->start(['externalUsername' => 'ada@acme.com', 'required' => '3']),
            fn () => $tq->recovery->status(''),
            fn () => $tq->recovery->list([]),
        ] as $call) {
            try {
                $call();
                $this->fail('expected a config error');
            } catch (TouchqueConfigException $e) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertSame([], self::$api->calls());
    }
}
