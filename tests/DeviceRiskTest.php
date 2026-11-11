<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Resources\DeviceRisk;
use Touchque\Touchque;

/**
 * Device risk against the shared fake Touchque API: the report goes through
 * untouched and the answer fails toward asking. Same scenarios as the Node
 * SDK's DeviceRisk tests.
 */
class DeviceRiskTest extends TestCase
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

    private function tq(): Touchque
    {
        self::$api->reset();
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testCheckSendsTheReportAndReadsTheAnswer(): void
    {
        $r = $this->tq()->deviceRisk->check('dre_flaggedaaaaaaaaaaaaaaa', 'sign_up', 'ayse@acme.com', '203.0.113.7');
        $this->assertSame('ok', $r['report']);
        $this->assertSame('tqv_fakeVisitor00000001', $r['visitorId']);
        $this->assertSame('DRK-2QX', $r['caseCode']);
        $this->assertFalse($r['signals'][0]['enforced']);
        $event = $this->tq()->deviceRisk->getEvent('dre_aaaaaaaaaaaaaaaaaaaaaa');
        $this->assertSame('tqv_fakeVisitor00000001', $event['visitorId']);
        $relay = $this->tq()->deviceRisk->check(null, 'sign_in', null, null, 'REPORT');
        $this->assertSame([], $relay['signals']);
        $this->assertSame(['device_many_accounts'], array_column($r['signals'], 'code'));
        $this->assertFalse($r['stepUp']);
        $this->assertTrue($r['wouldStepUp']);
        $this->assertSame('shadow', $r['mode']);
    }

    public function testTheFormFieldAsItCameIsAnsweredNeverThrown(): void
    {
        foreach ([null, '', ['x']] as $value) {
            $r = $this->tq()->deviceRisk->check($value, 'sign_in', 'ayse@acme.com');
            $this->assertSame('missing', $r['report']);
            $this->assertNull($r['visitorId']);
            $this->assertSame(['device_identification_missing'], array_column($r['signals'], 'code'));
            $this->assertFalse($r['stepUp']);
            $this->assertTrue($r['wouldStepUp']);
        }
        $this->assertSame('unknown', $this->tq()->deviceRisk->check('nope')['report']);
        $this->assertSame('invalid', DeviceRisk::parse(['report' => 'whatever'])['report']);
    }

    public function testAWrongEventFailsBeforeAnyRequest(): void
    {
        $this->expectException(TouchqueConfigException::class);
        $this->tq()->deviceRisk->check('nope', 'tracking');
    }

    public function testTheAnswerFailsTowardAsking(): void
    {
        $this->assertTrue(DeviceRisk::parse([])['stepUp']);
        $this->assertFalse(DeviceRisk::parse(['stepUp' => false])['stepUp']);
        $r = DeviceRisk::parse(['signals' => [['code' => 'device_tampered', 'text' => 't'], null, ['text' => 'x']], 'requires' => 'passkey']);
        $this->assertSame([['code' => 'device_tampered', 'text' => 't', 'strength' => 'number_match']], $r['signals']);
        $this->assertSame('passkey', $r['requires']);
    }

    public function testEngineUnavailableComesThroughAndANormalAnswerHasNull(): void
    {
        $down = DeviceRisk::parse(['report' => 'ok', 'signals' => [], 'stepUp' => true, 'wouldStepUp' => true, 'requires' => 'number_match', 'mode' => 'enforce', 'engine' => 'unavailable']);
        $this->assertSame('unavailable', $down['engine']);
        $this->assertTrue($down['stepUp']);
        $this->assertSame('number_match', $down['requires']);
        $normal = DeviceRisk::parse(['report' => 'ok', 'signals' => [], 'stepUp' => false, 'requires' => 'none', 'mode' => 'shadow']);
        $this->assertNull($normal['engine']);
        $this->assertFalse($normal['stepUp']);
        $this->assertNull(DeviceRisk::parse(['engine' => 42])['engine']);
    }

    public function testRiskCheckAcceptsDeviceRisk(): void
    {
        $r = $this->tq()->risk->check(['externalUsername' => 'ayse@acme.com', 'deviceRiskRequestId' => 'dre_aaaaaaaaaaaaaaaaaaaaaa']);
        $this->assertTrue($r['prompt']);
    }

    public function testTheAddressTheCountsAndABotAnswerComeThrough(): void
    {
        $r = DeviceRisk::parse(['report' => 'ok', 'network' => ['type' => 'hosting'], 'velocity' => ['identifications1h' => 2], 'bot' => ['result' => 'suspected', 'reasons' => ['pointer_synthetic']]]);
        $this->assertSame('hosting', $r['network']['type']);
        $this->assertSame(2, $r['velocity']['identifications1h']);
        $this->assertSame('suspected', $r['bot']['result']);
        $this->assertNull(DeviceRisk::parse(['network' => 'x'])['network']);
    }

    public function testSearchEventsPagesWithTheOpaqueCursorAndSendsTheFilters(): void
    {
        $first = $this->tq()->deviceRisk->searchEvents(['account' => 'ada@example.com', 'stepUp' => false, 'ip' => '203.0.113.0/24', 'limit' => 1]);
        $this->assertEquals(['account' => 'ada@example.com', 'ip' => '203.0.113.0/24', 'stepUp' => 'false', 'limit' => '1'], self::$api->lastDeviceRiskSearch());
        $this->assertSame(['dre_fakeEvent00000000002'], array_column($first['events'], 'requestId'));
        $this->assertNull($first['nextCursor']);
        $seen = [];
        $cursor = null;
        do {
            $page = $this->tq()->deviceRisk->searchEvents(['limit' => 1] + ($cursor ? ['cursor' => $cursor] : []));
            $seen = array_merge($seen, array_column($page['events'], 'requestId'));
            $cursor = $page['nextCursor'];
        } while ($cursor);
        $this->assertSame(['dre_fakeEvent00000000003', 'dre_fakeEvent00000000002', 'dre_fakeEvent00000000001'], $seen);
        $this->expectException(TouchqueConfigException::class);
        $this->tq()->deviceRisk->searchEvents(['limit' => 101]);
    }
}
