<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueFeatureException;
use TouchQue\Exceptions\TouchQueFeatureNotInPlanException;
use TouchQue\Exceptions\TouchQueFeatureOffException;
use TouchQue\Exceptions\TouchQueFeatureReadOnlyException;
use TouchQue\TouchQue;

/**
 * A feature the workspace's organization cannot use comes back as a typed
 * exception with the feature's id, still a TouchQueAPIException. Same
 * scenarios as the Node SDK, against the shared fake TouchQue API.
 */
class FeatureErrorTest extends TestCase
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

    public static function refusals(): array
    {
        return [
            ['feature_not_in_plan', TouchQueFeatureNotInPlanException::class, 'not_in_plan'],
            ['feature_read_only', TouchQueFeatureReadOnlyException::class, 'read_only'],
            ['feature_off', TouchQueFeatureOffException::class, 'off'],
        ];
    }

    /** @dataProvider refusals */
    public function testEachFeatureRefusalHasItsOwnException(string $code, string $class, string $reason): void
    {
        self::$api->opts(['featureRefused' => $code, 'feature' => 'device_risk']);
        try {
            (new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl)))->login->request(self::USER, 'LOGIN');
            $this->fail('expected a feature exception');
        } catch (TouchQueAPIException $e) {
            $this->assertInstanceOf($class, $e);
            $this->assertInstanceOf(TouchQueFeatureException::class, $e);
            $this->assertSame(403, $e->getStatus());
            $this->assertSame('device_risk', $e->getFeature());
            $this->assertSame($reason, $e->getFeatureReason());
        }
    }

    public function testOtherRefusalsStayPlainApiExceptions(): void
    {
        self::$api->opts(['blocked' => 'access_policy']);
        try {
            (new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl)))->login->request(self::USER, 'LOGIN');
            $this->fail('expected an API exception');
        } catch (TouchQueAPIException $e) {
            $this->assertNotInstanceOf(TouchQueFeatureException::class, $e);
        }
    }
}
