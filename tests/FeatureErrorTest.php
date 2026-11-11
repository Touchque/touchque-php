<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueFeatureException;
use Touchque\Exceptions\TouchqueFeatureNotInPlanException;
use Touchque\Exceptions\TouchqueFeatureOffException;
use Touchque\Exceptions\TouchqueFeatureReadOnlyException;
use Touchque\Touchque;

/**
 * A feature the workspace's organization cannot use comes back as a typed
 * exception with the feature's id, still a TouchqueAPIException. Same
 * scenarios as the Node SDK, against the shared fake Touchque API.
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
            ['feature_not_in_plan', TouchqueFeatureNotInPlanException::class, 'not_in_plan'],
            ['feature_read_only', TouchqueFeatureReadOnlyException::class, 'read_only'],
            ['feature_off', TouchqueFeatureOffException::class, 'off'],
        ];
    }

    /** @dataProvider refusals */
    public function testEachFeatureRefusalHasItsOwnException(string $code, string $class, string $reason): void
    {
        self::$api->opts(['featureRefused' => $code, 'feature' => 'device_risk']);
        try {
            (new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl)))->login->request(self::USER, 'LOGIN');
            $this->fail('expected a feature exception');
        } catch (TouchqueAPIException $e) {
            $this->assertInstanceOf($class, $e);
            $this->assertInstanceOf(TouchqueFeatureException::class, $e);
            $this->assertSame(403, $e->getStatus());
            $this->assertSame('device_risk', $e->getFeature());
            $this->assertSame($reason, $e->getFeatureReason());
        }
    }

    public function testOtherRefusalsStayPlainApiExceptions(): void
    {
        self::$api->opts(['blocked' => 'access_policy']);
        try {
            (new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl)))->login->request(self::USER, 'LOGIN');
            $this->fail('expected an API exception');
        } catch (TouchqueAPIException $e) {
            $this->assertNotInstanceOf(TouchqueFeatureException::class, $e);
        }
    }
}
