<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Touchque;

/** login->reportFraud() against the shared fake Touchque API. */
class ReportFraudTest extends TestCase
{
    private static ?FakeApi $api = null;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$api) {
            self::$api->close();
        }
    }

    private function client(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testReportFraudFlow(): void
    {
        self::$api->link('jane@acme.com');
        $tq = $this->client();
        $req = $tq->login->request('jane@acme.com', 'LOGIN');

        $first = $tq->login->reportFraud($req['requestId'], 'chargeback', 'Disputed by card holder');
        $this->assertSame(['reported' => true, 'alreadyReported' => false, 'requestId' => $req['requestId']], $first);
        $this->assertTrue($tq->login->reportFraud($req['requestId'])['alreadyReported']);

        try {
            $tq->login->reportFraud($req['requestId'], 'because');
            $this->fail('invalid reason must be rejected');
        } catch (TouchqueAPIException $e) {
            $this->assertSame(400, $e->getStatus());
        }
        try {
            $tq->login->reportFraud('unknown-id');
            $this->fail('unknown request must be rejected');
        } catch (TouchqueAPIException $e) {
            $this->assertSame(404, $e->getStatus());
        }
    }

    public function testEmptyIdFailsLocally(): void
    {
        $this->expectException(TouchqueConfigException::class);
        $this->client()->login->reportFraud('');
    }
}
