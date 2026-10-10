<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\TouchQue;

/** login->reportFraud() against the shared fake TouchQue API. */
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

    private function client(): TouchQue
    {
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
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
        } catch (TouchQueAPIException $e) {
            $this->assertSame(400, $e->getStatus());
        }
        try {
            $tq->login->reportFraud('unknown-id');
            $this->fail('unknown request must be rejected');
        } catch (TouchQueAPIException $e) {
            $this->assertSame(404, $e->getStatus());
        }
    }

    public function testEmptyIdFailsLocally(): void
    {
        $this->expectException(TouchQueConfigException::class);
        $this->client()->login->reportFraud('');
    }
}
