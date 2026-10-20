<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Guard;
use TouchQue\TouchQue;

/**
 * "Why?" case codes against the shared fake TouchQue API: every decision names
 * one, the step shows it with plain reasons, a refusal and the raw API error
 * carry it, and the silent check returns it. Same scenarios as the Node SDK.
 */
class CaseCodeTest extends TestCase
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

    private function client(): TouchQue
    {
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testANumberMatchedStepNamesItsCaseAndPlainReasons(): void
    {
        self::$api->opts(['numberMatch' => true]);
        $step = $this->client()->start('LOGIN', self::USER);
        $this->assertSame('waiting', $step['state']);
        $this->assertSame('K7P-2QX', $step['caseCode']);
        $this->assertSame([['code' => 'number_match_requested', 'text' => 'The risk check asked for number matching']], $step['reasons']);
    }

    public function testARefusalNamesItsCaseInTheStepAndOnTheException(): void
    {
        self::$api->opts(['blocked' => 'access_policy']);
        $tq = $this->client();
        $this->assertSame(['state' => 'blocked', 'reason' => 'access_policy', 'caseCode' => 'REF-USE'], $tq->start('LOGIN', self::USER));
        try {
            $tq->login->request(self::USER, 'LOGIN');
            $this->fail('expected a refusal');
        } catch (TouchQueAPIException $e) {
            $this->assertSame(403, $e->getStatus());
            $this->assertSame('REF-USE', $e->getCaseCode());
        }
    }

    public function testTheSilentCheckReturnsItsCase(): void
    {
        $this->assertSame('CHK-2QX', $this->client()->risk->check(['externalUsername' => self::USER])['caseCode']);
    }

    public function testTheGuardKeepsShowingTheCaseWhileItWaits(): void
    {
        self::$api->opts(['numberMatch' => true]);
        $tq = $this->client();
        $first = Guard::run($tq, self::USER, 'LOGIN');
        $again = Guard::run($tq, self::USER, 'LOGIN', null, null, null, null, $first['body']['token']);
        $this->assertSame('K7P-2QX', $first['body']['touchque']['caseCode']);
        $this->assertSame('waiting', $again['body']['touchque']['state']);
        $this->assertSame('K7P-2QX', $again['body']['touchque']['caseCode']);
    }
}
