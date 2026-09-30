<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Guard;
use TouchQue\TouchQue;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Exceptions\TouchQueException;

/**
 * Contract tests against the shared fake TouchQue API — a real HTTP round
 * trip, so request signing is verified too (not just mocked). Same
 * scenarios as the Node/Python SDKs' step-up tests.
 */
class ContractTest extends TestCase
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

    private function client(): TouchQue
    {
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testStartCheckCompleteFullFlow(): void
    {
        self::$api->link('jane@acme.com');
        $tq = $this->client();

        $step = $tq->start('SEND_MONEY', 'jane@acme.com', ['Amount' => '250 EUR'], 'tx-9');
        $this->assertSame('waiting', $step['state']);
        $this->assertSame('47', $step['number']); // SEND_MONEY is critical in the fake API
        $this->assertSame([['label' => 'Amount', 'value' => '250 EUR']], $step['details']);

        $this->assertSame('waiting', $tq->check($step['requestId'])['state']);
        self::$api->approve();
        $this->assertSame('approved', $tq->check($step['requestId'])['state']);

        $approval = $tq->complete($step['requestId'], 'jane@acme.com', 'SEND_MONEY', ['Amount' => '250 EUR'], 'tx-9');
        $this->assertSame(['phishingResistant' => false, 'method' => 'push'], $approval['assurance']);

        $this->expectException(\Throwable::class);
        $tq->complete($step['requestId'], 'jane@acme.com', 'SEND_MONEY', ['Amount' => '250 EUR'], 'tx-9');
    }

    public function testCompleteRefusesADifferentAmount(): void
    {
        self::$api->link('jane2@acme.com');
        $tq = $this->client();
        $step = $tq->start('SEND_MONEY', 'jane2@acme.com', ['Amount' => '250 EUR']);
        self::$api->approve($step['requestId']);
        $this->expectException(TouchQueException::class);
        $tq->complete($step['requestId'], 'jane2@acme.com', 'SEND_MONEY', ['Amount' => '9999 EUR']);
    }

    public function testUnknownActionIsAClearConfigError(): void
    {
        self::$api->link('jane3@acme.com');
        $tq = $this->client();
        $this->expectException(TouchQueConfigException::class);
        $this->expectExceptionMessageMatches('/NOT_DEFINED/');
        $tq->start('NOT_DEFINED', 'jane3@acme.com');
    }

    public function testActionsDefineCreatesAndUpdates(): void
    {
        $tq = $this->client();
        $tq->actions->define('EXPORT', 'Export data', null, true);
        $calls = self::$api->calls();
        $body = null;
        foreach ($calls as $c) {
            if ($c['path'] === '/action-types') {
                $body = $c['body'];
            }
        }
        $this->assertSame(['type' => 'EXPORT', 'name' => 'Export data', 'critical' => true], $body);
    }

    public function testGuardFullFlowViaRun(): void
    {
        self::$api->link('guard@acme.com');
        self::$api->opts(['numberMatch' => true]);
        $tq = $this->client();

        $first = Guard::run($tq, 'guard@acme.com', 'LOGIN');
        $this->assertSame(202, $first['status']);
        $this->assertSame('waiting', $first['body']['touchque']['state']);
        $this->assertSame('47', $first['body']['touchque']['number']);
        $token = $first['body']['token'];

        $still = Guard::run($tq, 'guard@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertSame(202, $still['status']);

        self::$api->approve();
        $done = Guard::run($tq, 'guard@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertSame(200, $done['status']);
        $this->assertSame('push', $done['approved']['assurance']['method']);

        $replay = Guard::run($tq, 'guard@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertArrayNotHasKey('approved', $replay);
        $this->assertContains($replay['status'], [403, 408, 409]);
    }

    public function testGuardEnrollThenOfflineCode(): void
    {
        $tq = $this->client();

        $first = Guard::run($tq, 'new-offline@acme.com', 'LOGIN');
        $this->assertSame(202, $first['status']);
        $this->assertSame('enroll', $first['body']['touchque']['state']);
        $this->assertStringStartsWith('data:image/png;base64,', $first['body']['touchque']['enroll']['qrCodeDataUrl']);

        self::$api->link('new-offline@acme.com');
        $token = $first['body']['token'];
        $waiting = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertSame('waiting', $waiting['body']['touchque']['state']);

        $off = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $waiting['body']['token'], true);
        $this->assertSame('offline', $off['body']['touchque']['state']);
        $this->assertSame('data:image/png;base64,OFFLINE', $off['body']['touchque']['offline']['qrDataUrl']);

        $wrong = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, 'ZZZZ999');
        $this->assertSame(4, $wrong['body']['touchque']['offline']['attemptsLeft']);

        $ok = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $wrong['body']['token'], false, 'ABCD123');
        $this->assertSame(200, $ok['status']);
        $this->assertSame(['phishingResistant' => false, 'method' => 'offline_code'], $ok['approved']['assurance']);
    }

    public function testGuardPhoneRejectKillsTheOfflineQr(): void
    {
        $tq = $this->client();
        self::$api->link('reject-offline@acme.com');

        $start = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN');
        $off = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $start['body']['token'], true);
        $this->assertSame('offline', $off['body']['touchque']['state']);
        // The QR is linked to the push the user started.
        $qrCalls = array_values(array_filter(self::$api->calls(), fn ($c) => $c['path'] === '/offline/challenge'));
        $this->assertSame($start['body']['touchque']['requestId'], end($qrCalls)['body']['requestId']);

        // While the QR is up the page keeps polling; nothing changes until the phone answers.
        $poll = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token']);
        $this->assertSame(202, $poll['status']);
        $this->assertSame('offline', $poll['body']['touchque']['state']);
        $this->assertSame($off['body']['touchque']['offline']['challengeId'], $poll['body']['touchque']['offline']['challengeId']);

        self::$api->reject(); // the user taps Reject on the phone

        $rejected = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $poll['body']['token']);
        $this->assertSame(403, $rejected['status']);
        $this->assertSame('rejected', $rejected['body']['touchque']['state']);
        // Even the right code from the QR already on screen does not finish it…
        $late = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, 'ABCD123');
        $this->assertSame('rejected', $late['body']['touchque']['state']);
        $this->assertSame('request_rejected', $late['body']['touchque']['reason']);
        // …nor the time-based code…
        $totp = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, '123456', 'totp');
        $this->assertSame('rejected', $totp['body']['touchque']['state']);
        // …and pressing offline mode again gets no QR for that sign-in.
        $again = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $start['body']['token'], true);
        $this->assertSame('rejected', $again['body']['touchque']['state']);
    }

    public function testGuardOfflineQrCarriesTheNumberForMatching(): void
    {
        $tq = $this->client();
        self::$api->link('nm-offline@acme.com');
        self::$api->opts(['numberMatch' => true]);
        try {
            $start = Guard::run($tq, 'nm-offline@acme.com', 'LOGIN');
            $this->assertSame('47', $start['body']['touchque']['number']);
            $off = Guard::run($tq, 'nm-offline@acme.com', 'LOGIN', null, null, null, null, $start['body']['token'], true);
            $this->assertSame('47', $off['body']['touchque']['offline']['challengeCode']);
        } finally {
            self::$api->opts(['numberMatch' => false]);
        }
    }

    public function testGuardFrozenRateLimitedBlocked(): void
    {
        self::$api->link('blocked@acme.com');
        $tq = $this->client();

        self::$api->opts(['frozen' => true]);
        $frozen = Guard::run($tq, 'blocked@acme.com', 'LOGIN');
        $this->assertSame(423, $frozen['status']);
        $this->assertSame(900, $frozen['body']['touchque']['retryAfter']);

        self::$api->opts(['frozen' => false, 'rateLimited' => true]);
        $limited = Guard::run($tq, 'blocked@acme.com', 'LOGIN');
        $this->assertSame(429, $limited['status']);

        self::$api->opts(['rateLimited' => false, 'blocked' => 'geo_policy']);
        $blocked = Guard::run($tq, 'blocked@acme.com', 'LOGIN');
        $this->assertSame(403, $blocked['status']);
        $this->assertSame(['state' => 'blocked', 'reason' => 'geo_policy'], $blocked['body']['touchque']);
    }
}
