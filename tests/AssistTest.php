<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Resources\Assist;
use Touchque\Touchque;

/**
 * The help desk against the shared fake Touchque API: a passed check used once
 * for its own action, a wrong number, "this isn't me" and unfreeze, and no
 * phone. Same scenarios as the Node SDK's Assist tests.
 */
class AssistTest extends TestCase
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
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    private function apiError(callable $call): TouchqueAPIException
    {
        try {
            $call();
        } catch (TouchqueAPIException $e) {
            return $e;
        }
        $this->fail('no TouchqueAPIException');
    }

    public function testAPassedCheckIsUsedOnceForItsAction(): void
    {
        self::$api->reset();
        self::$api->link('ayse@acme.com');
        $tq = $this->tq();
        $s = $tq->assist->open(['externalUsername' => 'ayse@acme.com', 'agent' => ['name' => 'Deniz Kaya', 'title' => 'IT help desk'], 'reason' => 'Ticket 4411']);
        $this->assertSame('OPEN', $s['status']);
        $this->assertTrue($s['notified']);
        $this->assertTrue($s['phone']);
        $check = $tq->assist->verify($s['id'], 'reset_2fa', 'reset your two-step verification');
        $this->assertMatchesRegularExpression('/^\d{2}$/', $check['challengeCode']);
        self::$api->post('/__test/assist', ['requestId' => $check['requestId'], 'action' => 'approve']);
        $this->assertTrue(Assist::checkPassed($tq->assist->get($s['id']), $check['requestId']));
        $this->assertSame(428, $this->apiError(fn() => $tq->assist->spend($s['id'], $check['requestId'], 'reset_password'))->getStatus());
        $this->assertFalse(Assist::checkPassed($tq->assist->spend($s['id'], $check['requestId'], 'reset_2fa'), $check['requestId']));
        $this->assertSame($s['id'], $tq->assist->list(['externalUsername' => 'ayse@acme.com'])[0]['id']);
        $this->assertSame('ENDED', $tq->assist->end($s['id'])['status']);
        $this->assertSame('assist_not_open', $this->apiError(fn() => $tq->assist->verify($s['id'], 'unlock'))->getErrorCode());
    }

    public function testWrongNumberNotMeAndUnfreeze(): void
    {
        self::$api->reset();
        self::$api->link('ayse@acme.com');
        $tq = $this->tq();
        $s = $tq->assist->open(['externalUsername' => 'ayse@acme.com', 'agent' => ['name' => 'Deniz Kaya'], 'notify' => false]);
        $bad = $tq->assist->verify($s['id'], 'activation_link');
        self::$api->post('/__test/assist', ['requestId' => $bad['requestId'], 'action' => 'wrong_number']);
        $this->assertSame('check_required', $this->apiError(fn() => $tq->assist->spend($s['id'], $bad['requestId'], 'activation_link'))->getErrorCode());
        $notMe = $tq->assist->verify($s['id'], 'activation_link');
        self::$api->post('/__test/assist', ['requestId' => $notMe['requestId'], 'action' => 'not_me']);
        $now = $tq->assist->get($s['id']);
        $this->assertTrue($now['frozen']);
        $this->assertSame('not_me', $now['checks'][1]['outcome']);
        $unlock = $tq->assist->verify($s['id'], 'unlock');
        self::$api->post('/__test/assist', ['requestId' => $unlock['requestId'], 'action' => 'approve']);
        $out = $tq->assist->unfreeze($s['id'], $unlock['requestId']);
        $this->assertTrue($out['unfrozen']);
        $this->assertFalse($out['session']['frozen']);
    }

    public function testNoPhoneRoutesToNeverLockedOut(): void
    {
        self::$api->reset();
        $tq = $this->tq();
        $tq->auth->generateSecret('can@acme.com');
        $s = $tq->assist->open(['externalUsername' => 'can@acme.com', 'agent' => ['name' => 'Deniz Kaya']]);
        $this->assertFalse($s['phone']);
        $e = $this->apiError(fn() => $tq->assist->verify($s['id'], 'new_phone'));
        $this->assertSame('no_phone', $e->getErrorCode());
        $this->assertSame('never_locked_out', $e->getData()['route']);
    }

    public function testMissingArgumentsNeverReachTheApi(): void
    {
        $tq = $this->tq();
        foreach ([
            fn() => $tq->assist->open(['externalUsername' => 'a@b.com']),
            fn() => $tq->assist->open(['externalUsername' => 'a@b.com', 'agent' => ['name' => 'x'], 'nope' => 1]),
            fn() => $tq->assist->get(''),
            fn() => $tq->assist->list([]),
            fn() => $tq->assist->verify('id', ''),
        ] as $call) {
            try {
                $call();
                $this->fail('no TouchqueConfigException');
            } catch (TouchqueConfigException $e) {
                $this->assertStringContainsString('assist->', $e->getMessage());
            }
        }
    }
}
