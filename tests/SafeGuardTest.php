<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueRejectedException;
use Touchque\SafeApproval;
use Touchque\Touchque;

/**
 * Safe Guard: the verifier against the shared vectors (fixtures/safe-guard-vectors.json, derived
 * from the reference project and shared with every server SDK), and request / status / wait
 * against the shared fake Touchque API.
 */
final class SafeGuardTest extends TestCase
{
    private static FakeApi $api;
    private static array $vectors;

    public static function setUpBeforeClass(): void
    {
        self::$vectors = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/safe-guard-vectors.json'), true);
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    private static function vector(string $name): array
    {
        foreach (self::$vectors['vectors'] as $v) {
            if ($v['name'] === $name) {
                return $v;
            }
        }
        throw new \RuntimeException("no vector $name");
    }

    public function testEveryVector(): void
    {
        foreach (self::$vectors['vectors'] as $v) {
            $t = $v['safeTx'];
            $this->assertSame($v['safeTxHash'], SafeApproval::safeTxHash($t), $v['name']);
            $this->assertSame($v['governanceHash'], SafeApproval::governanceHash($t), $v['name']);
            $this->assertSame($v['message'], SafeApproval::message($v['purpose'], $t['chainId'], $t['guard'], $t['safe'], $v['subject'], $v['expiresAt'], $v['displayDigest']), $v['name']);
            if (isset($v['rows'])) {
                $this->assertSame($v['rowsDigest'], SafeApproval::displayDigest($v['rows']), $v['name']);
            }
            $this->assertSame([
                'valid' => true, 'reason' => null, 'purpose' => $v['purpose'], 'approverIndex' => $t['approverIndex'], 'expiresAt' => $v['expiresAt'],
                'displayDigest' => $v['displayDigest'], 'safeTxHash' => $v['safeTxHash'], 'governanceHash' => $v['governanceHash'],
            ], SafeApproval::verify($t, $v['approval'], self::$vectors['approverKey'], ['now' => self::$vectors['now'], 'approverIndex' => $t['approverIndex'], 'purpose' => $v['purpose']]), $v['name']);
        }
    }

    public function testEveryCheck(): void
    {
        foreach (self::$vectors['checks'] as $c) {
            $key = $c['keyXY'] ?? $c['key'] ?? self::$vectors['approverKey'];
            $got = SafeApproval::verify(self::vector($c['vector'])['safeTx'], $c['approval'], $key, $c['options'] + ['now' => self::$vectors['now']]);
            $this->assertSame($c['reason'], $got['reason'], $c['name']);
            $this->assertSame($c['reason'] === null, $got['valid'], $c['name']);
            if (isset($c['purpose'])) {
                $this->assertSame($c['purpose'], $got['purpose'], $c['name']);
            }
        }
    }

    public function testTrailerAndScheduleCall(): void
    {
        $w = self::$vectors['withApprovals'];
        $this->assertSame($w['expected'], SafeApproval::withApprovals($w['ownerSignatures'], $w['approvals']));
        $s = self::$vectors['scheduleCall'];
        $this->assertSame($s['expected'], SafeApproval::scheduleCall($s['safe'], $s['governanceHash'], $s['approvals']));
    }

    public function testATransactionThatIsNotOneThrows(): void
    {
        $t = self::$vectors['vectors'][0]['safeTx'];
        $t['tx']['operation'] = 2;
        $this->expectException(TouchqueConfigException::class);
        SafeApproval::safeTxHash($t);
    }

    public function testRequestWaitAndCheckTheApprovalHere(): void
    {
        self::$api->link('treasurer@acme.com');
        $v = self::vector('bybit_pattern');
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
        self::$api->opts(['safeTxView' => ['class' => $v['class'], 'flags' => ['delegatecall'], 'safeTxHash' => $v['safeTxHash'], 'governanceHash' => $v['governanceHash'], 'purpose' => $v['purpose']]]);
        $safeTx = $v['safeTx'];
        $safeTx['chainId'] = 1;
        $safeTx['tx']['nonce'] = 42;
        $sent = $tq->safeGuard->request('treasurer@acme.com', 'safe_payment', $safeTx, ['referenceId' => 'tx-1']);
        $this->assertSame($v['governanceHash'], $sent['safeTx']['governanceHash']);
        $call = self::$api->calls()[count(self::$api->calls()) - 1];
        $this->assertSame('/safe-guard/approvals', $call['path']);
        $this->assertSame('1', $call['body']['safeTx']['chainId']);
        $this->assertSame('42', $call['body']['safeTx']['tx']['nonce']);
        $this->assertSame('tx-1', $call['body']['referenceId']);
        $this->assertArrayNotHasKey('approval', $tq->safeGuard->status($sent['requestId'])['safeTx']);

        self::$api->post('/__test/approve', ['id' => $sent['requestId'], 'safeTx' => ['approval' => $v['approval'], 'expiresAt' => $v['expiresAt']]]);
        $done = $tq->safeGuard->waitForApproval($sent['requestId'], 5000, 10);
        $this->assertSame('CONFIRMED', $done['status']);
        $check = SafeApproval::verify($safeTx, $done['safeTx']['approval'], self::$vectors['approverKey'], ['now' => self::$vectors['now'], 'approverIndex' => $done['safeTx']['approverIndex'], 'purpose' => 'schedule']);
        $this->assertTrue($check['valid']);
        $this->assertSame('schedule', $check['purpose']);
        // Without the purpose named, only an ordinary approval passes: this one is to schedule.
        $this->assertSame('signature_invalid', SafeApproval::verify($safeTx, $done['safeTx']['approval'], self::$vectors['approverKey'], ['now' => self::$vectors['now']])['reason']);

        $again = $tq->safeGuard->request('treasurer@acme.com', 'safe_payment', $v['safeTx']);
        self::$api->post('/__test/reject', ['id' => $again['requestId']]);
        $this->expectException(TouchqueRejectedException::class);
        $tq->safeGuard->waitForApproval($again['requestId'], 5000, 10);
    }
}
