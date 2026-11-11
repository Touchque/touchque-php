<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Resources\QrPairings;
use Touchque\Touchque;

/**
 * QR pairing against the shared fake Touchque API: register, the QR's text and
 * hash, the phone's scan, a request for the phone that scanned, and refusals.
 * Same scenarios as the Node SDK's QrPairings tests.
 */
class QrPairingsTest extends TestCase
{
    private const THUMB = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    private static ?FakeApi $api = null;

    public static function setUpBeforeClass(): void
    {
        exec('which node', $out, $code);
        if ($code !== 0) {
            self::markTestSkipped('node is required for contract tests');
        }
        self::$api = FakeApi::start();
        self::$api->link('ayse@acme.com');
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

    private function stored(): array
    {
        $all = json_decode((string) file_get_contents(self::$api->baseUrl . '/__test/qr-pairings'), true);
        return end($all);
    }

    public function testCreateScanThenAskThePhoneThatScanned(): void
    {
        $tq = $this->tq();
        $p = $tq->qrPairings->create(self::THUMB, ['clientIp' => '203.0.113.7', 'userAgent' => 'Mozilla/5.0', 'browser' => 'Chrome 155', 'os' => 'macOS 15']);
        $this->assertSame(QrPairings::uri($p['pairingId'], $p['nonce'], self::THUMB), $p['uri']);
        $this->assertMatchesRegularExpression('#^touchque://pair-browser\?v=1&p=[\w-]{22}&n=[\w-]{43}&k=[\w-]{43}$#', $p['uri']);
        $this->assertSame(rtrim(strtr(base64_encode(hash('sha256', $p['nonce'], true)), '+/', '-_'), '='), $this->stored()['nonceHash']);
        $this->assertSame('waiting', $tq->qrPairings->get($p['pairingId'])['state']);
        $this->assertSame('pairing_not_confirmed', $this->apiError(fn () => $tq->login->request('ayse@acme.com', 'LOGIN', null, null, null, false, false, null, null, null, null, null, null, null, null, null, $p['pairingId']))->getErrorCode());

        self::$api->post('/__test/qr-scan', ['id' => $p['pairingId'], 'user' => 'ayse@acme.com']);
        $seen = $tq->qrPairings->get($p['pairingId']);
        $this->assertSame(['confirmed', 'ayse@acme.com', []], [$seen['state'], $seen['externalUsername'], $seen['proximity']['warnings']]);
        $req = $tq->login->request('ayse@acme.com', 'LOGIN', null, null, null, false, false, null, null, null, null, null, null, null, null, null, $p['pairingId']);
        $after = $tq->qrPairings->get($p['pairingId']);
        $this->assertSame(['requested', $req['requestId']], [$after['state'], $after['requestId']]);
    }

    public function testRefuseAfterTheScanAndChecksBeforeTheCall(): void
    {
        $tq = $this->tq();
        $p = $tq->qrPairings->create(self::THUMB, ['ttlSeconds' => 60]);
        $e = $this->apiError(fn () => $tq->qrPairings->refuse($p['pairingId'], 'policy', 'Not yet'));
        $this->assertSame([409, 'not_open'], [$e->getStatus(), $e->getErrorCode()]);
        self::$api->post('/__test/qr-scan', ['id' => $p['pairingId'], 'user' => 'ayse@acme.com', 'confirm' => false]);
        $refused = $tq->qrPairings->refuse($p['pairingId'], 'device_not_approved', 'Ask IT to approve this computer.', null, 'ABC-123');
        $this->assertSame(['refused', 'device_not_approved', 'ABC-123'], [$refused['state'], $refused['outcome']['reason'], $refused['outcome']['deviceCode']]);
        foreach ([
            fn () => $tq->qrPairings->create('short'),
            fn () => $tq->qrPairings->create(self::THUMB, ['ttlSeconds' => 10]),
            fn () => $tq->qrPairings->create(self::THUMB, ['nonce' => 'x']),
            fn () => $tq->qrPairings->refuse($p['pairingId'], 'nope', 'x'),
            fn () => $tq->qrPairings->refuse($p['pairingId'], 'other', ' '),
        ] as $call) {
            try {
                $call();
                $this->fail('no TouchqueConfigException');
            } catch (TouchqueConfigException $e) {
                $this->assertNotSame('', $e->getMessage());
            }
        }
    }
}
