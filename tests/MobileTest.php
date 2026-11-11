<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Resources\Mobile;
use Touchque\Touchque;

/**
 * Mobile SDK (the partner's own app as the approver) against the shared fake
 * Touchque API: an enrollment token the app spends once, replace for a second
 * phone, the devices, the settings, and the push a MOBILE_PUSH webhook
 * becomes. Same scenarios as the Node SDK's tests.
 */
class MobileTest extends TestCase
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

    public function testATokenIsSpentOnceAndASecondPhoneNeedsReplace(): void
    {
        $tq = $this->tq();
        $first = $tq->mobile->createEnrollment(['externalUsername' => 'ada@shop.example']);
        $this->assertMatchesRegularExpression('/^tqe_[A-Za-z0-9_-]{43}$/', $first['enrollmentToken']);
        $device = self::$api->post('/__test/mobile-enroll', ['enrollmentToken' => $first['enrollmentToken'], 'platform' => 'android']);
        try {
            $tq->mobile->createEnrollment(['externalUsername' => 'ada@shop.example']);
            $this->fail('expected already_enrolled');
        } catch (TouchqueAPIException $e) {
            $this->assertSame('already_enrolled', $e->getErrorCode());
        }
        $second = $tq->mobile->createEnrollment(['externalUsername' => 'ada@shop.example', 'replace' => true, 'ttlSeconds' => 300]);
        $this->assertSame($device['deviceId'], $second['replacesDeviceId']);
        self::$api->post('/__test/mobile-enroll', ['enrollmentToken' => $second['enrollmentToken']]);
        $active = $tq->mobile->listDevices(['externalUsername' => 'ada@shop.example'])['devices'];
        $this->assertSame(['ios'], array_column($active, 'platform'));
        $this->assertSame('replaced', $tq->mobile->getDevice($device['deviceId'])['revokedReason']);
        $this->assertSame(['via' => 'webhook', 'ok' => true], $tq->mobile->testPush($active[0]['deviceId']));
        $this->assertSame(['removed' => true, 'wasLinked' => true], $tq->mobile->removeDevice($active[0]['deviceId']));
    }

    public function testSettingsChangeOnlyWhatIsGiven(): void
    {
        $tq = $this->tq();
        $this->assertSame('optional', $tq->mobile->settings()['attestation']);
        $s = $tq->mobile->updateSettings(['iosAppIds' => ['ABCDE12345.com.shop.app'], 'attestation' => 'required']);
        $this->assertSame(['ABCDE12345.com.shop.app'], $s['iosAppIds']);
        $this->assertSame(600, $s['enrollTtlSeconds']);
    }

    public function testYourOwnPushKeys(): void
    {
        $tq = $this->tq();
        $s = $tq->mobile->updateSettings([
            'apns' => ['keyId' => 'ABC123DEFG', 'teamId' => 'TEAM123456', 'topic' => 'com.shop.app', 'key' => '-----BEGIN PRIVATE KEY-----'],
            'fcm' => ['serviceAccount' => ['project_id' => 'shop', 'client_email' => 'push@shop.iam.gserviceaccount.com', 'private_key' => 'x']],
        ]);
        $this->assertSame('touchque', $s['push']['ios']);
        $this->assertSame(['projectId' => 'shop', 'clientEmail' => 'push@shop.iam.gserviceaccount.com'], $s['push']['fcm']);
        $this->assertSame('webhook', $tq->mobile->updateSettings(['apns' => null])['push']['ios']);
    }

    public function testAMobilePushWebhookBecomesTheApnsPayloadAndFcmData(): void
    {
        $event = [
            'event' => 'MOBILE_PUSH', 'externalUsername' => 'ada@shop.example', 'deviceId' => 'd1', 'platform' => 'ios', 'pushToken' => 'apns-token',
            'kind' => 'approval', 'requestId' => 'r1', 'expiresAt' => '2026-10-26T10:00:30.000Z',
            'alert' => ['title' => 'Change delivery address', 'body' => 'Demo Shop is waiting for your approval.'],
            'data' => ['touchque' => '{"v":1,"k":"approval","did":"d1","rid":"r1"}'],
        ];
        $push = Mobile::pushFromWebhook($event);
        $this->assertSame(['aps' => ['sound' => 'default', 'interruption-level' => 'time-sensitive', 'alert' => $event['alert']], 'touchque' => $event['data']['touchque']], $push['apns']);
        $this->assertSame(['touchque' => $event['data']['touchque']], $push['fcmData']);
        $this->assertNull(Mobile::pushFromWebhook(['event' => 'DEVICE_LINKED']));
        $this->assertTrue(Mobile::isPushExpired($push, new \DateTimeImmutable('2026-10-26T10:01:00Z')));
        $this->assertFalse(Mobile::isPushExpired($push, new \DateTimeImmutable('2026-10-26T10:00:00Z')));
    }
}
