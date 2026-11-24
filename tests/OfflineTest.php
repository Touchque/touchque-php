<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Http\HttpClient;
use Touchque\Resources\Offline;
use Touchque\Exceptions\TouchqueAPIException;

class OfflineTest extends TestCase
{
    public function testChallengePostsExpectedFields(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/offline/challenge', [
                'externalUsername' => 'a@b.com', 'type' => 'WITHDRAW',
                'details' => ['Amount' => '10 EUR'], 'ttlSeconds' => 60,
            ])
            ->willReturn(['challengeId' => 'c1', 'qrDataUrl' => 'data:x']);

        (new Offline($http))->challenge('a@b.com', 'WITHDRAW', ['Amount' => '10 EUR'], null, null, 60);
    }

    public function testVerifyReturnsApprovedFalseInsteadOfThrowing(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willThrowException(
            new TouchqueAPIException('invalid', 401, ['reason' => 'invalid_code', 'attemptsLeft' => 3])
        );

        $result = (new Offline($http))->verify('c1', 'WRONG12');

        $this->assertSame(['approved' => false, 'reason' => 'invalid_code', 'attemptsLeft' => 3], $result);
    }

    public function testVerifyRethrowsServerErrors(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willThrowException(new TouchqueAPIException('boom', 500));

        $this->expectException(TouchqueAPIException::class);
        (new Offline($http))->verify('c1', 'AAAA123');
    }

    public function testVerifyTotpPostsTypeForCriticalActionChecks(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/offline/totp/verify', ['externalUsername' => 'a@b.com', 'code' => '123456', 'type' => 'WITHDRAW'])
            ->willReturn(['approved' => true, 'externalUsername' => 'a@b.com']);

        $result = (new Offline($http))->verifyTotp('a@b.com', '123456', 'WITHDRAW');
        $this->assertTrue($result['approved']);
    }

    public function testChallengeLinksThePushAndAsksForNumberMatching(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/offline/challenge', [
                'externalUsername' => 'a@b.com', 'type' => 'LOGIN', 'requestId' => 'req-1', 'requireNumberMatch' => true,
            ])
            ->willReturn(['challengeId' => 'c1', 'challengeCode' => '47']);

        $ch = (new Offline($http))->challenge('a@b.com', 'LOGIN', null, null, null, null, true, 'req-1', true);
        $this->assertSame('47', $ch['challengeCode']);
    }

    public function testChallengeAsksForTheCompactQrAndItsTerminalDrawing(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/offline/challenge', [
                'externalUsername' => 'a@b.com', 'type' => 'LOGIN', 'includeQrImage' => false,
                'qrFormat' => 'compact', 'includeQrTerminal' => true,
            ])
            ->willReturn(['challengeId' => 'c1', 'qr' => 'TQ3:X', 'qrFormat' => 'compact', 'qrDataUrl' => null, 'qrTerminal' => "█▀█\n▀▀▀"]);

        $ch = (new Offline($http))->challenge('a@b.com', 'LOGIN', includeQrImage: false, qrFormat: 'compact', includeQrTerminal: true);
        $this->assertSame(['compact', "█▀█\n▀▀▀"], [$ch['qrFormat'], $ch['qrTerminal']]);
    }

    public function testVerifyTotpForwardsRequestIdAndARejectedRequestIsAResult(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/offline/totp/verify', $this->callback(fn ($b) => ($b['requestId'] ?? null) === 'req-1'))
            ->willThrowException(new TouchqueAPIException('rejected', 410, ['reason' => 'request_rejected']));

        $result = (new Offline($http))->verifyTotp('a@b.com', 'ABCDEFG', 'LOGIN', null, 'req-1');
        $this->assertFalse($result['approved']);
        $this->assertSame('request_rejected', $result['reason']);
    }

    public function testIssueDevicePackPostsThePersonTheDeviceAndTheAccount(): void
    {
        $scope = ['id' => 'pc-1', 'name' => 'LAPTOP-JANE'];
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))
            ->method('post')
            ->withConsecutive(
                ['/offline/device-packs', ['externalUsername' => 'jane@acme.com', 'scope' => $scope, 'account' => 'ACME\\jane']],
                ['/offline/device-packs', ['externalUsername' => 'jane@acme.com', 'scope' => $scope, 'account' => 'ACME\\jane', 'count' => 5, 'validDays' => 7]]
            )
            ->willReturn(['scope' => $scope + ['epoch' => '0123456789abcdef'], 'slots' => []]);

        $offline = new Offline($http);
        $offline->issueDevicePack('jane@acme.com', $scope, 'ACME\\jane');
        $offline->issueDevicePack('jane@acme.com', $scope, 'ACME\\jane', 5, 7);
    }

    public function testRevokeAndReportDevicePacksPostTheScopeIdAndTimesInUtc(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(3))
            ->method('post')
            ->withConsecutive(
                ['/offline/device-packs/revoke', ['scopeId' => 'pc-1']],
                ['/offline/device-packs/revoke', ['scopeId' => 'pc-1', 'externalUsername' => 'jane@acme.com', 'reason' => 'lost']],
                ['/offline/device-packs/report', ['scopeId' => 'pc-1', 'externalUsername' => 'jane@acme.com', 'used' => [
                    ['index' => 7, 'at' => '2026-11-12T08:30:00.000Z'],
                    ['index' => 8, 'at' => '2026-11-12T09:00:00.000Z'],
                    ['index' => 9, 'at' => '2026-11-12T09:30:00.000Z'],
                ]]]
            )
            ->willReturn(['revoked' => 1]);

        $offline = new Offline($http);
        $offline->revokeDeviceScope('pc-1');
        $offline->revokeDeviceScope('pc-1', 'jane@acme.com', 'lost');
        $at = new \DateTime('2026-11-12 11:30:00', new \DateTimeZone('Europe/Istanbul'));
        $offline->reportDevicePackUse('pc-1', 'jane@acme.com', [
            ['index' => 7, 'at' => $at],
            ['index' => 8, 'at' => new \DateTimeImmutable('2026-11-12T09:00:00Z')],
            ['index' => 9, 'at' => '2026-11-12T09:30:00.000Z'],
        ]);
        $this->assertSame('Europe/Istanbul', $at->getTimezone()->getName()); // the caller's DateTime is not changed
    }

    public function testDeviceCodeHelpersFollowTheSharedVectors(): void
    {
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/offline-device-vectors.json'), true);
        foreach ($vectors['normalize'] as $case) {
            $this->assertSame($case['expected'], Offline::normalizeDeviceCode($case['input']));
        }
        foreach ($vectors['codes'] as $case) {
            $this->assertSame($case['expectedCode'], Offline::normalizeDeviceCode($case['expectedCode']));
        }
        $this->assertSame($vectors['slotQr']['expectedFormatted'], Offline::formatDeviceCode($vectors['slotQr']['expectedCode']));
        $this->assertSame('5KMY9-TPZAQ', Offline::formatDeviceCode(" 5kmy9 tpzaq\n"));
        $this->assertSame([null, null], [Offline::normalizeDeviceCode('5KMY9-TPZAQ1'), Offline::formatDeviceCode('5KMY9-TPZA')]);

        $d = $vectors['digest'];
        $slot = ['index' => $d['index'], 'salt' => base64_encode(hex2bin($d['saltHex'])), 'digest' => base64_encode(hex2bin($d['expectedDigestHex']))];
        $this->assertTrue(Offline::verifyDeviceCode($d['kdf'], $slot, $d['code']));
        $this->assertTrue(Offline::verifyDeviceCode($d['kdf'], $slot, strtolower($vectors['slotQr']['expectedFormatted'])));
        $this->assertFalse(Offline::verifyDeviceCode($d['kdf'], $slot, 'PDG4MSATZB')); // another slot's code
        $this->assertFalse(Offline::verifyDeviceCode($d['kdf'], ['index' => $d['index'] + 1] + $slot, $d['code'])); // the index is in the salt
        $this->assertFalse(Offline::verifyDeviceCode(['name' => 'scrypt'] + $d['kdf'], $slot, $d['code']));
        $this->assertFalse(Offline::verifyDeviceCode(['length' => 32] + $d['kdf'], $slot, $d['code']));
        $this->assertFalse(Offline::verifyDeviceCode($d['kdf'], ['salt' => 'not base64!'] + $slot, $d['code']));
    }

    public function testVerifyDeviceCodeRefusesAMalformedCodeWithoutComputing(): void
    {
        // A billion iterations would take minutes: an answer in time means nothing was computed.
        $slow = ['name' => 'pbkdf2-sha256', 'iterations' => 1000000000, 'length' => 16];
        $slot = ['index' => 7, 'salt' => base64_encode(str_repeat("\0", 16)), 'digest' => base64_encode(str_repeat("\0", 16))];
        $started = microtime(true);
        foreach (['', '5KMY9TPZA', '5KMY9TPZAQ1', 'ABCDEFGHI0', 'ABCDEFGHIO', '5KMY9_TPZAQ'] as $typed) {
            $this->assertFalse(Offline::verifyDeviceCode($slow, $slot, $typed));
        }
        $this->assertLessThan(1, microtime(true) - $started);
    }
}
