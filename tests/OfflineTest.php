<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Http\HttpClient;
use TouchQue\Resources\Offline;
use TouchQue\Exceptions\TouchQueAPIException;

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
            new TouchQueAPIException('invalid', 401, ['reason' => 'invalid_code', 'attemptsLeft' => 3])
        );

        $result = (new Offline($http))->verify('c1', 'WRONG12');

        $this->assertSame(['approved' => false, 'reason' => 'invalid_code', 'attemptsLeft' => 3], $result);
    }

    public function testVerifyRethrowsServerErrors(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willThrowException(new TouchQueAPIException('boom', 500));

        $this->expectException(TouchQueAPIException::class);
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

    public function testVerifyTotpForwardsRequestIdAndARejectedRequestIsAResult(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/offline/totp/verify', $this->callback(fn ($b) => ($b['requestId'] ?? null) === 'req-1'))
            ->willThrowException(new TouchQueAPIException('rejected', 410, ['reason' => 'request_rejected']));

        $result = (new Offline($http))->verifyTotp('a@b.com', 'ABCDEFG', 'LOGIN', null, 'req-1');
        $this->assertFalse($result['approved']);
        $this->assertSame('request_rejected', $result['reason']);
    }
}
