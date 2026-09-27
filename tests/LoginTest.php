<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Http\HttpClient;
use TouchQue\Resources\Login;
use TouchQue\Exceptions\TouchQueRejectedException;
use TouchQue\Exceptions\TouchQueTimeoutException;

class LoginTest extends TestCase
{
    public function testRequestPostsRequiredAndOptionalFields(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/login/request', ['externalUsername' => 'a@b.com', 'type' => 'WITHDRAW', 'referenceId' => 'txn_1'])
            ->willReturn(['requestId' => 'req_1']);

        $login = new Login($http);
        $login->request('a@b.com', 'WITHDRAW', 'txn_1');
    }

    public function testRequestForwardsDetailsForTheApprovalScreen(): void
    {
        $details = ['Amount' => '1,250.00 USD', 'Recipient' => 'Jane Doe'];
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/login/request', ['externalUsername' => 'a@b.com', 'type' => 'WITHDRAW', 'clientIp' => '203.0.113.7', 'details' => $details])
            ->willReturn(['requestId' => 'req_1']);

        $login = new Login($http);
        $login->request('a@b.com', 'WITHDRAW', null, '203.0.113.7', null, false, false, $details);
    }

    public function testStatusGetsExpectedPath(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('get')
            ->with('/login/status/req_1')
            ->willReturn(['status' => 'PENDING']);

        $login = new Login($http);
        $result = $login->status('req_1');

        $this->assertSame('PENDING', $result['status']);
    }

    public function testVerifyReturnsApprovedTrueWhenConfirmedOnFirstPoll(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1']);
        $http->method('get')->willReturn(['status' => 'CONFIRMED']);

        $login = new Login($http);
        $result = $login->verify('a@b.com');

        $this->assertTrue($result['approved']);
        $this->assertSame('CONFIRMED', $result['status']);
        $this->assertSame('req_1', $result['requestId']);
    }

    public function testVerifyThrowsRejectedExceptionWhenRejectedOnFirstPoll(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1']);
        $http->method('get')->willReturn(['status' => 'REJECTED']);

        $this->expectException(TouchQueRejectedException::class);
        (new Login($http))->verify('a@b.com');
    }

    public function testVerifyThrowsTimeoutExceptionWhenExpired(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1']);
        $http->method('get')->willReturn(['status' => 'EXPIRED']);

        $this->expectException(TouchQueTimeoutException::class);
        (new Login($http))->verify('a@b.com');
    }

    public function testVerifyThrowsPasskeyRequiredWhenPolicyDemandsIt(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1', 'requiresPasskey' => true]);

        $this->expectException(\TouchQue\Exceptions\TouchQuePasskeyRequiredError::class);
        (new Login($http))->verify('a@b.com');
    }

    public function testConsumePostsToTheConsumeEndpoint(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/login/req_1/consume', [])
            ->willReturn(['consumed' => true, 'requestId' => 'req_1']);

        $result = (new Login($http))->consume('req_1');
        $this->assertTrue($result['consumed']);
    }

    public function testVerifyThrowsTimeoutExceptionImmediatelyWhenTimeoutMsIsZero(): void
    {
        // timeoutMs=0 means any elapsed time (even a few microseconds) exceeds
        // the budget on the FIRST status check — this reaches the timeout
        // branch without ever calling the real usleep(), keeping the test fast.
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1']);
        $http->method('get')->willReturn(['status' => 'PENDING']);

        $this->expectException(TouchQueTimeoutException::class);
        (new Login($http))->verify('a@b.com', 'LOGIN', null, 0);
    }

    public function testApproveWithRecoveryCodePostsExpectedPayload(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/login/recovery', ['requestId' => 'req_1', 'code' => 'ABCD-1234'])
            ->willReturn(['success' => true, 'message' => 'approved']);

        $result = (new Login($http))->approveWithRecoveryCode('req_1', 'ABCD-1234');

        $this->assertTrue($result['success']);
    }
}
