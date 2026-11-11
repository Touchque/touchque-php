<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Http\HttpClient;
use Touchque\Resources\Login;
use Touchque\Exceptions\TouchqueRejectedException;
use Touchque\Exceptions\TouchqueTimeoutException;
use Touchque\Exceptions\TouchquePasskeyRequiredError;
use Touchque\Resources\Webhook;

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

    public function testRequestSendsChallengeDigitsOnlyAsTwoOrThree(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))
            ->method('post')
            ->willReturnCallback(function (string $path, array $body) {
                static $call = 0;
                $call++;
                $this->assertSame('/login/request', $path);
                if ($call === 1) {
                    $this->assertSame(3, $body['challengeDigits']);
                } else {
                    $this->assertArrayNotHasKey('challengeDigits', $body);
                }
                return ['requestId' => 'req_1'];
            });

        $login = new Login($http);
        $login->request('a@b.com', 'LOGIN', null, null, null, false, true, null, null, null, 3);
        $login->request('a@b.com', 'LOGIN', null, null, null, false, false, null, null, null, 4);
    }

    public function testRequestSendsExpiresInWhenGiven(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/login/request', ['externalUsername' => 'a@b.com', 'type' => 'AGENT_ON_BEHALF', 'expiresIn' => 180, 'clientSignals' => 'eyJ2IjoxfQ'])
            ->willReturn(['requestId' => 'req_1']);
        (new Login($http))->request('a@b.com', 'AGENT_ON_BEHALF', null, null, null, false, false, null, null, null, null, 180, 'eyJ2IjoxfQ');
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

        $this->expectException(TouchqueRejectedException::class);
        (new Login($http))->verify('a@b.com');
    }

    public function testVerifyThrowsTimeoutExceptionWhenExpired(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1']);
        $http->method('get')->willReturn(['status' => 'EXPIRED']);

        $this->expectException(TouchqueTimeoutException::class);
        (new Login($http))->verify('a@b.com');
    }

    public function testVerifyThrowsPasskeyRequiredWhenPolicyDemandsIt(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1', 'requiresPasskey' => true]);

        $this->expectException(\Touchque\Exceptions\TouchquePasskeyRequiredError::class);
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

        $this->expectException(TouchqueTimeoutException::class);
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

    public function testVerifyThrowsPasskeyRequiredWhenTheRequestMovesToAPasskeyMidFlight(): void
    {
        // Vishing Shield: the user tapped Approve during a call; the request is still open for a passkey.
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturn(['requestId' => 'req_1']);
        $http->method('get')->willReturnOnConsecutiveCalls(['status' => 'PENDING'], ['status' => 'PENDING', 'requiresPasskey' => true]);
        try {
            (new Login($http))->verify('a@b.com');
            $this->fail('expected TouchquePasskeyRequiredError');
        } catch (TouchquePasskeyRequiredError $e) {
            $this->assertSame('req_1', $e->requestId);
            $this->assertSame('step_up', $e->reason);
        }
    }

    public function testWaitForApprovalReturnsApprovedOnceTheStatusFlipsToConfirmed(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->never())->method('post');
        $http->expects($this->exactly(2))
            ->method('get')
            ->with('/login/status/req_1')
            ->willReturnOnConsecutiveCalls(['status' => 'PENDING'], ['status' => 'CONFIRMED', 'confirmedVia' => 'PUSH', 'provisional' => true]);

        $result = (new Login($http))->waitForApproval('req_1', 5000, 1);

        $this->assertTrue($result['approved']);
        $this->assertSame('CONFIRMED', $result['status']);
        $this->assertSame('req_1', $result['requestId']);
        $this->assertSame('PUSH', $result['confirmedVia']);
        $this->assertNull($result['assurance']);
        $this->assertTrue($result['provisional']);
    }

    public function testWaitForApprovalThrowsRejectedExceptionWhenRejected(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('get')->willReturn(['status' => 'REJECTED']);

        $this->expectException(TouchqueRejectedException::class);
        (new Login($http))->waitForApproval('req_1', 5000, 1);
    }

    public function testWaitForApprovalThrowsTimeoutExceptionWhenExpired(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('get')->willReturn(['status' => 'EXPIRED']);

        $this->expectException(TouchqueTimeoutException::class);
        (new Login($http))->waitForApproval('req_1', 5000, 1);
    }

    public function testWaitForApprovalThrowsTimeoutExceptionWhenTheTimeoutElapses(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->method('get')->willReturn(['status' => 'PENDING']);

        $this->expectException(TouchqueTimeoutException::class);
        (new Login($http))->waitForApproval('req_1', 5, 2);
    }

    public function testWaitForApprovalThrowsPasskeyRequiredWhenTheRequestMovesToAPasskeyMidFlight(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))
            ->method('get')
            ->willReturnOnConsecutiveCalls(['status' => 'PENDING'], ['status' => 'PENDING', 'requiresPasskey' => true]);
        try {
            (new Login($http))->waitForApproval('req_1', 5000, 1);
            $this->fail('expected TouchquePasskeyRequiredError');
        } catch (TouchquePasskeyRequiredError $e) {
            $this->assertSame('req_1', $e->requestId);
            $this->assertSame('step_up', $e->reason);
        }
    }

    public function testWaitForApprovalNeedsARequestId(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->never())->method('get');

        $this->expectException(\Touchque\Exceptions\TouchqueConfigException::class);
        (new Login($http))->waitForApproval('');
    }

    public function testWebhookReasonAndEventConstants(): void
    {
        $this->assertSame('vishing_suspected', Webhook::REASON_VISHING_SUSPECTED);
        $this->assertSame('phishing_origin', Webhook::REASON_PHISHING_ORIGIN);
        $this->assertSame('user_reported_coached', Webhook::REASON_USER_REPORTED_COACHED);
        $this->assertSame('APPROVAL_REVOKED', Webhook::EVENT_APPROVAL_REVOKED);
        $this->assertSame('APPROVAL_RECONFIRMED', Webhook::EVENT_APPROVAL_RECONFIRMED);
    }
}
