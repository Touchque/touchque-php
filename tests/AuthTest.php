<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Http\HttpClient;
use TouchQue\Resources\Auth;

class AuthTest extends TestCase
{
    public function testGenerateSecretPostsExpectedPayload(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/auth/generate-secret', ['externalUsername' => 'a@b.com'])
            ->willReturn(['secret' => 's']);

        $auth = new Auth($http);
        $result = $auth->generateSecret('a@b.com');

        $this->assertSame('s', $result['secret']);
    }

    public function testResetSecretPostsExpectedPayload(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/auth/secret/reset', ['externalUsername' => 'a@b.com'])
            ->willReturn(['secret' => 'new']);

        $auth = new Auth($http);
        $auth->resetSecret('a@b.com');
    }

    public function testValidateSecretPostsExpectedPayload(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method('post')
            ->with('/auth/secret/validate', ['secret' => '123456'])
            ->willReturn(['valid' => true]);

        $auth = new Auth($http);
        $result = $auth->validateSecret('123456');

        $this->assertTrue($result['valid']);
    }

    public function testGetUserGetsExpectedPath(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->once())
            ->method("get")
            ->with("/users/a%2Bx%40b.com")
            ->willReturn(["externalUsername" => "a@b.com", "used" => false]);

        $auth = new Auth($http);
        $result = $auth->getUser("a+x@b.com");

        $this->assertFalse($result["used"]);
    }

    public function testGetUserReturnsTheLinkedPhonesPostureAsDevice(): void
    {
        $device = [
            "platform" => "ios", "model" => "iPhone15,3", "osVersion" => "18.1", "securityPatch" => null,
            "appVersion" => "1.2.0", "screenLock" => true, "biometrics" => "face",
            "jailbroken" => false, "compromised" => false, "hardwareKey" => true, "attestation" => "apple-appattest",
            "signed" => true, "reportedAt" => "2026-10-25T10:00:00.000Z", "lastSeenAt" => "2026-10-25T10:05:00.000Z",
            "linkedAt" => "2026-10-20T09:00:00.000Z", "state" => "healthy", "issues" => [],
        ];
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))
            ->method("get")
            ->willReturnOnConsecutiveCalls(
                ["externalUsername" => "a@b.com", "used" => true, "deviceId" => "dev_1", "device" => $device],
                ["externalUsername" => "c@d.com", "used" => false, "deviceId" => null, "device" => null]
            );

        $auth = new Auth($http);

        $linked = $auth->getUser("a@b.com");
        $this->assertSame($device, $linked["device"]);
        $this->assertSame("healthy", $linked["device"]["state"]);
        $this->assertTrue($linked["device"]["hardwareKey"]);

        $pending = $auth->getUser("c@d.com");
        $this->assertNull($pending["device"]);
    }
}
