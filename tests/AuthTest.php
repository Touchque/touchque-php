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
}
