<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Http\HttpClient;
use TouchQue\Resources\WebAuthn;

class WebAuthnTest extends TestCase
{
    private function http()
    {
        return $this->createMock(HttpClient::class);
    }

    public function testRegisterOptionsSendsDiscoverableOnlyWhenTrue(): void
    {
        $http = $this->http();
        $http->expects($this->exactly(2))->method('post')->willReturnCallback(
            function ($path, $body) {
                static $call = 0;
                $call++;
                if ($call === 1) {
                    $this->assertSame('/webauthn/register/options', $path);
                    $this->assertSame(['externalUsername' => 'a@b.com'], $body);
                } else {
                    $this->assertSame(['externalUsername' => 'a@b.com', 'discoverable' => true], $body);
                }
                return ['challenge' => 'c'];
            }
        );

        $wa = new WebAuthn($http);
        $wa->registerOptions('a@b.com');
        $wa->registerOptions('a@b.com', true);
    }

    public function testRegisterVerifySendsLabelOnlyWhenPresent(): void
    {
        $http = $this->http();
        $http->expects($this->once())->method('post')
            ->with('/webauthn/register/verify', [
                'externalUsername' => 'a@b.com',
                'response' => ['id' => 'x'],
                'label' => 'MacBook',
            ])
            ->willReturn(['verified' => true, 'credentialId' => 'cred_1']);

        $wa = new WebAuthn($http);
        $r = $wa->registerVerify('a@b.com', ['id' => 'x'], 'MacBook');
        $this->assertSame('cred_1', $r['credentialId']);
    }

    public function testAuthenticateOptionsAndVerify(): void
    {
        $http = $this->http();
        $http->expects($this->exactly(2))->method('post')->willReturnCallback(
            function ($path, $body) {
                static $call = 0;
                $call++;
                if ($call === 1) {
                    $this->assertSame('/webauthn/login/options', $path);
                    $this->assertSame(['requestId' => 'req_1'], $body);
                    return ['challenge' => 'c'];
                }
                $this->assertSame('/webauthn/login/verify', $path);
                $this->assertSame(['requestId' => 'req_1', 'response' => ['id' => 'a']], $body);
                return ['success' => true, 'message' => 'ok'];
            }
        );

        $wa = new WebAuthn($http);
        $wa->authenticateOptions('req_1');
        $wa->authenticateVerify('req_1', ['id' => 'a']);
    }

    public function testPrimaryOptionsAndVerify(): void
    {
        $http = $this->http();
        $http->expects($this->exactly(2))->method('post')->willReturnCallback(
            function ($path, $body) {
                static $call = 0;
                $call++;
                if ($call === 1) {
                    $this->assertSame('/webauthn/authenticate/primary/options', $path);
                    return ['attemptId' => 'att_1', 'options' => []];
                }
                $this->assertSame('/webauthn/authenticate/primary/verify', $path);
                $this->assertSame(['attemptId' => 'att_1', 'response' => ['id' => 'a']], $body);
                return ['success' => false, 'requiresStepUp' => true, 'externalUsername' => 'a@b.com', 'riskScore' => 0.95];
            }
        );

        $wa = new WebAuthn($http);
        $this->assertSame('att_1', $wa->primaryOptions('a@b.com')['attemptId']);
        $this->assertTrue($wa->primaryVerify('att_1', ['id' => 'a'])['requiresStepUp']);
    }

    public function testListCredentialsPassesQueryParam(): void
    {
        $http = $this->http();
        $http->expects($this->once())->method('get')
            ->with('/webauthn/credentials', ['externalUsername' => 'a@b.com'])
            ->willReturn(['credentials' => [['id' => 'c1']]]);

        $wa = new WebAuthn($http);
        $this->assertSame('c1', $wa->listCredentials('a@b.com')['credentials'][0]['id']);
    }

    public function testDeleteCredentialUrlEncodesId(): void
    {
        $http = $this->http();
        $http->expects($this->once())->method('delete')
            ->with('/webauthn/credentials/cred%2F1%202')
            ->willReturn(['deleted' => true]);

        $wa = new WebAuthn($http);
        $this->assertTrue($wa->deleteCredential('cred/1 2')['deleted']);
    }
}
