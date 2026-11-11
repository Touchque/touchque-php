<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\HostedLogin\HostedLogin;
use Touchque\HostedLogin\MyAccountException;

/** My Account API client: the refresh-token trade, calls, the step-up answer. */
class MyAccountTest extends TestCase
{
    private array $calls = [];

    private function login(): HostedLogin
    {
        return new HostedLogin([
            'domain' => 'acme.login.touchque.com', 'clientId' => 'c1',
            'transport' => function (string $method, string $url, array $headers, ?string $body) {
                $this->calls[] = compact('method', 'url', 'headers', 'body');
                $path = parse_url($url, PHP_URL_PATH);
                if ($path === '/oauth/token') {
                    parse_str($body, $f);
                    return [200, json_encode(['access_token' => 'me-at', 'token_type' => 'Bearer', 'expires_in' => 600, 'scope' => $f['scope'], 'refresh_token' => 'tqr_2'])];
                }
                if ($path === '/me/v1/profile' && $method === 'PATCH') {
                    return [200, json_encode(['id' => 'usr_1'] + json_decode($body, true))];
                }
                if ($path === '/me/v1/sessions/s%201') {
                    return [204, ''];
                }
                if ($path === '/me/v1' && $method === 'DELETE') {
                    return [401, json_encode(['error' => 'insufficient_user_authentication', 'error_description' => 'A more recent sign-in is required', 'max_age' => 600])];
                }
                return [404, json_encode(['error' => 'not_found'])];
            },
        ]);
    }

    public function testTradeAndCalls(): void
    {
        $login = $this->login();
        $me = $login->myAccountToken('tqr_1');
        $this->assertSame('me-at', $me['accessToken']);
        $this->assertSame('tqr_2', $me['refreshToken']);
        parse_str($this->calls[0]['body'], $f);
        $this->assertSame('https://acme.login.touchque.com/me/', $f['audience']);
        $account = $login->myAccount($me['accessToken']);
        $this->assertSame(['id' => 'usr_1', 'name' => 'Zoë'], $account->updateProfile(['name' => 'Zoë']));
        $this->assertContains('Authorization: Bearer me-at', $this->calls[1]['headers']);
        $account->endSession('s 1');
        $this->assertSame('https://acme.login.touchque.com/account/security', $login->accountUrl('security'));
    }

    public function testStepUp(): void
    {
        try {
            $this->login()->myAccount('old')->deleteAccount();
            $this->fail('no exception');
        } catch (MyAccountException $e) {
            $this->assertTrue($e->isStepUp());
            $this->assertSame(600, $e->getMaxAge());
            $this->assertSame(401, $e->getStatus());
        }
    }
}
