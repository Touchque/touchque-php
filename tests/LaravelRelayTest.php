<?php

namespace TouchQue\Tests;

use Illuminate\Contracts\Routing\Registrar;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Laravel\TouchQueRelay;
use TouchQue\Relay\RelayResponse;
use TouchQue\Resources\WebAuthn;
use TouchQue\TouchQue;

class LaravelRelayTest extends TestCase
{
    protected function setUp(): void
    {
        if (!class_exists(Request::class) || !interface_exists(Registrar::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
    }

    private function client(): TouchQue
    {
        $tq = new TouchQue(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        $tq->webauthn = $this->createMock(WebAuthn::class);
        return $tq;
    }

    private static function jsonRequest(string $uri, string $method, array $body): Request
    {
        $request = Request::create($uri, $method, [], [], [], ['CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => '203.0.113.7'], (string)json_encode($body));
        return $request;
    }

    public function testRegistersAllFourteenRoutesOnTheControllerClass(): void
    {
        $registered = [];
        $router = $this->createMock(Registrar::class);
        foreach (['get', 'post', 'delete'] as $verb) {
            $router->method($verb)->willReturnCallback(function ($uri, $action) use ($verb, &$registered) {
                $registered[] = strtoupper($verb) . ' ' . $uri . ' ' . $action[0] . '@' . $action[1];
                return null;
            });
        }
        TouchQueRelay::routes($router, '/touchque/');
        $this->assertCount(14, $registered);
        $this->assertContains('POST /touchque/login ' . TouchQueRelay::class . '@login', $registered);
        $this->assertContains('DELETE /touchque/passkey/credentials/{id} ' . TouchQueRelay::class . '@deleteCredential', $registered);
        $this->assertContains('GET /touchque/enroll/status ' . TouchQueRelay::class . '@enrollStatus', $registered);
        foreach ($registered as $line) {
            $method = substr($line, strrpos($line, '@') + 1);
            $this->assertTrue(method_exists(TouchQueRelay::class, $method), $method);
        }
    }

    public function testOnAuthenticatedCanUseTheSessionAndTheResponse(): void
    {
        $tq = $this->client();
        $tq->webauthn->method('primaryVerify')->with('att_1', ['id' => 'x'])
            ->willReturn(['success' => true, 'externalUsername' => 'jane@acme.com', 'requestId' => 'req_2']);
        $relay = new TouchQueRelay($tq, [
            'onAuthenticated' => function (Request $request, RelayResponse $response, array $info) {
                $request->session()->put('touchque_user', $info['externalUsername']);
                $response->addHeader('Set-Cookie', 'app_session=abc; Path=/; HttpOnly');
            },
        ]);
        $request = self::jsonRequest('/touchque/passkey/authenticate/verify', 'POST', ['attemptId' => 'att_1', 'response' => ['id' => 'x']]);
        $session = new Store('test', new ArraySessionHandler(60));
        $request->setLaravelSession($session);

        $res = $relay->passkeyAuthenticateVerify($request);
        $this->assertInstanceOf(JsonResponse::class, $res);
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(['status' => 'success', 'requestId' => 'req_2'], json_decode((string)$res->getContent(), true));
        $this->assertSame('jane@acme.com', $session->get('touchque_user'));
        $this->assertSame('app_session', $res->headers->getCookies()[0]->getName());
    }

    public function testDefaultUserComesFromLaravelAuth(): void
    {
        $tq = $this->client();
        $tq->webauthn->expects($this->once())->method('listCredentials')->with('jane@acme.com')->willReturn([]);
        $relay = new TouchQueRelay($tq);

        $anonymous = Request::create('/touchque/passkey/credentials', 'GET');
        $res = $relay->passkeyCredentials($anonymous);
        $this->assertSame(401, $res->getStatusCode());
        $this->assertSame('UNAUTHORIZED_FOR_2FA', json_decode((string)$res->getContent(), true)['error']);

        $signedIn = Request::create('/touchque/passkey/credentials', 'GET');
        $signedIn->setUserResolver(function () {
            return (object)['email' => 'jane@acme.com'];
        });
        $res = $relay->passkeyCredentials($signedIn);
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame('{}', $res->getContent());
    }

    public function testRateLimitHeadersReachTheLaravelResponse(): void
    {
        $tq = $this->client();
        $tq->webauthn->method('authenticateOptions')->willReturn(['challenge' => 'c']);
        $relay = new TouchQueRelay($tq, ['rateLimit' => ['perIp' => 1]]);
        $this->assertSame(200, $relay->passkeyLoginOptions(self::jsonRequest('/touchque/passkey/login/options', 'POST', ['requestId' => 'r']))->getStatusCode());
        $res = $relay->passkeyLoginOptions(self::jsonRequest('/touchque/passkey/login/options', 'POST', ['requestId' => 'r']));
        $this->assertSame(429, $res->getStatusCode());
        $this->assertGreaterThan(0, (int)$res->headers->get('Retry-After'));
        $this->assertSame('RATE_LIMITED', json_decode((string)$res->getContent(), true)['error']);
    }
}
