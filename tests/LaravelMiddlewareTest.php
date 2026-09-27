<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use Illuminate\Http\Request;
use TouchQue\Config;
use TouchQue\TouchQue;
use TouchQue\Laravel\TouchQueMiddleware;
use Illuminate\Http\JsonResponse;

class LaravelMiddlewareTest extends TestCase
{
    private static ?FakeApi $api = null;

    public static function setUpBeforeClass(): void
    {
        if (!class_exists(Request::class)) {
            self::markTestSkipped('illuminate/http not installed');
        }
        exec('which node', $out, $code);
        if ($code !== 0) {
            self::markTestSkipped('node is required for contract tests');
        }
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api?->close();
    }

    private function client(): TouchQue
    {
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testFullFlowThroughMiddleware(): void
    {
        self::$api->link('jane@acme.com');
        self::$api->opts(['numberMatch' => true]);
        $tq = $this->client();

        $middleware = new class ($tq) extends TouchQueMiddleware {
            protected function resolveUser(Request $request): ?string
            {
                return $request->header('X-User');
            }
        };

        $handler = function (Request $request) {
            return new JsonResponse(['done' => true, 'touchque' => $request->attributes->get('touchque')]);
        };

        $request = Request::create('/transfer', 'POST', [], [], [], [], (string)json_encode(['amount' => 5]));
        $request->headers->set('X-User', 'jane@acme.com');
        $request->headers->set('Content-Type', 'application/json');

        $first = $middleware->handle($request, $handler, 'SEND_MONEY');
        $this->assertSame(202, $first->getStatusCode());
        $body = json_decode($first->getContent(), true);
        $this->assertSame('47', $body['touchque']['number']);

        self::$api->approve();

        $request2 = Request::create('/transfer', 'POST', [], [], [], [], (string)json_encode(['amount' => 5]));
        $request2->headers->set('X-User', 'jane@acme.com');
        $request2->headers->set('X-TouchQue-Token', $body['token']);
        $done = $middleware->handle($request2, $handler, 'SEND_MONEY');
        $this->assertSame(200, $done->getStatusCode());
        $this->assertTrue(json_decode($done->getContent(), true)['done']);
    }

    public function testNoUserIs401(): void
    {
        $tq = $this->client();
        $middleware = new TouchQueMiddleware($tq);
        $handler = fn (Request $r) => response()->json(['unreachable' => true]);
        $request = Request::create('/transfer', 'POST');
        $res = $middleware->handle($request, $handler, 'SEND_MONEY');
        $this->assertSame(401, $res->getStatusCode());
    }
}
