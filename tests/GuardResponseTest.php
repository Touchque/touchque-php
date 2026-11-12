<?php

namespace Touchque\Tests;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Guard;
use Touchque\Laravel\TouchqueMiddleware;
use Touchque\Relay\RelayHandler;
use Touchque\Relay\RelayResponse;
use Touchque\Touchque;

/**
 * Guard::response(): the answer for a guard result in your own handler is the
 * one TouchqueMiddleware and the relay send for it.
 */
class GuardResponseTest extends TestCase
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

    private static function client(?callable $logger = null): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl, 10000, $logger));
    }

    /** Real guard results: 202 waiting, 403 rejected, 429 rate_limited, 500 misconfigured. */
    private static function results(Touchque $tq): array
    {
        self::$api->link('answers@acme.com');
        $waiting = Guard::run($tq, 'answers@acme.com', 'LOGIN');
        self::$api->reject();
        $rejected = Guard::run($tq, 'answers@acme.com', 'LOGIN', null, null, null, null, $waiting['body']['token']);
        self::$api->opts(['rateLimited' => true]);
        try {
            $limited = Guard::run($tq, 'answers@acme.com', 'LOGIN');
        } finally {
            self::$api->opts(['rateLimited' => false]);
        }
        $misconfigured = Guard::run($tq, 'answers@acme.com', 'NO_SUCH_ACTION');
        $results = ['202' => $waiting, '403' => $rejected, '429' => $limited, '500' => $misconfigured];
        foreach ($results as $status => $result) {
            self::assertSame((int)$status, $result['status']);
        }
        return $results;
    }

    /** What TouchqueMiddleware answers for $result (its private respond()). */
    private static function middlewareAnswer(Touchque $tq, array $result, ?callable $errorBody): JsonResponse
    {
        $middleware = new TouchqueMiddleware($tq, $errorBody !== null ? ['errorBody' => $errorBody] : []);
        $respond = new \ReflectionMethod(TouchqueMiddleware::class, 'respond');
        if (\PHP_VERSION_ID < 80100) {
            $respond->setAccessible(true);
        }
        return $respond->invoke($middleware, $result);
    }

    /** What the relay answers for $result (its private guardResponse()). */
    private static function relayAnswer(array $result): RelayResponse
    {
        $answer = new \ReflectionMethod(RelayHandler::class, 'guardResponse');
        if (\PHP_VERSION_ID < 80100) {
            $answer->setAccessible(true);
        }
        return $answer->invoke(null, $result);
    }

    private function assertSameAnswer(array $expected, JsonResponse $res, string $case): void
    {
        $this->assertSame($expected['status'], $res->getStatusCode(), $case);
        $this->assertSame(json_encode($expected['body']), $res->getContent(), $case);
        foreach ($expected['headers'] as $name => $value) {
            if ($name === 'Cache-Control') {
                // Symfony adds "private" to a Cache-Control without public / private.
                $this->assertTrue($res->headers->hasCacheControlDirective($value), "$case: $name");
                continue;
            }
            $this->assertSame($value, $res->headers->get($name), "$case: $name");
        }
        foreach (['Retry-After', 'X-Touchque-State', 'X-Touchque-Reason'] as $name) {
            $this->assertSame(isset($expected['headers'][$name]), $res->headers->has($name), "$case: $name");
        }
    }

    public function testTheHelperGivesWhatTheAdaptersSend(): void
    {
        $tq = self::client();
        $errorBodies = [
            'no errorBody' => null,
            'an object' => fn (array $r) => ['message' => $r['message'], 'code' => $r['code'], 'touchque' => 'mine'],
            'a string' => fn (array $r) => $r['message'],
            'null' => fn () => null,
        ];
        foreach (self::results($tq) as $status => $result) {
            foreach ($errorBodies as $name => $errorBody) {
                $expected = Guard::response($result, $errorBody, $tq);
                $this->assertSameAnswer($expected, self::middlewareAnswer($tq, $result, $errorBody), "$status, $name");
            }
            $plain = Guard::response($result);
            $relay = self::relayAnswer($result);
            $this->assertSame([$plain['status'], $plain['headers'], $plain['body']], [$relay->getStatus(), $relay->getHeaders(), $relay->getBody()], "relay $status");
        }
    }

    public function testWhatTheHelperGives(): void
    {
        $results = self::results(self::client());
        $shape = fn (array $r) => ['message' => $r['message'], 'code' => $r['code'], 'touchque' => 'mine'];

        // A 202 step: the body as it is, never errorBody.
        $called = false;
        $waiting = Guard::response($results['202'], function () use (&$called) {
            $called = true;
            return 'never';
        });
        $this->assertFalse($called);
        $this->assertSame([202, ['Cache-Control' => 'no-store'], $results['202']['body']], [$waiting['status'], $waiting['headers'], $waiting['body']]);

        // 403: the state headers; errorBody's object gets the step, the SDK's key wins, no token.
        $rejected = Guard::response($results['403'], $shape);
        $this->assertSame(['Cache-Control' => 'no-store', 'X-Touchque-State' => 'rejected'], $rejected['headers']);
        $this->assertSame(
            ['message' => 'The approval was rejected.', 'code' => 'rejected', 'touchque' => $results['403']['body']['touchque']],
            json_decode(json_encode($rejected['body']), true)
        );

        // 429: Retry-After and the reason; the default body keeps its token.
        $limited = Guard::response($results['429']);
        $this->assertSame(['Cache-Control' => 'no-store', 'Retry-After' => '60', 'X-Touchque-State' => 'rate_limited'], $limited['headers']);
        $this->assertSame($results['429']['body'], $limited['body']);
        $this->assertArrayHasKey('token', $limited['body']);

        // 500: a string from errorBody is the body as it is.
        $misconfigured = Guard::response($results['500'], fn (array $r) => $r['code']);
        $this->assertSame([500, 'misconfigured'], [$misconfigured['status'], $misconfigured['body']]);
        $this->assertSame(['Cache-Control' => 'no-store', 'X-Touchque-State' => 'blocked', 'X-Touchque-Reason' => 'misconfigured'], $misconfigured['headers']);
    }

    public function testAFailingErrorBodyIsLoggedAndTheDefaultBodySent(): void
    {
        $lines = [];
        $tq = self::client(function (string $level, string $message) use (&$lines): void {
            $lines[] = [$level, $message];
        });
        $result = Guard::unauthenticated();
        $boom = function () {
            throw new \RuntimeException('template missing');
        };

        $answer = Guard::response($result, $boom, $tq);
        $this->assertSame([401, $result['body']], [$answer['status'], $answer['body']]);
        $this->assertSame([['error', '[Touchque] errorBody failed: template missing']], $lines);

        // A result that cannot be encoded takes the same path.
        $lines = [];
        $this->assertSame($result['body'], Guard::response($result, fn () => ['message' => "\xB1\x31"], $tq)['body']);
        $this->assertSame([['error', '[Touchque] errorBody failed: Malformed UTF-8 characters, possibly incorrectly encoded']], $lines);

        // Without a client: Laravel's logger.
        $log = new class {
            public array $lines = [];

            public function error(string $message): void
            {
                $this->lines[] = $message;
            }
        };
        Log::swap($log);
        try {
            $this->assertSame($result['body'], Guard::response($result, $boom)['body']);
        } finally {
            Facade::clearResolvedInstances();
        }
        $this->assertSame(['[Touchque] errorBody failed: template missing'], $log->lines);
    }

    public function testAnApprovalHasNoAnswer(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Guard::response(['status' => 200, 'approved' => ['requestId' => 'r1']]);
    }
}
