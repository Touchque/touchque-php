<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Illuminate\Container\Container;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Log;
use Touchque\Config;
use Touchque\Guard;
use Touchque\Touchque;
use Touchque\Laravel\TouchqueMiddleware;
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

    private function client(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testFullFlowThroughMiddleware(): void
    {
        self::$api->link('jane@acme.com');
        self::$api->opts(['numberMatch' => true]);
        $tq = $this->client();

        $middleware = new class ($tq) extends TouchqueMiddleware {
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
        $request2->headers->set('X-Touchque-Token', $body['token']);
        $done = $middleware->handle($request2, $handler, 'SEND_MONEY');
        $this->assertSame(200, $done->getStatusCode());
        $this->assertTrue(json_decode($done->getContent(), true)['done']);
    }

    public function testDetailsFromARequestMacroReachThePhone(): void
    {
        self::$api->link('mac@acme.com');
        $middleware = new class ($this->client()) extends TouchqueMiddleware {
            protected function resolveUser(Request $request): ?string
            {
                return 'mac@acme.com';
            }
        };
        Request::macro('transferDetails', function () {
            return ['Amount' => '250 EUR'];
        });
        try {
            $res = $middleware->handle(Request::create('/transfer', 'POST'), fn (Request $r) => new JsonResponse([]), 'SEND_MONEY', 'transferDetails');
        } finally {
            Request::flushMacros();
        }
        $this->assertSame(202, $res->getStatusCode());
        $this->assertSame([['label' => 'Amount', 'value' => '250 EUR']], json_decode($res->getContent(), true)['touchque']['details']);
    }

    public function testAnUnknownDetailsNameIsMisconfiguredNotApprovedWithoutDetails(): void
    {
        $middleware = new class ($this->client()) extends TouchqueMiddleware {
            protected function resolveUser(Request $request): ?string
            {
                return 'mac@acme.com';
            }
        };
        $res = $middleware->handle(Request::create('/transfer', 'POST'), fn (Request $r) => new JsonResponse(['unreachable' => true]), 'SEND_MONEY', 'noSuchDetails');
        $this->assertSame(500, $res->getStatusCode());
        $this->assertSame('misconfigured', json_decode($res->getContent(), true)['touchque']['reason']);
    }

    public function testNoUserIs401(): void
    {
        $tq = $this->client();
        $middleware = new TouchqueMiddleware($tq);
        $handler = fn (Request $r) => response()->json(['unreachable' => true]);
        $request = Request::create('/transfer', 'POST');
        $res = $middleware->handle($request, $handler, 'SEND_MONEY');
        $this->assertSame(401, $res->getStatusCode());
    }

    private const MISCONFIGURED = [
        'touchque' => ['state' => 'blocked', 'reason' => 'misconfigured'],
        'error' => ['code' => 'misconfigured', 'message' => 'Two-factor approval is not configured correctly.'],
    ];
    private const UNAUTHENTICATED = [
        'touchque' => ['state' => 'blocked', 'reason' => 'unauthenticated'],
        'error' => ['code' => 'unauthenticated', 'message' => 'Sign in first.'],
    ];

    /** A middleware for a fixed signed-in user (null: nobody signed in). */
    private static function middlewareFor(?string $user, ?Touchque $tq, array $options = []): TouchqueMiddleware
    {
        return new class ($user, $tq, $options) extends TouchqueMiddleware {
            private ?string $user;

            public function __construct(?string $user, ?Touchque $tq, array $options)
            {
                parent::__construct($tq, $options);
                $this->user = $user;
            }

            protected function resolveUser(Request $request): ?string
            {
                return $this->user;
            }
        };
    }

    /** Runs $fn like a deploy without TQ_API_KEY / TQ_API_SECRET, with Laravel's logger captured. */
    private static function withoutKeys(callable $fn): array
    {
        $saved = ['TQ_API_KEY' => getenv('TQ_API_KEY'), 'TQ_API_SECRET' => getenv('TQ_API_SECRET')];
        putenv('TQ_API_KEY');
        putenv('TQ_API_SECRET');
        $flag = new \ReflectionProperty(Guard::class, 'loggedUnconfigured');
        if (\PHP_VERSION_ID < 80100) {
            $flag->setAccessible(true);
        }
        $flag->setValue(null, false);
        $log = new class {
            public array $lines = [];

            public function error(string $message): void
            {
                $this->lines[] = $message;
            }
        };
        Log::swap($log);
        try {
            $fn();
            return $log->lines;
        } finally {
            Facade::clearResolvedInstances();
            foreach ($saved as $name => $value) {
                if ($value !== false) {
                    putenv("$name=$value");
                }
            }
        }
    }

    public function testMissingKeysAnswer500MisconfiguredAndTheRouteNeverRuns(): void
    {
        $ran = false;
        $handler = function () use (&$ran) {
            $ran = true;
            return new JsonResponse(['ran' => true]);
        };
        $lines = self::withoutKeys(function () use ($handler) {
            // The default client: built on the request, never at construction.
            $signedIn = self::middlewareFor('jane@acme.com', null);
            foreach ([1, 2] as $_) {
                $res = $signedIn->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
                $this->assertSame(500, $res->getStatusCode());
                $this->assertSame(self::MISCONFIGURED, json_decode($res->getContent(), true));
                $this->assertStringContainsString('no-store', $res->headers->get('Cache-Control'));
                $this->assertSame('application/json', $res->headers->get('Content-Type'));
            }
            $anonymous = (new TouchqueMiddleware())->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
            $this->assertSame(401, $anonymous->getStatusCode());
            $this->assertSame(self::UNAUTHENTICATED, json_decode($anonymous->getContent(), true));
        });
        $this->assertFalse($ran, 'the protected route must never run');
        $this->assertSame(['[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.'], $lines);
    }

    public function testMissingKeysGoThroughErrorBody(): void
    {
        self::withoutKeys(function () {
            $middleware = self::middlewareFor('jane@acme.com', null, ['errorBody' => fn (array $r) => ['error' => $r['code'], 'status' => $r['status']]]);
            $res = $middleware->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');
            $this->assertSame(500, $res->getStatusCode());
            $this->assertSame(['error' => 'misconfigured', 'status' => 500, 'touchque' => self::MISCONFIGURED['touchque']], json_decode($res->getContent(), true));
        });
    }

    public function testErrorBodyShapesRefusalsAndKeepsTheStep(): void
    {
        self::$api->link('shape@acme.com');
        $calls = 0;
        $middleware = self::middlewareFor('shape@acme.com', $this->client(), ['errorBody' => function (array $r) use (&$calls) {
            $calls++;
            return ['message' => $r['message'], 'code' => $r['code']];
        }]);
        $handler = fn () => new JsonResponse(['ran' => true]);

        $first = $middleware->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
        $this->assertSame(202, $first->getStatusCode());
        $this->assertSame(0, $calls, 'never called for a 202 step');
        $token = json_decode($first->getContent(), true)['token'];

        self::$api->reject();
        $request = Request::create('/transfer', 'POST');
        $request->headers->set('X-Touchque-Token', $token);
        $res = $middleware->handle($request, $handler, 'SEND_MONEY');
        $this->assertSame(403, $res->getStatusCode());
        $body = json_decode($res->getContent(), true);
        $this->assertSame(['message', 'code', 'touchque'], array_keys($body), 'no token is added');
        $this->assertSame(['The approval was rejected.', 'rejected', 'rejected'], [$body['message'], $body['code'], $body['touchque']['state']]);
        $this->assertStringContainsString('no-store', $res->headers->get('Cache-Control'));
        $this->assertSame(1, $calls);

        // Status and headers stay: 423 with Retry-After.
        self::$api->opts(['frozen' => true]);
        try {
            $frozen = $middleware->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
        } finally {
            self::$api->opts(['frozen' => false]);
        }
        $this->assertSame([423, '900'], [$frozen->getStatusCode(), $frozen->headers->get('Retry-After')]);
        $body = json_decode($frozen->getContent(), true);
        $this->assertSame(['Too many rejected approvals. Try again later.', 'frozen', 900], [$body['message'], $body['code'], $body['touchque']['retryAfter']]);
    }

    public function testErrorBodyObjectGetsTheStepAndTheSdksKeyWins(): void
    {
        $step = self::UNAUTHENTICATED['touchque'];
        $answer = fn ($value) => self::middlewareFor(null, $this->client(), ['errorBody' => fn () => $value])
            ->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');

        $res = $answer(['error' => 'login_required', 'touchque' => 'mine']);
        $this->assertSame(401, $res->getStatusCode());
        $this->assertSame(['error' => 'login_required', 'touchque' => $step], json_decode($res->getContent(), true));
        $this->assertSame(['error' => 'login_required', 'touchque' => $step], json_decode($answer((object)['error' => 'login_required'])->getContent(), true));
    }

    public function testTheResponseKeepsItsOriginalContent(): void
    {
        $run = fn (array $options) => self::middlewareFor(null, $this->client(), $options)
            ->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');

        // Laravel's getOriginalContent() is the body, as with any JsonResponse.
        $plain = $run([]);
        $this->assertSame(self::UNAUTHENTICATED, $plain->getOriginalContent());
        $this->assertSame(json_encode(self::UNAUTHENTICATED), $plain->getContent());
        $shaped = $run(['errorBody' => fn (array $r) => ['code' => $r['code']]]);
        $this->assertEquals((object)['code' => 'unauthenticated', 'touchque' => self::UNAUTHENTICATED['touchque']], $shaped->getOriginalContent());
        $this->assertSame('Sign in first.', $run(['errorBody' => fn (array $r) => $r['message']])->getOriginalContent());
        // null is sent as null, not {}.
        $this->assertSame('null', $run(['errorBody' => fn () => null])->getContent());
    }

    public function testErrorBodyNonObjectIsSentAsItIs(): void
    {
        foreach (['Sign in first', 42, ['a', 'b'], [], null] as $value) {
            $res = self::middlewareFor(null, $this->client(), ['errorBody' => fn () => $value])
                ->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');
            $this->assertSame(401, $res->getStatusCode());
            $this->assertSame(json_encode($value), $res->getContent());
            $this->assertSame('application/json', $res->headers->get('Content-Type'));
        }
    }

    // ── Through a real Laravel container ─────────────────────────────────

    /** Runs $fn with a fresh container as Laravel's application. */
    private static function withContainer(callable $fn): void
    {
        $app = new Container();
        Container::setInstance($app);
        try {
            $fn($app);
        } finally {
            Container::setInstance(null);
        }
    }

    /** A request whose Laravel auth user is $email. */
    private static function signedIn(string $email): Request
    {
        $request = Request::create('/transfer', 'POST');
        $request->setUserResolver(fn () => (object)['email' => $email]);
        return $request;
    }

    private function fakeClient(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testMissingKeysThroughLaravelsContainer(): void
    {
        $ran = 0;
        $handler = function () use (&$ran) {
            $ran++;
            return new JsonResponse(['ran' => true]);
        };
        $lines = self::withoutKeys(function () use ($handler) {
            self::withContainer(function (Container $app) use ($handler) {
                // Built by the container like an aliased route middleware; no binding at all.
                $middleware = $app->make(TouchqueMiddleware::class);
                foreach ([1, 2] as $_) {
                    $res = $middleware->handle(self::signedIn('jane@acme.com'), $handler, 'SEND_MONEY');
                    $this->assertSame([500, self::MISCONFIGURED], [$res->getStatusCode(), json_decode($res->getContent(), true)]);
                }
                // The service provider's binding throws without keys: the same answer.
                $app->singleton(Touchque::class, fn () => new Touchque());
                $res = $app->make(TouchqueMiddleware::class)->handle(self::signedIn('jane@acme.com'), $handler, 'SEND_MONEY');
                $this->assertSame(500, $res->getStatusCode());
            });
        });
        $this->assertSame(0, $ran, 'the protected route must never run');
        $this->assertSame(['[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.'], $lines);
    }

    public function testTheContainersBindingsGiveTheClient(): void
    {
        self::$api->link('bound@acme.com');
        $handler = fn () => new JsonResponse(['ran' => true]);
        $unreachable = fn () => new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        self::withoutKeys(function () use ($handler, $unreachable) {
            self::withContainer(function (Container $app) use ($handler, $unreachable) {
                // A singleton binding of the service provider.
                $app->singleton(Touchque::class, fn () => $this->fakeClient());
                $res = $app->make(TouchqueMiddleware::class)->handle(self::signedIn('bound@acme.com'), $handler, 'SEND_MONEY');
                $this->assertSame(202, $res->getStatusCode());
            });
            self::withContainer(function (Container $app) use ($handler, $unreachable) {
                // A contextual binding wins over the global one, as with constructor injection.
                $app->singleton(Touchque::class, $unreachable);
                $app->when(TouchqueMiddleware::class)->needs(Touchque::class)->give(fn () => $this->fakeClient());
                $res = $app->make(TouchqueMiddleware::class)->handle(self::signedIn('bound@acme.com'), $handler, 'SEND_MONEY');
                $this->assertSame(202, $res->getStatusCode());
                // A subclass without its own binding takes the middleware's.
                $res = self::middlewareFor('bound@acme.com', null)->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
                $this->assertSame(202, $res->getStatusCode());
            });
            self::withContainer(function (Container $app) use ($handler, $unreachable) {
                // Given as a binding name, and bound to a subclass.
                $app->singleton(Touchque::class, $unreachable);
                $app->bind('touchque.fake', fn () => $this->fakeClient());
                $subclass = self::middlewareFor('bound@acme.com', null);
                $app->when(get_class($subclass))->needs(Touchque::class)->give('touchque.fake');
                $res = $subclass->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
                $this->assertSame(202, $res->getStatusCode());
            });
        });
    }

    public function testErrorBodyIsDecidedByWhatItEncodesTo(): void
    {
        $step = self::UNAUTHENTICATED['touchque'];
        $answer = fn ($value) => self::middlewareFor(null, $this->client(), ['errorBody' => fn () => $value])
            ->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');
        $arrayable = new class implements Arrayable {
            public function toArray()
            {
                return ['message' => 'from toArray'];
            }
        };
        $emptyJson = new class implements Jsonable {
            public function toJson($options = 0)
            {
                return '{}';
            }
        };
        $list = new class implements \JsonSerializable {
            public function jsonSerialize(): array
            {
                return ['a', 'b'];
            }
        };

        $this->assertSame(['message' => 'from toArray', 'touchque' => $step], json_decode($answer($arrayable)->getContent(), true));
        $this->assertSame(['message' => 'collection', 'touchque' => $step], json_decode($answer(new Collection(['message' => 'collection']))->getContent(), true));
        $this->assertSame('{"touchque":' . json_encode($step) . '}', $answer($emptyJson)->getContent(), 'an empty object is still an object');
        $this->assertSame('["a","b"]', $answer($list)->getContent());

        // A result that cannot be encoded takes the failure path.
        $lines = [];
        $logger = function (string $level, string $message) use (&$lines): void {
            $lines[] = $message;
        };
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl, 10000, $logger));
        $res = self::middlewareFor(null, $tq, ['errorBody' => fn () => ['message' => "\xB1\x31"]])
            ->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');
        $this->assertSame([401, self::UNAUTHENTICATED], [$res->getStatusCode(), json_decode($res->getContent(), true)]);
        $this->assertSame(['[Touchque] errorBody failed: Malformed UTF-8 characters, possibly incorrectly encoded'], $lines);
    }

    public function testAnswersOf400AndAboveCarryTheStateHeaders(): void
    {
        self::$api->link('headers@acme.com');
        $handler = fn () => new JsonResponse(['ran' => true]);
        // Even when errorBody sends no `touchque` key, the headers carry the step.
        $anonymous = self::middlewareFor(null, $this->client(), ['errorBody' => fn () => 'Sign in first'])
            ->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
        $this->assertSame([401, 'blocked', 'unauthenticated'], [$anonymous->getStatusCode(), $anonymous->headers->get('X-Touchque-State'), $anonymous->headers->get('X-Touchque-Reason')]);

        $middleware = self::middlewareFor('headers@acme.com', $this->client());
        $waiting = $middleware->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
        $this->assertSame(202, $waiting->getStatusCode());
        $this->assertNull($waiting->headers->get('X-Touchque-State'), 'not on a 202 step');

        self::$api->opts(['frozen' => true]);
        try {
            $frozen = $middleware->handle(Request::create('/transfer', 'POST'), $handler, 'SEND_MONEY');
        } finally {
            self::$api->opts(['frozen' => false]);
        }
        $this->assertSame([423, 'frozen', '900'], [$frozen->getStatusCode(), $frozen->headers->get('X-Touchque-State'), $frozen->headers->get('Retry-After')]);
        $this->assertFalse($frozen->headers->has('X-Touchque-Reason'), 'no reason, no header');
    }

    public function testAThrowingErrorBodyIsLoggedAndTheDefaultBodySent(): void
    {
        $lines = [];
        $logger = function (string $level, string $message) use (&$lines): void {
            $lines[] = [$level, $message];
        };
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl, 10000, $logger));
        $middleware = self::middlewareFor(null, $tq, ['errorBody' => function () {
            throw new \RuntimeException('template missing');
        }]);
        $res = $middleware->handle(Request::create('/transfer', 'POST'), fn () => new JsonResponse(['ran' => true]), 'SEND_MONEY');
        $this->assertSame(401, $res->getStatusCode());
        $this->assertSame(self::UNAUTHENTICATED, json_decode($res->getContent(), true));
        $this->assertSame([['error', '[Touchque] errorBody failed: template missing']], $lines);
    }
}
