<?php

namespace Touchque\Tests;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Guard;
use Touchque\Touchque;

/**
 * Guard::run(null, ...) and Guard::isStatusPoll(null, ...): the default client,
 * built from TQ_API_KEY / TQ_API_SECRET per request and kept once built.
 */
class GuardDefaultClientTest extends TestCase
{
    private const ENV = ['TQ_API_KEY', 'TQ_API_SECRET', 'TQ_API_URL'];
    private const UNCONFIGURED = '[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.';

    private static ?FakeApi $api = null;
    private array $savedEnv = [];
    private $log;

    public static function setUpBeforeClass(): void
    {
        if (!class_exists(Log::class)) {
            self::markTestSkipped('illuminate/support is needed to read the log line');
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

    protected function setUp(): void
    {
        foreach (self::ENV as $name) {
            $this->savedEnv[$name] = getenv($name);
        }
        self::resetGuard();
        // Outside a Laravel app the default client logs through Laravel's logger only when there is one.
        $this->log = new class {
            public array $lines = [];

            public function error(string $message): void
            {
                $this->lines[] = $message;
            }
        };
        Log::swap($this->log);
        self::setKeys(false);
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        foreach ($this->savedEnv as $name => $value) {
            putenv($value === false ? $name : "$name=$value");
        }
        self::resetGuard();
    }

    /** Forgets the default client and the "logged once" flag, like a new process. */
    private static function resetGuard(): void
    {
        Guard::setDefaultClient(null);
        $property = new \ReflectionProperty(Guard::class, 'loggedUnconfigured');
        if (\PHP_VERSION_ID < 80100) {
            $property->setAccessible(true);
        }
        $property->setValue(null, false);
        Container::setInstance(null);
    }

    /** The client built from the environment, if any (without building one). */
    private static function defaultClient(): ?Touchque
    {
        $property = new \ReflectionProperty(Guard::class, 'environmentClient');
        if (\PHP_VERSION_ID < 80100) {
            $property->setAccessible(true);
        }
        return $property->getValue();
    }

    private static function fakeClient(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    /** The fake API's keys in the environment, or none. */
    private static function setKeys(bool $set): void
    {
        if ($set) {
            putenv('TQ_API_KEY=tq_test_key');
            putenv('TQ_API_SECRET=test_secret');
            putenv('TQ_API_URL=' . self::$api->baseUrl);
            return;
        }
        foreach (self::ENV as $name) {
            putenv($name);
        }
    }

    public function testWithoutKeysANullClientAnswers500Or401AndLogsOnce(): void
    {
        foreach ([1, 2] as $_) {
            $this->assertSame(Guard::misconfigured(), Guard::run(null, 'jane@acme.com', 'SEND_MONEY'));
        }
        $this->assertSame(Guard::unauthenticated(), Guard::run(null, null, 'SEND_MONEY'));
        $this->assertFalse(Guard::isStatusPoll(null, 'jane@acme.com', 'SEND_MONEY', null, null, 'v1.e30.x'));

        $answer = Guard::response(Guard::run(null, 'jane@acme.com', 'SEND_MONEY'));
        $this->assertSame(500, $answer['status']);
        $this->assertSame(['Cache-Control' => 'no-store', 'X-Touchque-State' => 'blocked', 'X-Touchque-Reason' => 'misconfigured'], $answer['headers']);
        $this->assertSame([self::UNCONFIGURED], $this->log->lines, 'logged once per process');
    }

    public function testWithKeysANullClientRunsTheGuard(): void
    {
        self::setKeys(true);
        $user = 'default-client@acme.com';
        self::$api->link($user);

        $first = Guard::run(null, $user, 'LOGIN');
        $this->assertSame([202, 'waiting'], [$first['status'], $first['body']['touchque']['state']]);
        $token = $first['body']['token'];
        $this->assertTrue(Guard::isStatusPoll(null, $user, 'LOGIN', null, null, $token));

        self::$api->approve();
        $done = Guard::run(null, $user, 'LOGIN', null, null, null, null, $token);
        $this->assertSame([200, $user], [$done['status'], $done['approved']['user']]);
        $this->assertSame([], $this->log->lines);
    }

    public function testTheDefaultClientIsKeptOnceBuiltAndAFailedBuildIsRetried(): void
    {
        $user = 'retry@acme.com';
        self::$api->link($user);
        $this->assertSame(500, Guard::run(null, $user, 'LOGIN')['status']);
        $this->assertNull(self::defaultClient());

        // The keys arrive (a later deploy, a secret mounted late): the next request builds it.
        self::setKeys(true);
        $this->assertSame(202, Guard::run(null, $user, 'LOGIN')['status']);
        $built = self::defaultClient();
        $this->assertInstanceOf(Touchque::class, $built);
        $this->assertSame(202, Guard::run(null, $user, 'LOGIN')['status']);
        $this->assertSame($built, self::defaultClient(), 'built once, then kept');
        $this->assertSame($built, Guard::defaultClient());
        $this->assertSame([self::UNCONFIGURED], $this->log->lines);
    }

    public function testDefaultClientFailsFastAtStartup(): void
    {
        try {
            Guard::defaultClient();
            $this->fail('no keys: defaultClient() throws');
        } catch (TouchqueConfigException $e) {
            $this->assertSame(Config::MISSING_KEYS, $e->getMessage(), 'it names the problem');
        }
        $this->assertSame([], $this->log->lines, 'the check throws; only the guard logs');
        self::setKeys(true);
        $this->assertInstanceOf(Touchque::class, Guard::defaultClient());
    }

    public function testSetDefaultClientGivesTheNullPathYourClientAndNullForgetsIt(): void
    {
        $user = 'mine@acme.com';
        self::$api->link($user);
        $lines = [];
        $mine = new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl, 10000, function (string $level, string $message) use (&$lines): void {
            $lines[] = $message;
        }));
        Guard::setDefaultClient($mine); // no keys in the environment: yours is used
        $this->assertSame($mine, Guard::defaultClient());
        $first = Guard::run(null, $user, 'LOGIN');
        $this->assertSame(202, $first['status']);
        $this->assertTrue(Guard::isStatusPoll(null, $user, 'LOGIN', null, null, $first['body']['token']));
        // Its logger gets the guard's lines (here: Touchque unreachable).
        Guard::setDefaultClient(new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9', 1000, function (string $level, string $message) use (&$lines): void {
            $lines[] = $message;
        })));
        $this->assertSame(503, Guard::run(null, $user, 'LOGIN')['status']);
        $this->assertStringStartsWith('[Touchque] approval failed: ', $lines[0] ?? '');

        // null forgets it: the next call builds from the environment again.
        Guard::setDefaultClient(null);
        $this->assertSame(500, Guard::run(null, $user, 'LOGIN')['status']);
        self::setKeys(true);
        $this->assertSame(202, Guard::run(null, $user, 'LOGIN')['status']);
        $this->assertNotSame($mine, Guard::defaultClient());
    }

    public function testALaravelBindingIsTheDefaultClient(): void
    {
        $user = 'bound@acme.com';
        self::$api->link($user);
        $app = new Container();
        Container::setInstance($app);
        $built = 0;
        // An empty environment: the service provider's binding has the keys (e.g. from config/services.php).
        $app->bind(Touchque::class, function () use (&$built) {
            $built++;
            return self::fakeClient();
        });
        $this->assertSame(202, Guard::run(null, $user, 'LOGIN')['status']);
        $this->assertSame(202, Guard::run(null, $user, 'LOGIN')['status']);
        $this->assertSame(2, $built, 'resolved on each call: the container owns its lifetime');
        $this->assertNull(self::defaultClient(), 'nothing built from the environment');

        // A client given to setDefaultClient() wins over the binding.
        $mine = self::fakeClient();
        Guard::setDefaultClient($mine);
        $this->assertSame($mine, Guard::defaultClient());
        $this->assertSame(2, $built);
        Guard::setDefaultClient(null);

        // A binding that cannot build its client: 500, logged once.
        $app->bind(Touchque::class, fn () => new Touchque());
        $this->assertSame(Guard::misconfigured(), Guard::run(null, $user, 'LOGIN'));
        $this->assertSame(Guard::unauthenticated(), Guard::run(null, null, 'LOGIN'));
        $this->assertSame([self::UNCONFIGURED], $this->log->lines);
    }
}
