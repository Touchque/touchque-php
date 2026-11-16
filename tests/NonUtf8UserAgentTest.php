<?php

namespace Touchque\Tests;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueNetworkException;
use Touchque\Guard;
use Touchque\Http\HttpClient;
use Touchque\Laravel\TouchqueMiddleware;
use Touchque\Laravel\TouchqueRelay;
use Touchque\Relay\RelayHandler;
use Touchque\Touchque;

/**
 * A browser's User-Agent header is bytes. One that is not valid UTF-8 must not fail what it
 * goes with (json_encode() refuses the whole body): it is sent with U+FFFD in place of what
 * is not UTF-8, through the relay, the Laravel middleware and relay, Guard::run(), start()
 * and every call that forwards it. Any other field that is not UTF-8 still fails the call.
 */
class NonUtf8UserAgentTest extends TestCase
{
    /** A documentation address the fake API places in Berlin. */
    private const IP = '203.0.113.7';
    /** An iPhone's Safari with a Latin-1 "é" (one byte, 0xE9) at the end: not UTF-8. */
    private const RAW_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1 caf\xe9";
    /** What goes out for it: U+FFFD for that byte. */
    private const SENT_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1 caf\u{FFFD}";

    private static ?FakeApi $api = null;
    private static int $seq = 0;

    public static function setUpBeforeClass(): void
    {
        exec('which node', $out, $code);
        if ($code === 0) {
            self::$api = FakeApi::start();
        }
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$api !== null) {
            self::$api->close();
            self::$api = null;
        }
    }

    private static function user(string $name): string
    {
        return $name . '-' . (++self::$seq) . '-' . bin2hex(random_bytes(3)) . '@example.com';
    }

    // ── what is sent ─────────────────────────────────────────────────────

    public function testTheUserAgentGoesWithTheReplacementCharacterForWhatIsNotUtf8(): void
    {
        $this->assertSame(1, preg_match('//u', self::SENT_UA));
        foreach ([
            [self::RAW_UA, self::SENT_UA],
            ["Mozilla/5.0 \xff\xfe", "Mozilla/5.0 \u{FFFD}\u{FFFD}"],
            // A multi-byte character cut short is one replacement.
            ["Mozilla/5.0 \xe2\x82 x", "Mozilla/5.0 \u{FFFD} x"],
            ["\x80", "\u{FFFD}"],
        ] as [$raw, $sent]) {
            $this->assertSame(
                ['externalUsername' => 'jane@acme.com', 'clientIp' => self::IP, 'userAgent' => $sent],
                HttpClient::withUtf8UserAgent(['externalUsername' => 'jane@acme.com', 'clientIp' => self::IP, 'userAgent' => $raw]),
                bin2hex($raw)
            );
        }
    }

    public function testAValidUserAgentAndEveryOtherFieldGoAsTheyAre(): void
    {
        // Valid UTF-8 is not touched: other scripts, control characters (Touchque strips those), ''.
        foreach (["Mozilla/5.0 (Linux; Android 15) \u{00DC}n\u{00EF}c\u{00F8}d\u{00E9} \u{2713}", "curl/8.7.1\t\x00", ''] as $valid) {
            $this->assertSame(['userAgent' => $valid], HttpClient::withUtf8UserAgent(['userAgent' => $valid]));
        }
        // Only a string in the top-level userAgent field: a username that is not UTF-8 is never made into another.
        $others = ['externalUsername' => "jos\xe9@acme.com", 'context' => ['userAgent' => "x\xff"]];
        $this->assertSame($others, HttpClient::withUtf8UserAgent($others));
        $this->assertSame(['userAgent' => null], HttpClient::withUtf8UserAgent(['userAgent' => null]));
        $this->assertSame(['userAgent' => 7], HttpClient::withUtf8UserAgent(['userAgent' => 7]));
        $this->assertSame([], HttpClient::withUtf8UserAgent([]));
    }

    /**
     * Without the fake API: the call gets past the encoding (to the closed port, a network
     * error), where it threw InvalidArgumentException before.
     */
    public function testTheCallIsSentWhereItUsedToThrow(): void
    {
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9', 2000));
        $calls = [
            'generateSecret' => fn () => $tq->auth->generateSecret('jane@acme.com', self::IP, self::RAW_UA),
            'resetSecret' => fn () => $tq->auth->resetSecret('jane@acme.com', self::IP, self::RAW_UA),
            'login->request' => fn () => $tq->login->request('jane@acme.com', 'LOGIN', null, self::IP, self::RAW_UA),
        ];
        foreach ($calls as $name => $call) {
            try {
                $call();
                $this->fail("$name answered, but nothing should listen on port 9");
            } catch (TouchqueNetworkException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testAUsernameThatIsNotUtf8StillFailsTheCall(): void
    {
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9', 2000));
        $this->expectException(\InvalidArgumentException::class);
        $tq->auth->generateSecret("jos\xe9@acme.com", self::IP, self::RAW_UA);
    }

    // ── through the shared fake API ──────────────────────────────────────

    private function realClient(): Touchque
    {
        if (self::$api === null) {
            $this->markTestSkipped('node is required for contract tests');
        }
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    /** The userAgent of each call the fake API got on $path for $user, in order. */
    private static function sentUserAgents(string $path, string $user): array
    {
        $out = [];
        foreach (self::$api->calls() as $c) {
            if ($c['path'] === $path && ($c['body']['externalUsername'] ?? null) === $user) {
                $out[] = $c['body']['userAgent'] ?? null;
            }
        }
        return $out;
    }

    /** The body of the last call the fake API got on $path, or null. */
    private static function lastBody(string $path): ?array
    {
        $bodies = array_column(array_filter(self::$api->calls(), static fn (array $c): bool => $c['path'] === $path), 'body');
        return $bodies === [] ? null : end($bodies);
    }

    /**
     * Each call that forwards a browser's User-Agent sends it, signed as sent (the fake API
     * checks the signature over the body before it keeps the call).
     *
     * @dataProvider forwarders
     */
    public function testEveryCallThatForwardsTheUserAgentSendsIt(string $path, callable $call): void
    {
        $tq = $this->realClient();
        $user = self::user('ua-call');
        self::$api->link($user);
        try {
            $call($tq, $user);
        } catch (TouchqueAPIException $e) {
            // What the fake API answers (no QR for a linked phone, no vouchers) is not the point: what it got is.
        }
        $body = self::lastBody($path);
        $this->assertNotNull($body, "nothing reached $path");
        $this->assertSame(self::SENT_UA, $body['userAgent']);
    }

    public function forwarders(): array
    {
        $safeTx = [
            'chainId' => 1, 'safe' => '0x' . str_repeat('1', 40), 'guard' => '0x' . str_repeat('2', 40),
            'tx' => ['to' => '0x' . str_repeat('3', 40), 'value' => '0', 'data' => '0x', 'operation' => 0, 'nonce' => 42],
            'approverIndex' => 0,
        ];
        $browser = ['clientIp' => self::IP, 'userAgent' => self::RAW_UA];
        return [
            'login->request' => ['/login/request', fn (Touchque $tq, string $u) => $tq->login->request($u, 'LOGIN', null, self::IP, self::RAW_UA)],
            'auth->generateSecret' => ['/auth/generate-secret', fn (Touchque $tq, string $u) => $tq->auth->generateSecret($u, self::IP, self::RAW_UA)],
            'auth->resetSecret' => ['/auth/secret/reset', fn (Touchque $tq, string $u) => $tq->auth->resetSecret($u, self::IP, self::RAW_UA)],
            'offline->challenge' => ['/offline/challenge', fn (Touchque $tq, string $u) => $tq->offline->challenge($u, 'LOGIN', null, self::IP, self::RAW_UA)],
            'risk->check' => ['/risk/check', fn (Touchque $tq, string $u) => $tq->risk->check(['externalUsername' => $u] + $browser)],
            'recovery->start' => ['/recovery/start', fn (Touchque $tq, string $u) => $tq->recovery->start(['externalUsername' => $u] + $browser)],
            'qrPairings->create' => ['/qr-pairings', fn (Touchque $tq, string $u) => $tq->qrPairings->create(str_repeat('A', 43), $browser)],
            'safeGuard->request' => ['/safe-guard/approvals', fn (Touchque $tq, string $u) => $tq->safeGuard->request($u, 'SAFE_PAYMENT', $safeTx, $browser)],
        ];
    }

    public function testTheRelaysEnrollStartAndItsResetSendIt(): void
    {
        $tq = $this->realClient();
        $user = self::user('ua-relay-enroll');
        $relay = new RelayHandler($tq, ['getUserId' => fn () => $user, 'getLoginUser' => fn () => $user, 'rateLimit' => false]);
        $first = $relay->handle('POST', '/enroll/start', [], self::IP, self::RAW_UA, fn () => null);
        $this->assertSame(200, $first->getStatus());
        $this->assertSame('S', $first->getBody()['secret']);
        // Not scanned yet: 409, then the reset, with the same User-Agent.
        $again = $relay->handle('POST', '/enroll/start', [], self::IP, self::RAW_UA, fn () => null);
        $this->assertSame(200, $again->getStatus());
        $this->assertSame('S2', $again->getBody()['secret']);
        $this->assertSame([self::SENT_UA, self::SENT_UA], self::sentUserAgents('/auth/generate-secret', $user));
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/auth/secret/reset', $user));
        // The phone still reads the browser and the device from it.
        $context = $tq->auth->validateSecret('S2')['setupContext'];
        $this->assertSame([self::IP, ['browser' => 'Safari', 'os' => 'iOS', 'model' => 'iPhone']], [$context['ip'], $context['device']]);
    }

    public function testTheRelaysLoginOfflineQrAndSilentCheckSendIt(): void
    {
        $tq = $this->realClient();
        $user = self::user('ua-relay-login');
        $relay = new RelayHandler($tq, ['getUserId' => fn () => null, 'getLoginUser' => fn () => $user, 'rateLimit' => false, 'silentSignIn' => true]);
        $proof = fn (string $name): ?string => strcasecmp($name, Guard::BROWSER_HEADER) === 0 ? 'browser-proof' : null;

        // No phone yet: the push (404) and the first-time QR.
        $res = $relay->handle('POST', '/login', [], self::IP, self::RAW_UA, fn () => null);
        $this->assertSame(202, $res->getStatus());
        $this->assertSame('enroll', $res->getBody()['touchque']['state']);
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/login/request', $user));
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/auth/generate-secret', $user));

        // A linked phone, a browser with its key proof: the silent check, then the push.
        self::$api->link($user);
        $res = $relay->handle('POST', '/login', [], self::IP, self::RAW_UA, $proof);
        $this->assertSame(202, $res->getStatus());
        $this->assertSame('waiting', $res->getBody()['touchque']['state']);
        $this->assertSame(self::SENT_UA, self::$api->lastCheck()['userAgent']);
        $this->assertSame([self::SENT_UA, self::SENT_UA], self::sentUserAgents('/login/request', $user));

        // The QR for a phone with no internet.
        $res = $relay->handle('POST', '/offline/challenge', [], self::IP, self::RAW_UA, fn () => null);
        $this->assertSame(200, $res->getStatus());
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/offline/challenge', $user));
    }

    public function testGuardRunAndStartSendIt(): void
    {
        $tq = $this->realClient();
        $guarded = self::user('ua-guard');
        $result = Guard::run($tq, $guarded, 'LOGIN', null, null, self::IP, self::RAW_UA);
        $this->assertSame(202, $result['status']);
        $this->assertSame('enroll', $result['body']['touchque']['state']);
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/auth/generate-secret', $guarded));

        $started = self::user('ua-start');
        self::$api->link($started);
        $this->assertSame('waiting', $tq->start('LOGIN', $started, null, null, self::IP, self::RAW_UA)['state']);
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/login/request', $started));
    }

    /** A Laravel JSON request from 203.0.113.7 whose User-Agent header is the raw bytes. */
    private static function laravelRequest(string $uri): Request
    {
        $server = ['REMOTE_ADDR' => self::IP, 'HTTP_USER_AGENT' => self::RAW_UA, 'CONTENT_TYPE' => 'application/json'];
        return Request::create($uri, 'POST', [], [], [], $server, '{}');
    }

    public function testLaravelsMiddlewareSendsIt(): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        $tq = $this->realClient();
        $user = self::user('ua-laravel');
        $middleware = new class ($tq) extends TouchqueMiddleware {
            protected function resolveUser(Request $request): ?string
            {
                return $request->header('X-User');
            }
        };
        $request = self::laravelRequest('/transfer');
        $request->headers->set('X-User', $user);
        $this->assertSame(self::RAW_UA, $request->userAgent());
        $res = $middleware->handle($request, fn () => new JsonResponse([]), 'LOGIN');
        $this->assertSame(202, $res->getStatusCode());
        $this->assertSame('enroll', json_decode((string)$res->getContent(), true)['touchque']['state']);
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/login/request', $user));
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/auth/generate-secret', $user));
        $this->assertSame('iOS', $tq->auth->validateSecret('S')['setupContext']['device']['os']);
    }

    public function testLaravelsRelaySendsIt(): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        $tq = $this->realClient();
        $user = self::user('ua-laravel-relay');
        $relay = new TouchqueRelay($tq, ['getUserId' => fn () => $user, 'getLoginUser' => fn () => $user, 'rateLimit' => false]);
        $this->assertSame(202, $relay->login(self::laravelRequest('/touchque/login'))->getStatusCode());
        // The QR from POST /login is not scanned yet: 409, then the reset.
        $this->assertSame(200, $relay->enrollStart(self::laravelRequest('/touchque/enroll/start'))->getStatusCode());
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/login/request', $user));
        $this->assertSame([self::SENT_UA, self::SENT_UA], self::sentUserAgents('/auth/generate-secret', $user));
        $this->assertSame([self::SENT_UA], self::sentUserAgents('/auth/secret/reset', $user));
    }
}
