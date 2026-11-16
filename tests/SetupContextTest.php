<?php

namespace Touchque\Tests;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Guard;
use Touchque\Http\HttpClient;
use Touchque\Laravel\TouchqueMiddleware;
use Touchque\Laravel\TouchqueRelay;
use Touchque\Relay\RelayHandler;
use Touchque\Resources\Auth;
use Touchque\Resources\Login;
use Touchque\Steps;
use Touchque\Touchque;

/**
 * 2FA setup context: the request for a first-time linking QR carries the browser's IP and
 * User-Agent (never the QR), and validateSecret() answers where the QR was asked for as
 * `setupContext`. Request bodies, the adapters, the lenient parse of the shared
 * fixtures/setup-context.json, and round trips through the shared fake API.
 */
class SetupContextTest extends TestCase
{
    /** A documentation address the fake API places in Berlin. */
    private const IP = '203.0.113.7';
    /** One it places in New York. */
    private const OTHER_IP = '198.51.100.23';
    private const IPHONE_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
    private const WINDOWS_FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0';

    private static ?FakeApi $api = null;
    private static int $seq = 0;
    private static ?array $fixture = null;

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

    /** The shared fixture: each case a validate answer; `expected` the setupContext read from it. */
    private static function fixture(): array
    {
        if (self::$fixture === null) {
            self::$fixture = json_decode((string)file_get_contents(__DIR__ . '/../fixtures/setup-context.json'), true, 512, JSON_THROW_ON_ERROR);
        }
        return self::$fixture;
    }

    /** What $call sent through an Auth over a mocked HttpClient: [[path, body], ...]. */
    private function posted(callable $call, array $answer = ['secret' => 'S']): array
    {
        $sent = [];
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturnCallback(function (string $path, array $body) use (&$sent, $answer): array {
            $sent[] = [$path, $body];
            return $answer;
        });
        $call(new Auth($http));
        return $sent;
    }

    // ── the request for the QR ───────────────────────────────────────────

    public function testGenerateAndResetSendTheBrowsersIpAndUserAgent(): void
    {
        $sent = $this->posted(function (Auth $auth): void {
            $auth->generateSecret('a@b.com', self::IP, self::IPHONE_SAFARI);
            $auth->resetSecret('a@b.com', self::IP, self::IPHONE_SAFARI);
        });
        $body = ['externalUsername' => 'a@b.com', 'clientIp' => self::IP, 'userAgent' => self::IPHONE_SAFARI];
        $this->assertSame([['/auth/generate-secret', $body], ['/auth/secret/reset', $body]], $sent);
    }

    public function testANullOrEmptyIpOrUserAgentIsLeftOut(): void
    {
        $alone = ['externalUsername' => 'a@b.com'];
        foreach ([[null, null], ['', ''], [null, ''], ['', null]] as [$ip, $ua]) {
            $sent = $this->posted(function (Auth $auth) use ($ip, $ua): void {
                $auth->generateSecret('a@b.com', $ip, $ua);
                $auth->resetSecret('a@b.com', $ip, $ua);
            });
            $this->assertSame([['/auth/generate-secret', $alone], ['/auth/secret/reset', $alone]], $sent, json_encode([$ip, $ua]));
        }
        // Without the new arguments the body is the one sent before.
        $this->assertSame([['/auth/generate-secret', $alone]], $this->posted(fn (Auth $auth) => $auth->generateSecret('a@b.com')));
        $this->assertSame([['/auth/secret/reset', $alone]], $this->posted(fn (Auth $auth) => $auth->resetSecret('a@b.com')));
        // One of the two.
        $this->assertSame($alone + ['clientIp' => self::IP], $this->posted(fn (Auth $auth) => $auth->generateSecret('a@b.com', self::IP, ''))[0][1]);
        $this->assertSame($alone + ['userAgent' => 'UA'], $this->posted(fn (Auth $auth) => $auth->resetSecret('a@b.com', null, 'UA'))[0][1]);
    }

    /**
     * A given IP and User-Agent go out as login->request() sends them: not trimmed, not
     * checked to be an address, no length limit (Touchque decides what it keeps).
     *
     * @dataProvider browserValues
     */
    public function testTheIpAndUserAgentGoOutAsTheLoginRequestSendsThem(?string $ip, ?string $ua): void
    {
        $sent = $this->posted(function (Auth $auth) use ($ip, $ua): void {
            $auth->generateSecret('a@b.com', $ip, $ua);
            $auth->resetSecret('a@b.com', $ip, $ua);
        });
        $login = null;
        $http = $this->createMock(HttpClient::class);
        $http->method('post')->willReturnCallback(function (string $path, array $body) use (&$login): array {
            $login = $body;
            return ['requestId' => 'r'];
        });
        (new Login($http))->request('a@b.com', 'LOGIN', null, $ip, $ua);

        $browser = fn (array $body): array => array_intersect_key($body, ['clientIp' => true, 'userAgent' => true]);
        $given = array_filter(['clientIp' => $ip, 'userAgent' => $ua], fn ($v) => $v !== null);
        $this->assertSame($given, $browser($login));
        $this->assertSame($given, $browser($sent[0][1]));
        $this->assertSame($given, $browser($sent[1][1]));
    }

    public function browserValues(): array
    {
        return [
            'both' => [self::IP, self::IPHONE_SAFARI],
            'padded' => ['  203.0.113.7 ', " Mozilla/5.0 (X11; Linux x86_64)\t"],
            'not an address' => ['unknown', 'curl/8.7.1'],
            'IPv6 with a port' => ['[2001:db8::1]:443', 'Mozilla/5.0'],
            'long' => [self::OTHER_IP, str_repeat('Mozilla/5.0 (Windows NT 10.0; Win64; x64) ', 50)],
            'only the IP' => [self::IP, null],
            'only the User-Agent' => [null, self::IPHONE_SAFARI],
            'neither' => [null, null],
        ];
    }

    // ── setupContext on the validate answer ──────────────────────────────

    public function testTheFixtureHasTheSharedCases(): void
    {
        foreach (['full', 'allNull', 'missing', 'null', 'wrongTypes', 'extraFields'] as $case) {
            $this->assertArrayHasKey($case, self::fixture());
            $this->assertArrayHasKey($case, self::fixture()['expected']);
        }
    }

    /**
     * Every case of fixtures/setup-context.json, read by parseSetupContext() and by
     * validateSecret(), which always answers the key and leaves the rest as sent.
     *
     * @dataProvider fixtureCases
     */
    public function testTheSharedFixtureReadsAsExpected(string $case): void
    {
        $answer = self::fixture()[$case];
        $expected = self::fixture()['expected'][$case];
        $this->assertSame($expected, Auth::parseSetupContext($answer['setupContext'] ?? null));

        $res = null;
        $sent = $this->posted(function (Auth $auth) use (&$res): void {
            $res = $auth->validateSecret('S');
        }, $answer);
        $this->assertSame([['/auth/secret/validate', ['secret' => 'S']]], $sent);
        $this->assertArrayHasKey('setupContext', $res);
        $this->assertSame($expected, $res['setupContext']);
        unset($res['setupContext'], $answer['setupContext']);
        $this->assertSame($answer, $res);
    }

    public function fixtureCases(): array
    {
        $cases = array_keys(array_diff_key(self::fixture(), ['expected' => true]));
        return array_combine($cases, array_map(fn (string $c): array => [$c], $cases));
    }

    public function testAnythingButAnObjectIsNoSetupContext(): void
    {
        foreach ([null, 'Berlin', '', 203, 1.5, true, false, [self::IP, 'Berlin'], [['ip' => self::IP]]] as $raw) {
            $this->assertNull(Auth::parseSetupContext($raw), json_encode($raw));
        }
        $res = null;
        $this->posted(function (Auth $auth) use (&$res): void {
            $res = $auth->validateSecret('S');
        }, ['valid' => true, 'setupContext' => 'Berlin, Germany']);
        $this->assertSame(['valid' => true, 'setupContext' => null], $res);
    }

    public function testAnEmptyObjectIsASetupContextWithNothingKnown(): void
    {
        $nothing = ['ip' => null, 'location' => null, 'device' => null, 'requestedAt' => null, 'farFromPhone' => null];
        // json_decode() gives {} and [] alike: an empty array is an object here.
        $this->assertSame($nothing, Auth::parseSetupContext(json_decode('{}', true)));
        $this->assertSame($nothing, Auth::parseSetupContext(['asn' => 7922, 'warnings' => ['new_country']]));
        $this->assertSame(
            ['ip' => null, 'location' => ['city' => null, 'country' => null, 'countryCode' => null],
                'device' => ['browser' => null, 'os' => null, 'model' => null], 'requestedAt' => null, 'farFromPhone' => null],
            Auth::parseSetupContext(json_decode('{"location": {}, "device": {}}', true))
        );
    }

    public function testEachFieldOfTheWrongTypeIsNullAndNothingThrows(): void
    {
        $raw = json_decode('{"ip": ["203.0.113.7"], "location": ["Berlin", "Germany"], "device": "Safari on iOS",
            "requestedAt": 1763285400000, "farFromPhone": 1}', true);
        $this->assertSame(['ip' => null, 'location' => null, 'device' => null, 'requestedAt' => null, 'farFromPhone' => null], Auth::parseSetupContext($raw));

        $raw = json_decode('{"ip": "203.0.113.7", "location": {"city": 7, "country": {"name": "Germany"}, "countryCode": ["DE"]},
            "device": {"browser": null, "os": 1.5, "model": true}, "requestedAt": "2026-11-16T10:30:00+01:00", "farFromPhone": false}', true);
        $this->assertSame([
            'ip' => self::IP,
            'location' => ['city' => null, 'country' => null, 'countryCode' => null],
            'device' => ['browser' => null, 'os' => null, 'model' => null],
            // Not parsed into a date: the string as Touchque sent it.
            'requestedAt' => '2026-11-16T10:30:00+01:00',
            'farFromPhone' => false,
        ], Auth::parseSetupContext($raw));

        foreach (['true', 0, 'false', []] as $notABool) {
            $this->assertNull(Auth::parseSetupContext(['farFromPhone' => $notABool])['farFromPhone'], json_encode($notABool));
        }
    }

    // ── the adapters send what they send with the push ───────────────────

    /**
     * A client with no phone linked to anyone: every login request answers 404
     * device_not_linked, the first secret of a user is a QR and the next one 409 (not
     * scanned yet), so a reset follows. $seen gets [what, user, ip, userAgent] for each
     * login request, new secret and reset. $ttlMs is how long a QR lives.
     */
    private function unlinkedClient(array &$seen, int $ttlMs = 300000): Touchque
    {
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        $qr = static function (string $secret) use ($ttlMs): array {
            return ['secret' => $secret, 'qrCodeDataUrl' => 'data:image/png;base64,' . $secret, 'recoveryCodes' => ['r'],
                'expiresAt' => Steps::isoOf((int)(microtime(true) * 1000) + $ttlMs)];
        };
        $tq->login = $this->createMock(Login::class);
        $tq->login->method('request')->willReturnCallback(function (string $user, string $type, ?string $referenceId, ?string $ip, ?string $ua) use (&$seen): array {
            $seen[] = ['login', $user, $ip, $ua];
            throw new TouchqueAPIException('No linked device found for this user', 404, ['code' => 'device_not_linked']);
        });
        $pending = [];
        $tq->auth = $this->createMock(Auth::class);
        $tq->auth->method('generateSecret')->willReturnCallback(function (string $user, ?string $ip, ?string $ua) use (&$seen, &$pending, $qr): array {
            $seen[] = ['generate', $user, $ip, $ua];
            if (isset($pending[$user])) {
                throw new TouchqueAPIException('Secret already generated', 409, ['error' => 'Secret already generated']);
            }
            $pending[$user] = true;
            return $qr('S');
        });
        $tq->auth->method('resetSecret')->willReturnCallback(function (string $user, ?string $ip, ?string $ua) use (&$seen, $qr): array {
            $seen[] = ['reset', $user, $ip, $ua];
            return $qr('S2');
        });
        $tq->auth->method('getUser')->willReturn(['used' => false, 'deviceId' => null]);
        return $tq;
    }

    public function testTheGuardSendsTheQrRequestTheBrowserItSendsWithThePush(): void
    {
        $seen = [];
        $tq = $this->unlinkedClient($seen);
        $first = Guard::run($tq, 'jane@acme.com', 'LOGIN', null, null, self::IP, self::IPHONE_SAFARI);
        $this->assertSame('enroll', $first['body']['touchque']['state']);
        $this->assertSame([
            ['login', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
            ['generate', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
        ], $seen);

        // A new attempt while the QR is not scanned yet: 409, then the reset, from this request's browser.
        $seen = [];
        Guard::run($tq, 'jane@acme.com', 'LOGIN', null, null, self::OTHER_IP, self::WINDOWS_FIREFOX);
        $this->assertSame([
            ['login', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
            ['generate', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
            ['reset', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
        ], $seen);
    }

    public function testANewQrNearTheOldOnesExpiryCarriesThePollsBrowser(): void
    {
        $seen = [];
        $tq = $this->unlinkedClient($seen, 10000); // inside the 15 s the guard keeps in hand
        $first = Guard::run($tq, 'jane@acme.com', 'LOGIN', null, null, self::IP, self::IPHONE_SAFARI);
        $seen = [];
        $poll = Guard::run($tq, 'jane@acme.com', 'LOGIN', null, null, self::OTHER_IP, self::WINDOWS_FIREFOX, $first['body']['token']);
        $this->assertSame('data:image/png;base64,S2', $poll['body']['touchque']['enroll']['qrCodeDataUrl']);
        $this->assertSame([
            ['login', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
            ['generate', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
            ['reset', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
        ], $seen);
    }

    public function testWithoutAnIpOrUserAgentNoneIsSentAsForThePush(): void
    {
        $seen = [];
        Guard::run($this->unlinkedClient($seen), 'jane@acme.com', 'LOGIN');
        $this->assertSame([['login', 'jane@acme.com', null, null], ['generate', 'jane@acme.com', null, null]], $seen);
    }

    public function testStartSendsThemWithTheQrRequest(): void
    {
        $seen = [];
        $step = $this->unlinkedClient($seen)->start('LOGIN', 'jane@acme.com', null, null, self::IP, self::IPHONE_SAFARI);
        $this->assertSame('enroll', $step['state']);
        $this->assertSame([
            ['login', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
            ['generate', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
        ], $seen);
    }

    public function testTheRelaysEnrollStartAndItsResetSendTheBrowser(): void
    {
        $seen = [];
        $relay = new RelayHandler($this->unlinkedClient($seen), ['getUserId' => fn () => 'jane@acme.com', 'getLoginUser' => fn () => 'jane@acme.com']);
        $first = $relay->handle('POST', '/enroll/start', [], self::IP, self::IPHONE_SAFARI, fn () => null);
        $this->assertSame('S', $first->getBody()['secret']);
        // Not scanned yet: the relay asks for a new QR (409, then a reset), from this request's browser.
        $again = $relay->handle('POST', '/enroll/start', [], self::OTHER_IP, self::WINDOWS_FIREFOX, fn () => null);
        $this->assertSame('S2', $again->getBody()['secret']);
        $this->assertSame([
            ['generate', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
            ['generate', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
            ['reset', 'jane@acme.com', self::OTHER_IP, self::WINDOWS_FIREFOX],
        ], $seen);
    }

    public function testTheRelaysLoginSendsTheQrRequestWhatItSendsWithThePush(): void
    {
        $seen = [];
        $relay = new RelayHandler($this->unlinkedClient($seen), ['getUserId' => fn () => null, 'getLoginUser' => fn () => 'Jane@Acme.com', 'rateLimit' => false]);
        $res = $relay->handle('POST', '/login', [], self::IP, self::IPHONE_SAFARI, fn () => null);
        $this->assertSame('enroll', $res->getBody()['touchque']['state']);
        $this->assertSame([
            ['login', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
            ['generate', 'jane@acme.com', self::IP, self::IPHONE_SAFARI],
        ], $seen);
    }

    public function testARelayWithoutAnIpOrUserAgentSendsNoneAsForLogin(): void
    {
        $seen = [];
        $relay = new RelayHandler($this->unlinkedClient($seen), ['getUserId' => fn () => 'jane@acme.com', 'getLoginUser' => fn () => 'jane@acme.com', 'rateLimit' => false]);
        $relay->handle('POST', '/login', [], '', null, fn () => null);
        $relay->handle('POST', '/enroll/start', [], '', null, fn () => null);
        $this->assertSame([
            ['login', 'jane@acme.com', null, null],
            ['generate', 'jane@acme.com', null, null],
            ['generate', 'jane@acme.com', null, null],
            ['reset', 'jane@acme.com', null, null],
        ], $seen);
    }

    /** A Laravel request from $peer, with X-Forwarded-For when given, from an iPhone. */
    private static function laravelRequest(string $uri, string $peer, ?string $forwardedFor = null): Request
    {
        $server = ['REMOTE_ADDR' => $peer, 'HTTP_USER_AGENT' => self::IPHONE_SAFARI, 'CONTENT_TYPE' => 'application/json'];
        if ($forwardedFor !== null) {
            $server['HTTP_X_FORWARDED_FOR'] = $forwardedFor;
        }
        return Request::create($uri, 'POST', [], [], [], $server, '{}');
    }

    /**
     * Laravel's $request->ip() decides, as it does for the push: a peer that is not one
     * of your trusted proxies is the client (its X-Forwarded-For is ignored); behind them,
     * the nearest address that is not one of them, never the leftmost a browser can write.
     *
     * @dataProvider proxyCases
     */
    public function testLaravelSendsTheQrRequestTheIpItSendsWithThePush(array $trusted, string $peer, ?string $forwardedFor, string $client): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        Request::setTrustedProxies($trusted, $trusted === [] ? -1 : Request::HEADER_X_FORWARDED_FOR);
        try {
            // TouchqueMiddleware: one request, the push (no phone: 404), then the QR.
            $seen = [];
            $middleware = new class ($this->unlinkedClient($seen)) extends TouchqueMiddleware {
                protected function resolveUser(Request $request): ?string
                {
                    return 'jane@acme.com';
                }
            };
            $res = $middleware->handle(self::laravelRequest('/transfer', $peer, $forwardedFor), fn () => new JsonResponse([]), 'LOGIN');
            $this->assertSame(202, $res->getStatusCode());
            $this->assertSame([
                ['login', 'jane@acme.com', $client, self::IPHONE_SAFARI],
                ['generate', 'jane@acme.com', $client, self::IPHONE_SAFARI],
            ], $seen);

            // TouchqueRelay: POST /login behind the password step, then POST /enroll/start (409, reset).
            $seen = [];
            $relay = new TouchqueRelay($this->unlinkedClient($seen), [
                'getUserId' => fn () => 'jo@acme.com', 'getLoginUser' => fn () => 'jo@acme.com', 'rateLimit' => false,
            ]);
            $this->assertSame(202, $relay->login(self::laravelRequest('/touchque/login', $peer, $forwardedFor))->getStatusCode());
            $this->assertSame(200, $relay->enrollStart(self::laravelRequest('/touchque/enroll/start', $peer, $forwardedFor))->getStatusCode());
            $this->assertSame([
                ['login', 'jo@acme.com', $client, self::IPHONE_SAFARI],
                ['generate', 'jo@acme.com', $client, self::IPHONE_SAFARI],
                ['generate', 'jo@acme.com', $client, self::IPHONE_SAFARI],
                ['reset', 'jo@acme.com', $client, self::IPHONE_SAFARI],
            ], $seen);
        } finally {
            Request::setTrustedProxies([], -1);
        }
    }

    public function proxyCases(): array
    {
        return [
            'no proxy' => [[], self::IP, null, self::IP],
            'X-Forwarded-For from a peer you do not trust' => [[], self::IP, self::OTHER_IP, self::IP],
            'behind your proxy' => [['10.0.0.1'], '10.0.0.1', self::OTHER_IP . ', ' . self::IP, self::IP],
            'behind two of your proxies' => [['10.0.0.0/8'], '10.0.0.1', self::OTHER_IP . ', ' . self::IP . ', 10.0.0.2', self::IP],
            'your proxy sent no X-Forwarded-For' => [['10.0.0.1'], '10.0.0.1', null, '10.0.0.1'],
        ];
    }

    // ── round trips through the shared fake API ──────────────────────────

    private function realClient(): Touchque
    {
        if (self::$api === null) {
            $this->markTestSkipped('node is required for contract tests');
        }
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    /** The bodies the fake API got on $path for $user. */
    private static function bodies(string $path, string $user): array
    {
        $out = [];
        foreach (self::$api->calls() as $c) {
            if ($c['path'] === $path && ($c['body']['externalUsername'] ?? null) === $user) {
                $out[] = $c['body'];
            }
        }
        return $out;
    }

    public function testThePhoneSeesWhereTheQrWasAskedFor(): void
    {
        $tq = $this->realClient();
        $user = self::user('ctx');
        $before = (int)(microtime(true) * 1000);
        $this->assertSame('S', $tq->auth->generateSecret($user, self::IP, self::IPHONE_SAFARI)['secret']);
        $this->assertSame([['externalUsername' => $user, 'clientIp' => self::IP, 'userAgent' => self::IPHONE_SAFARI]], self::bodies('/auth/generate-secret', $user));

        $v = $tq->auth->validateSecret('S');
        $this->assertTrue($v['valid']);
        $this->assertSame($user, $v['externalUsername']);
        $this->assertSame('Fake workspace', $v['integration']['companyName']);
        $requestedAt = Steps::isoMs($v['setupContext']['requestedAt']);
        $this->assertNotNull($requestedAt, 'requestedAt is the ISO 8601 string as sent');
        $this->assertGreaterThanOrEqual($before - 1000, $requestedAt);
        $this->assertSame([
            'ip' => self::IP,
            'location' => ['city' => 'Berlin', 'country' => 'Germany', 'countryCode' => 'DE'],
            'device' => ['browser' => 'Safari', 'os' => 'iOS', 'model' => 'iPhone'],
            'requestedAt' => $v['setupContext']['requestedAt'],
            'farFromPhone' => null,
        ], $v['setupContext']);
    }

    public function testAResetSendsItsOwnRequest(): void
    {
        $tq = $this->realClient();
        $user = self::user('ctx-reset');
        $tq->auth->generateSecret($user, self::IP, self::IPHONE_SAFARI);
        $this->assertSame('S2', $tq->auth->resetSecret($user, self::OTHER_IP, self::WINDOWS_FIREFOX)['secret']);
        $this->assertSame([['externalUsername' => $user, 'clientIp' => self::OTHER_IP, 'userAgent' => self::WINDOWS_FIREFOX]], self::bodies('/auth/secret/reset', $user));
        $context = $tq->auth->validateSecret('S2')['setupContext'];
        $this->assertSame(
            [self::OTHER_IP, ['city' => 'New York', 'country' => 'United States', 'countryCode' => 'US'], ['browser' => 'Firefox', 'os' => 'Windows', 'model' => null]],
            [$context['ip'], $context['location'], $context['device']]
        );
    }

    /** A reset records its own request: one without the browser leaves the new QR with none. */
    public function testAResetWithoutTheBrowserLeavesTheNewQrWithNone(): void
    {
        $tq = $this->realClient();
        $user = self::user('ctx-reset-none');
        $tq->auth->generateSecret($user, self::IP, self::IPHONE_SAFARI);
        $this->assertSame('S2', $tq->auth->resetSecret($user)['secret']);
        $this->assertSame([['externalUsername' => $user]], self::bodies('/auth/secret/reset', $user));
        $v = $tq->auth->validateSecret('S2');
        $this->assertTrue($v['valid']);
        $this->assertNull($v['setupContext']);
    }

    public function testWithoutTheBrowserThereIsNoSetupContext(): void
    {
        $tq = $this->realClient();
        $user = self::user('ctx-none');
        $tq->auth->generateSecret($user);
        $this->assertSame([['externalUsername' => $user]], self::bodies('/auth/generate-secret', $user));
        $v = $tq->auth->validateSecret('S');
        $this->assertArrayHasKey('setupContext', $v);
        $this->assertNull($v['setupContext']);
    }

    public function testAServerAnsweringNoSetupContext(): void
    {
        $tq = $this->realClient();
        self::$api->opts(['setupContextNull' => true]);
        try {
            $tq->auth->generateSecret(self::user('ctx-null'), self::IP, self::IPHONE_SAFARI);
            $v = $tq->auth->validateSecret('S');
            $this->assertTrue($v['valid']);
            $this->assertNull($v['setupContext']);
        } finally {
            self::$api->opts(['setupContextNull' => false]);
        }
    }

    public function testTheGuardsQrAndItsRenewalEachShowTheirBrowser(): void
    {
        $tq = $this->realClient();
        $user = self::user('ctx-guard');
        self::$api->opts(['secretTtlMs' => 10000]); // inside the guard's 15 s margin: the next poll renews the QR
        try {
            $first = Guard::run($tq, $user, 'LOGIN', null, null, self::IP, self::IPHONE_SAFARI);
            $this->assertSame('enroll', $first['body']['touchque']['state']);
            $context = $tq->auth->validateSecret('S')['setupContext'];
            $this->assertSame([self::IP, 'Berlin', 'Safari'], [$context['ip'], $context['location']['city'], $context['device']['browser']]);

            $poll = Guard::run($tq, $user, 'LOGIN', null, null, self::OTHER_IP, self::WINDOWS_FIREFOX, $first['body']['token']);
            $this->assertSame('data:image/png;base64,QR2-' . $user, $poll['body']['touchque']['enroll']['qrCodeDataUrl']);
            $context = $tq->auth->validateSecret('S2')['setupContext'];
            $this->assertSame([self::OTHER_IP, 'New York', 'Firefox'], [$context['ip'], $context['location']['city'], $context['device']['browser']]);
        } finally {
            self::$api->opts(['secretTtlMs' => null]);
        }
    }

    public function testTheRelaysEnrollStartShowsTheBrowserOnThePhone(): void
    {
        $tq = $this->realClient();
        $user = self::user('ctx-relay');
        $relay = new RelayHandler($tq, ['getUserId' => fn () => $user, 'getLoginUser' => fn () => $user]);
        $this->assertSame(200, $relay->handle('POST', '/enroll/start', [], self::IP, self::IPHONE_SAFARI, fn () => null)->getStatus());
        $this->assertSame(
            ['ip' => self::IP, 'location' => ['city' => 'Berlin', 'country' => 'Germany', 'countryCode' => 'DE'], 'device' => ['browser' => 'Safari', 'os' => 'iOS', 'model' => 'iPhone']],
            array_intersect_key($tq->auth->validateSecret('S')['setupContext'], ['ip' => true, 'location' => true, 'device' => true])
        );
    }

    public function testLaravelBehindYourProxyShowsTheClientsPlaceNotAWrittenOne(): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        $tq = $this->realClient();
        $user = self::user('ctx-laravel');
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR);
        try {
            $middleware = new class ($tq) extends TouchqueMiddleware {
                protected function resolveUser(Request $request): ?string
                {
                    return $request->header('X-User');
                }
            };
            // The browser wrote a New York address first; your proxy added the one it saw.
            $request = self::laravelRequest('/transfer', '10.0.0.1', self::OTHER_IP . ', ' . self::IP);
            $request->headers->set('X-User', $user);
            $res = $middleware->handle($request, fn () => new JsonResponse([]), 'LOGIN');
            $this->assertSame('enroll', json_decode((string)$res->getContent(), true)['touchque']['state']);
            $context = $tq->auth->validateSecret('S')['setupContext'];
            $this->assertSame([self::IP, 'Berlin', 'iOS'], [$context['ip'], $context['location']['city'], $context['device']['os']]);
        } finally {
            Request::setTrustedProxies([], -1);
        }
    }
}
