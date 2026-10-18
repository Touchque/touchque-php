<?php

namespace TouchQue\Tests;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueNetworkException;
use TouchQue\Guard;
use TouchQue\Http\HttpClient;
use TouchQue\Laravel\TouchQueMiddleware;
use TouchQue\Relay\RelayHandler;
use TouchQue\Relay\RelayResponse;
use TouchQue\Resources\Risk;
use TouchQue\TouchQue;

/**
 * Silent sign-ins against the shared fake TouchQue API (a real, signed HTTP
 * round trip): the risk resource, the proof on login requests, and the
 * guard / Laravel middleware / relay `silentSignIn` option. Same scenarios as
 * the Node SDK's silentSignIn tests.
 */
class SilentSignInTest extends TestCase
{
    private const USER = 'jane@acme.com';
    private const SILENT_CODES = ['known_browser', 'recent_approval', 'same_phone', 'familiar_network', 'no_risk_signal'];

    private static ?FakeApi $api = null;
    /** The proof as the browser sends it in X-TouchQue-Browser (base64url JSON). */
    private static string $proof;
    /** RFC 7638 thumbprint of that proof's key. */
    private static string $thumbprint;

    public static function setUpBeforeClass(): void
    {
        $vectors = json_decode((string)file_get_contents(__DIR__ . '/../fixtures/silent-sign-in-vectors.json'), true);
        foreach ($vectors['browserProof']['cases'] as $case) {
            if ($case['name'] === 'validHeaderEncoding') {
                self::$proof = $case['proof'];
            }
        }
        self::$thumbprint = $vectors['browserProof']['thumbprint']['expected'];
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
        self::$api->reset();
        self::$api->link(self::USER);
    }

    private function client(): TouchQue
    {
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    private function paths(): array
    {
        return array_column(self::$api->calls(), 'path');
    }

    /** Bodies of the POST /login/request calls, in order. */
    private function loginRequests(): array
    {
        return array_values(array_map(static function (array $c): array {
            return $c['body'];
        }, array_filter(self::$api->calls(), static function (array $c): bool {
            return $c['path'] === '/login/request';
        })));
    }

    /** Guard::run for a new attempt with the given proof and option. */
    private function guard(TouchQue $tq, ?string $proof, $silentSignIn = true, string $action = 'LOGIN', ?string $token = null): array
    {
        return Guard::run($tq, self::USER, $action, null, null, '203.0.113.7', 'UA', $token, false, null, null, true, $proof, $silentSignIn);
    }

    // ── risk resource ───────────────────────────────────────────────────

    public function testABrowserWithoutAKeyThenANewBrowserAreAskedAndNothingGoesToThePhone(): void
    {
        $tq = $this->client();
        $none = $tq->risk->check(['externalUsername' => self::USER]);
        $this->assertTrue($none['prompt']);
        $this->assertSame('normal', $none['assurance']);
        $this->assertSame('enforce', $none['silentMode']);
        $this->assertSame(['no_browser_key'], array_column($none['reasons'], 'code'));

        $res = $tq->risk->check([
            'externalUsername' => self::USER, 'type' => 'LOGIN', 'clientIp' => '203.0.113.7', 'userAgent' => 'UA',
            'browserProof' => self::$proof, 'maxAgeSeconds' => 3600,
        ]);
        $this->assertTrue($res['prompt']);
        $this->assertSame([['code' => 'new_browser', 'text' => 'This browser has not been approved on the phone for this account']], $res['reasons']);
        $this->assertSame([
            'externalUsername' => self::USER, 'type' => 'LOGIN', 'clientIp' => '203.0.113.7', 'userAgent' => 'UA',
            'browserProof' => self::$proof, 'maxAgeSeconds' => 3600,
        ], self::$api->lastCheck());
        $this->assertSame(['/risk/check', '/risk/check'], $this->paths());
    }

    public function testSilentAnswerButACriticalActionAndAnUnlinkedUserStillAsk(): void
    {
        self::$api->opts(['silent' => true]);
        $tq = $this->client();
        $res = $tq->risk->check(['externalUsername' => self::USER, 'browserProof' => self::$proof]);
        $this->assertFalse($res['prompt']);
        $this->assertSame('high', $res['assurance']);
        $this->assertSame(self::SILENT_CODES, array_column($res['reasons'], 'code'));

        $critical = $tq->risk->check(['externalUsername' => self::USER, 'type' => 'SEND_MONEY', 'browserProof' => self::$proof]);
        $this->assertTrue($critical['prompt']);
        $this->assertSame([['code' => 'critical_action', 'text' => 'The action is critical']], $critical['reasons']);

        $unlinked = $tq->risk->check(['externalUsername' => 'nobody@acme.com', 'browserProof' => self::$proof]);
        $this->assertTrue($unlinked['prompt']);
        $this->assertSame(['phone_not_linked'], array_column($unlinked['reasons'], 'code'));
    }

    public function testLoginRequestCarriesTheProofAndTheApprovalMakesTheBrowserKnownUntilForgotten(): void
    {
        $tq = $this->client();
        $first = $tq->login->request(self::USER, 'LOGIN', null, null, null, false, false, null, self::$proof);
        $this->assertSame(self::$proof, $this->loginRequests()[0]['browserProof']);
        $this->assertSame(['browsers' => []], $tq->risk->browsers(['externalUsername' => self::USER]));

        self::$api->approve($first['requestId']);
        $browsers = $tq->risk->browsers(['externalUsername' => self::USER])['browsers'];
        $this->assertCount(1, $browsers);
        $this->assertSame(self::$thumbprint, $browsers[0]['thumbprint']);
        $this->assertSame('push', $browsers[0]['lastMfaMethod']);
        $this->assertNull($browsers[0]['lastSilentAt']);
        $this->assertSame('/risk/browsers?externalUsername=jane%40acme.com', self::$api->calls()[2]['url']);

        $this->assertSame(['forgotten' => 0], $tq->risk->forgetBrowsers(['externalUsername' => self::USER, 'thumbprint' => 'other']));
        $this->assertSame(['forgotten' => 1], $tq->risk->forgetBrowsers(['externalUsername' => self::USER, 'thumbprint' => self::$thumbprint]));
        $this->assertSame([], $tq->risk->browsers(['externalUsername' => self::USER])['browsers']);

        // Without a thumbprint: every browser of the user.
        $again = $tq->login->request(self::USER, 'LOGIN', null, null, null, false, false, null, self::$proof);
        self::$api->approve($again['requestId']);
        $this->assertSame(['forgotten' => 1], $tq->risk->forgetBrowsers(['externalUsername' => self::USER]));
        $forgetAll = array_values(array_filter(self::$api->calls(), static function (array $c): bool {
            return $c['path'] === '/risk/browsers/forget';
        }));
        $this->assertSame(['externalUsername' => self::USER], end($forgetAll)['body']);
    }

    public function testAProvisionalApprovalDuringACallDoesNotMakeTheBrowserKnown(): void
    {
        $tq = $this->client();
        $tq->login->request(self::USER, 'LOGIN', null, null, null, false, false, null, self::$proof);
        self::$api->approve(null, 'DEVICE', true);
        $this->assertSame([], $tq->risk->browsers(['externalUsername' => self::USER])['browsers']);
    }

    public function testStartPassesTheProofThrough(): void
    {
        $tq = $this->client();
        $this->assertSame('waiting', $tq->start('LOGIN', self::USER, null, null, null, null, self::$proof)['state']);
        $this->assertSame(self::$proof, $this->loginRequests()[0]['browserProof']);
        $tq->start('LOGIN', self::USER);
        $this->assertArrayNotHasKey('browserProof', $this->loginRequests()[1]);
    }

    // ── guard: silentSignIn ─────────────────────────────────────────────

    public function testAKnownBrowserWithNothingNewIsApprovedAtOnceWithNoPush(): void
    {
        self::$api->opts(['silent' => true]);
        $res = $this->guard($this->client(), self::$proof);
        $this->assertSame(200, $res['status']);
        $approved = $res['approved'];
        $this->assertSame('silent', $approved['requestId']);
        $this->assertSame(self::USER, $approved['user']);
        $this->assertSame('LOGIN', $approved['action']);
        $this->assertSame('SILENT', $approved['confirmedVia']);
        $this->assertSame(['phishingResistant' => false, 'method' => 'silent'], $approved['assurance']);
        $this->assertNull($approved['approvalProof']);
        $this->assertSame(self::SILENT_CODES, array_column($approved['reasons'], 'code'));
        $this->assertSame([
            'externalUsername' => self::USER, 'type' => 'LOGIN', 'clientIp' => '203.0.113.7', 'userAgent' => 'UA', 'browserProof' => self::$proof,
        ], self::$api->lastCheck());
        $this->assertSame(['/risk/check'], $this->paths());
    }

    public function testOtherwiseThePushStartsWithTheProofAndPollsNeverAskAgain(): void
    {
        $tq = $this->client();
        $first = $this->guard($tq, self::$proof);
        $this->assertSame(202, $first['status']);
        $this->assertSame('waiting', $first['body']['touchque']['state']);
        $this->assertSame(['/risk/check', '/login/request'], $this->paths());
        $this->assertSame(self::$proof, $this->loginRequests()[0]['browserProof']);

        // Polling with the token never asks again, even if the answer would now be silent.
        self::$api->opts(['silent' => true]);
        $poll = $this->guard($tq, self::$proof, true, 'LOGIN', $first['body']['token']);
        $this->assertSame('waiting', $poll['body']['touchque']['state']);
        $this->assertCount(1, array_keys($this->paths(), '/risk/check', true));

        self::$api->approve();
        $done = $this->guard($tq, self::$proof, true, 'LOGIN', $first['body']['token']);
        $this->assertSame(200, $done['status']);
        $this->assertSame('DEVICE', $done['approved']['confirmedVia']);
        $this->assertSame('push', $done['approved']['assurance']['method']);
        $this->assertArrayNotHasKey('reasons', $done['approved']);
        $this->assertSame([self::$thumbprint], array_column($tq->risk->browsers(['externalUsername' => self::USER])['browsers'], 'thumbprint'));
    }

    public function testACriticalActionAlwaysAsksWithNumberMatching(): void
    {
        self::$api->opts(['silent' => true]);
        $res = $this->guard($this->client(), self::$proof, true, 'SEND_MONEY');
        $this->assertSame(202, $res['status']);
        $this->assertSame('waiting', $res['body']['touchque']['state']);
        $this->assertSame('47', $res['body']['touchque']['number']);
        $this->assertSame('SEND_MONEY', self::$api->lastCheck()['type']);
    }

    public function testFailsClosedAnyErrorOrAnythingButPromptFalseStartsThePush(): void
    {
        self::$api->opts(['silent' => true]); // the real answer would be silent
        $answers = [
            new TouchQueNetworkException('network down'),
            new TouchQueAPIException('not found', 404, ['error' => 'no route']),
            new TouchQueAPIException('server error', 500, ['error' => 'boom']),
            ['prompt' => 'false', 'reasons' => [], 'assurance' => 'high'],
            ['prompt' => 0, 'reasons' => []],
            ['prompt' => null],
            [],
        ];
        $prev = ini_set('error_log', '/dev/null');
        try {
            foreach ($answers as $i => $answer) {
                $tq = $this->client();
                $http = $this->createMock(HttpClient::class);
                $mocked = $http->expects($this->once())->method('post')->with('/risk/check');
                $answer instanceof \Throwable ? $mocked->willThrowException($answer) : $mocked->willReturn($answer);
                $tq->risk = new Risk($http);
                $res = $this->guard($tq, self::$proof);
                $this->assertSame(202, $res['status'], "answer $i");
                $this->assertSame('waiting', $res['body']['touchque']['state'], "answer $i");
            }
        } finally {
            ini_set('error_log', (string)$prev);
        }
        $this->assertCount(count($answers), $this->loginRequests());
    }

    public function testOffByDefaultWithoutAProofOrWithAProofTooLargeToBeOneNoCheck(): void
    {
        self::$api->opts(['silent' => true]);
        $tq = $this->client();
        $off = Guard::run($tq, self::USER, 'LOGIN', null, null, null, null, null, false, null, null, true, self::$proof);
        $this->assertSame(202, $off['status']);
        $this->assertSame(self::$proof, $this->loginRequests()[0]['browserProof']); // still attached: an approval makes the browser known
        $this->assertSame(202, $this->guard($tq, null)['status']);
        $this->assertSame(202, $this->guard($tq, '')['status']);
        $this->assertSame(202, $this->guard($tq, str_repeat('x', 5000))['status']);
        $this->assertArrayNotHasKey('browserProof', $this->loginRequests()[3]);
        $this->assertNotContains('/risk/check', $this->paths());
    }

    public function testMaxAgeSecondsIsSentWithTheCheck(): void
    {
        $this->guard($this->client(), self::$proof, ['maxAgeSeconds' => 0]);
        $this->assertSame(0, self::$api->lastCheck()['maxAgeSeconds']);
        $this->guard($this->client(), self::$proof, []);
        $this->assertArrayNotHasKey('maxAgeSeconds', self::$api->lastCheck());
    }

    public function testTheAdapterOptionIsValidated(): void
    {
        $tq = $this->client();
        foreach (['yes', 1, ['maxAgeSeconds' => -1], ['maxAgeSeconds' => '60'], ['max_age_seconds' => 60]] as $bad) {
            try {
                new RelayHandler($tq, ['getUserId' => fn () => null, 'silentSignIn' => $bad]);
                $this->fail('expected InvalidArgumentException for ' . json_encode($bad));
            } catch (\InvalidArgumentException $e) {
                $this->assertStringContainsString('silentSignIn', $e->getMessage());
            }
        }
        $this->assertSame(['silentSignIn' => false, 'browserProof' => null], Guard::silentInputFromHeaders(false, fn () => self::$proof));
        $this->assertSame(['silentSignIn' => true, 'browserProof' => self::$proof], Guard::silentInputFromHeaders(true, fn (string $name) => $name === Guard::BROWSER_HEADER ? self::$proof : null));
    }

    // ── adapters read X-TouchQue-Browser only when silentSignIn is on ───

    private function laravelRequest(?string $proof): Request
    {
        $request = Request::create('/account', 'POST', [], [], [], ['REMOTE_ADDR' => '203.0.113.7']);
        if ($proof !== null) {
            $request->headers->set('X-TouchQue-Browser', $proof);
        }
        return $request;
    }

    private function middleware(TouchQue $tq, array $options): TouchQueMiddleware
    {
        return new class ($tq, $options) extends TouchQueMiddleware {
            protected function resolveUser(Request $request): ?string
            {
                return 'jane@acme.com';
            }
        };
    }

    public function testLaravelMiddlewareRunsTheRouteAtOnceForAKnownBrowser(): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        self::$api->opts(['silent' => true]);
        $ran = 0;
        $handler = function (Request $request) use (&$ran) {
            $ran++;
            return new JsonResponse(['touchque' => $request->attributes->get('touchque')]);
        };
        $res = $this->middleware($this->client(), ['silentSignIn' => true])->handle($this->laravelRequest(self::$proof), $handler, 'LOGIN');
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(1, $ran);
        $body = json_decode($res->getContent(), true);
        $this->assertSame('SILENT', $body['touchque']['confirmedVia']);
        $this->assertSame('silent', $body['touchque']['assurance']['method']);
        $this->assertSame(self::$proof, self::$api->lastCheck()['browserProof']);
        $this->assertSame('203.0.113.7', self::$api->lastCheck()['clientIp']);

        // A subclass can turn it on too.
        $sub = new class ($this->client()) extends TouchQueMiddleware {
            protected $silentSignIn = ['maxAgeSeconds' => 3600];

            protected function resolveUser(Request $request): ?string
            {
                return 'jane@acme.com';
            }
        };
        $this->assertSame(200, $sub->handle($this->laravelRequest(self::$proof), $handler, 'LOGIN')->getStatusCode());
        $this->assertSame(3600, self::$api->lastCheck()['maxAgeSeconds']);
    }

    public function testLaravelMiddlewareWithoutSilentSignInIgnoresTheHeader(): void
    {
        if (!class_exists(Request::class)) {
            $this->markTestSkipped('illuminate/http not installed');
        }
        self::$api->opts(['silent' => true]);
        $handler = function () {
            $this->fail('the route must not run before an approval');
        };
        $res = $this->middleware($this->client(), [])->handle($this->laravelRequest(self::$proof), $handler, 'LOGIN');
        $this->assertSame(202, $res->getStatusCode());
        $this->assertNotContains('/risk/check', $this->paths());
        $this->assertArrayNotHasKey('browserProof', $this->loginRequests()[0]);

        $this->expectException(\InvalidArgumentException::class);
        $this->middleware($this->client(), ['silentSignIn' => 'on']);
    }

    public function testRelayLoginSucceedsSilentlyAndANewBrowserGetsThePushWithTheProof(): void
    {
        $calls = [];
        $relay = new RelayHandler($this->client(), [
            'getUserId' => fn () => null,
            'getLoginUser' => fn () => self::USER,
            'onAuthenticated' => function ($req, RelayResponse $res, array $info) use (&$calls) {
                $calls[] = $info;
            },
            'silentSignIn' => true,
        ]);
        $post = function () use ($relay): RelayResponse {
            return $relay->handle('POST', '/login', [], '203.0.113.7', 'UA', function (string $name): ?string {
                return strtolower($name) === Guard::BROWSER_HEADER ? self::$proof : null;
            });
        };

        $pushed = $post();
        $this->assertSame(202, $pushed->getStatus());
        $this->assertSame(self::$proof, $this->loginRequests()[0]['browserProof']);
        $this->assertSame([], $calls);

        self::$api->opts(['silent' => true]);
        $silent = $post();
        $this->assertSame(200, $silent->getStatus());
        $this->assertSame('success', $silent->getBody()['status']);
        $this->assertSame('silent', $silent->getBody()['requestId']);
        $this->assertSame('silent', $silent->getBody()['assurance']['method']);
        $this->assertSame([['externalUsername' => self::USER, 'requestId' => 'silent', 'via' => 'silent']], $calls);
        $this->assertCount(1, $this->loginRequests());
    }

    public function testRelayWithoutSilentSignInIgnoresTheHeader(): void
    {
        self::$api->opts(['silent' => true]);
        $relay = new RelayHandler($this->client(), ['getUserId' => fn () => null, 'getLoginUser' => fn () => self::USER]);
        $res = $relay->handle('POST', '/login', [], '203.0.113.7', 'UA', fn (string $name) => self::$proof);
        $this->assertSame(202, $res->getStatus());
        $this->assertNotContains('/risk/check', $this->paths());
    }
}
