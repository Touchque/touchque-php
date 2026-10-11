<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Config;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueNetworkException;
use TouchQue\Exceptions\TouchQueRejectedException;
use TouchQue\Relay\FixedWindowLimiter;
use TouchQue\Relay\MemoryRateLimitStore;
use TouchQue\Relay\RateLimitStore;
use TouchQue\Relay\RelayHandler;
use TouchQue\Relay\RelayResponse;
use TouchQue\Resources\Auth;
use TouchQue\Resources\Login;
use TouchQue\Resources\Offline;
use TouchQue\Resources\WebAuthn;
use TouchQue\TouchQue;

class RelayHandlerTest extends TestCase
{
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
        }
    }

    private function realClient(): TouchQue
    {
        if (self::$api === null) {
            $this->markTestSkipped('node is required for contract tests');
        }
        return new TouchQue(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    /** A client whose resources are PHPUnit mocks (nothing reaches the network). */
    private function mockClient(): TouchQue
    {
        $tq = new TouchQue(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        $tq->auth = $this->createMock(Auth::class);
        $tq->login = $this->createMock(Login::class);
        $tq->offline = $this->createMock(Offline::class);
        $tq->webauthn = $this->createMock(WebAuthn::class);
        return $tq;
    }

    private static function user(string $name): string
    {
        return $name . '-' . (++self::$seq) . '-' . bin2hex(random_bytes(3)) . '@example.com';
    }

    private function handler(TouchQue $tq, array $options = []): RelayHandler
    {
        return new RelayHandler($tq, $options + ['getUserId' => function () {
            return 'user@example.com';
        }]);
    }

    private function call(RelayHandler $h, string $method, string $path, array $body = [], array $headers = [], string $ip = '203.0.113.7'): RelayResponse
    {
        $lc = array_change_key_case($headers, CASE_LOWER);
        $res = $h->handle($method, $path, $body, $ip, $lc['user-agent'] ?? null, function (string $name) use ($lc) {
            return $lc[strtolower($name)] ?? null;
        }, ['native' => 'request']);
        $this->assertNotNull($res, "no relay route for $method $path");
        return $res;
    }

    private function loginPushesFor(string $user): int
    {
        return count(array_filter(self::$api->calls(), static function (array $c) use ($user): bool {
            return $c['path'] === '/login/request' && ($c['body']['externalUsername'] ?? null) === $user;
        }));
    }

    // ── construction / routing ───────────────────────────────────────────

    public function testGetUserIdIsRequired(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RelayHandler($this->mockClient(), []);
    }

    public function testUnknownRouteOrMethodReturnsNull(): void
    {
        $h = $this->handler($this->mockClient(), ['rateLimit' => false]);
        $this->assertNull($h->handle('GET', '/nope', [], '1.2.3.4', null, function () {
            return null;
        }));
        $this->assertNull($h->handle('GET', '/login', [], '1.2.3.4', null, function () {
            return null;
        }));
    }

    // ── auth-required routes ─────────────────────────────────────────────

    public function testAuthRequiredRoutes401WithoutUser(): void
    {
        $tq = $this->mockClient();
        foreach (['auth' => ['generateSecret', 'getUser', 'resetSecret'], 'webauthn' => ['registerOptions', 'registerVerify', 'listCredentials', 'deleteCredential']] as $res => $methods) {
            foreach ($methods as $m) {
                $tq->{$res}->expects($this->never())->method($m);
            }
        }
        $h = $this->handler($tq, ['getUserId' => function () {
            return null;
        }]);
        foreach ([['POST', '/enroll/start'], ['GET', '/enroll/status'], ['POST', '/passkey/register/options'], ['POST', '/passkey/register/verify'], ['GET', '/passkey/credentials'], ['DELETE', '/passkey/credentials/abc']] as [$method, $path]) {
            $res = $this->call($h, $method, $path);
            $this->assertSame(401, $res->getStatus(), "$method $path");
            $this->assertSame('UNAUTHORIZED_FOR_2FA', $res->getBody()['error']);
        }
    }

    public function testCallbacksReceiveTheNativeRequest(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->method('listCredentials')->with('jane@acme.com')->willReturn(['credentials' => []]);
        $seen = null;
        $h = $this->handler($tq, ['getUserId' => function ($req) use (&$seen) {
            $seen = $req;
            return 'jane@acme.com';
        }]);
        $res = $this->call($h, 'GET', '/passkey/credentials/');
        $this->assertSame(200, $res->getStatus());
        $this->assertSame(['native' => 'request'], $seen);
    }

    public function testDeleteCredentialRelaysDecodedIdScopedToUser(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->expects($this->once())->method('deleteCredential')->with('cred/1', 'user@example.com')->willReturn(['deleted' => true]);
        $res = $this->call($this->handler($tq), 'DELETE', '/passkey/credentials/cred%2F1');
        $this->assertSame(['deleted' => true], $res->getBody());
    }

    // ── enrollment ───────────────────────────────────────────────────────

    public function testEnrollStartIssuesSecretThenReplacesUnscannedQr(): void
    {
        $tq = $this->realClient();
        $user = self::user('enroll');
        $h = $this->handler($tq, ['getUserId' => function () use ($user) {
            return $user;
        }]);
        $first = $this->call($h, 'POST', '/enroll/start');
        $this->assertSame(200, $first->getStatus());
        $this->assertSame('data:image/png;base64,QR-' . $user, $first->getBody()['qrCodeDataUrl']);

        // A QR was issued but not scanned: 409 from TouchQue, safe to reset.
        $second = $this->call($h, 'POST', '/enroll/start');
        $this->assertSame(200, $second->getStatus());
        $this->assertSame('S2', $second->getBody()['secret']);
    }

    public function testEnrollStartNeverReplacesALinkedPhone(): void
    {
        $tq = $this->realClient();
        $user = self::user('linked');
        self::$api->link($user);
        $h = $this->handler($tq, ['getUserId' => function () use ($user) {
            return $user;
        }]);
        $res = $this->call($h, 'POST', '/enroll/start');
        $this->assertSame(409, $res->getStatus());
        $this->assertSame('already_linked', $res->getBody()['error']);
        $resets = array_filter(self::$api->calls(), static function (array $c) use ($user): bool {
            return $c['path'] === '/auth/secret/reset' && ($c['body']['externalUsername'] ?? null) === $user;
        });
        $this->assertCount(0, $resets);
    }

    public function testEnrollStatus(): void
    {
        $tq = $this->realClient();
        $user = self::user('status');
        $h = $this->handler($tq, ['getUserId' => function () use ($user) {
            return $user;
        }]);
        $this->assertSame(['linked' => false, 'used' => false, 'deviceId' => null], $this->call($h, 'GET', '/enroll/status')->getBody());
        self::$api->link($user);
        $this->assertSame(['linked' => true, 'used' => true, 'deviceId' => 'dev-1'], $this->call($h, 'GET', '/enroll/status')->getBody());
    }

    // ── classic login (two-phase) ────────────────────────────────────────

    public function testLoginRequiresAUsername(): void
    {
        $res = $this->call($this->handler($this->mockClient(), ['rateLimit' => false]), 'POST', '/login', []);
        $this->assertSame(400, $res->getStatus());
        $this->assertSame('externalUsername_required', $res->getBody()['error']);
    }

    public function testLoginAnswers202UntilApprovedThenAuthenticatesOnce(): void
    {
        $tq = $this->realClient();
        $user = self::user('login');
        self::$api->link($user);
        self::$api->opts(['numberMatch' => true]);
        $calls = [];
        $h = $this->handler($tq, [
            'rateLimit' => false,
            'getDetails' => function () {
                return ['Action' => 'Sign in'];
            },
            'onAuthenticated' => function ($req, RelayResponse $res, array $info) use (&$calls) {
                $calls[] = $info;
                $res->addHeader('Set-Cookie', 'sid=1; HttpOnly');
            },
        ]);

        try {
            $first = $this->call($h, 'POST', '/login', ['externalUsername' => strtoupper($user)], ['User-Agent' => 'Mozilla/5.0 (Macintosh)']);
            $this->assertSame(202, $first->getStatus());
            $this->assertSame('no-store', $first->getHeader('cache-control'));
            $step = $first->getBody()['touchque'];
            $this->assertSame('waiting', $step['state']);
            $this->assertSame('47', $step['number']);
            $this->assertSame([['label' => 'Action', 'value' => 'Sign in']], $step['details']);
            $this->assertCount(0, $calls);
            $sent = array_values(array_filter(self::$api->calls(), static function (array $c) use ($user): bool {
                return $c['path'] === '/login/request' && ($c['body']['externalUsername'] ?? null) === $user;
            }));
            $this->assertSame('LOGIN', $sent[0]['body']['type']);
            $this->assertSame('Mozilla/5.0 (Macintosh)', $sent[0]['body']['userAgent']);

            self::$api->approve();
            $token = $first->getBody()['token'];
            $done = $this->call($h, 'POST', '/login', ['externalUsername' => $user], ['X-TouchQue-Token' => $token]);
            $this->assertSame(200, $done->getStatus());
            $this->assertSame('success', $done->getBody()['status']);
            $this->assertSame($step['requestId'], $done->getBody()['requestId']);
            $this->assertSame('push', $done->getBody()['assurance']['method']);
            $this->assertSame('sid=1; HttpOnly', $done->getHeader('Set-Cookie'));
            $this->assertCount(1, $calls);
            $this->assertSame(['externalUsername' => $user, 'requestId' => $step['requestId'], 'via' => 'login'], $calls[0]);

            $replay = $this->call($h, 'POST', '/login', ['externalUsername' => $user], ['X-TouchQue-Token' => $token]);
            $this->assertNotSame(200, $replay->getStatus());
            $this->assertCount(1, $calls);
        } finally {
            self::$api->opts(['numberMatch' => false]);
        }
    }

    public function testLoginMapsOnAuthenticatedFailures(): void
    {
        $tq = $this->realClient();
        $user = self::user('cb');
        self::$api->link($user);
        $throw = new TouchQueRejectedException('rejected');
        $h = $this->handler($tq, ['rateLimit' => false, 'onAuthenticated' => function () use (&$throw) {
            throw $throw;
        }]);
        $run = function () use ($h, $user): RelayResponse {
            $first = $this->call($h, 'POST', '/login', ['externalUsername' => $user]);
            self::$api->approve($first->getBody()['touchque']['requestId']);
            return $this->call($h, 'POST', '/login', ['externalUsername' => $user], ['X-TouchQue-Token' => $first->getBody()['token']]);
        };

        $res = $run();
        $this->assertSame(403, $res->getStatus());
        $this->assertSame('2FA_REJECTED', $res->getBody()['error']);
        $this->assertNull($res->getHeader('Set-Cookie'));

        $throw = new \RuntimeException('database is down');
        $prev = ini_set('error_log', '/dev/null');
        try {
            $res = $run();
        } finally {
            ini_set('error_log', (string)$prev);
        }
        $this->assertSame(503, $res->getStatus());
        $this->assertSame('2FA_UNAVAILABLE', $res->getBody()['error']);
        $this->assertStringNotContainsString('database', $res->toJson());
    }

    // ── first-factor binding ─────────────────────────────────────────────

    public function testPreAuthLoginNeverHandsAnUnlinkedUserALinkingQr(): void
    {
        $user = self::user('unlinked');
        $before = count(array_filter(self::$api->calls(), fn ($c) => $c['path'] === '/auth/generate-secret'));
        $res = $this->call($this->handler($this->realClient(), ['rateLimit' => false]), 'POST', '/login', ['externalUsername' => $user]);
        $this->assertSame(202, $res->getStatus());
        $this->assertSame('enroll', $res->getBody()['touchque']['state']);
        $this->assertArrayNotHasKey('enroll', $res->getBody()['touchque']);
        $after = count(array_filter(self::$api->calls(), fn ($c) => $c['path'] === '/auth/generate-secret'));
        $this->assertSame($before, $after);
    }

    public function testLoginBehindThePasswordStepStillOffersLinking(): void
    {
        $user = self::user('unlinked2');
        $h = $this->handler($this->realClient(), ['rateLimit' => false, 'getLoginUser' => function () use ($user) {
            return $user;
        }]);
        $res = $this->call($h, 'POST', '/login', []);
        $this->assertSame(202, $res->getStatus());
        $this->assertNotEmpty($res->getBody()['touchque']['enroll']['qrCodeDataUrl']);
    }

    public function testLoginPushesOnlyToTheFirstFactorUser(): void
    {
        $tq = $this->realClient();
        $alice = self::user('alice');
        $victim = self::user('victim');
        self::$api->link($alice);
        self::$api->link($victim);
        $h = $this->handler($tq, ['rateLimit' => false, 'getLoginUser' => function () use ($alice) {
            return strtoupper($alice);
        }]);
        $res = $this->call($h, 'POST', '/login', ['externalUsername' => $victim]);
        $this->assertSame(202, $res->getStatus());
        $this->assertSame(1, $this->loginPushesFor($alice));
        $this->assertSame(0, $this->loginPushesFor($victim));
    }

    public function testPreAuthRoutes401WithoutFirstFactor(): void
    {
        $tq = $this->mockClient();
        $tq->login->expects($this->never())->method('request');
        $tq->offline->expects($this->never())->method('challenge');
        $tq->offline->expects($this->never())->method('verifyTotp');
        $h = $this->handler($tq, ['rateLimit' => false, 'getLoginUser' => function () {
            return null;
        }]);
        foreach ([['/login', ['externalUsername' => 'victim@example.com']], ['/offline/challenge', ['externalUsername' => 'victim@example.com']], ['/offline/totp', ['externalUsername' => 'victim@example.com', 'code' => 'AAAAAAA']]] as [$path, $body]) {
            $res = $this->call($h, 'POST', $path, $body);
            $this->assertSame(401, $res->getStatus(), $path);
            $this->assertSame('FIRST_FACTOR_REQUIRED', $res->getBody()['error']);
        }
    }

    public function testOfflineTotpUsesTheFirstFactorUserNotTheBody(): void
    {
        $tq = $this->mockClient();
        $tq->offline->expects($this->once())->method('verifyTotp')
            ->with('alice@example.com', 'ABCDEFG', 'LOGIN', '203.0.113.7', null)
            ->willReturn(['approved' => true, 'externalUsername' => 'alice@example.com']);
        $calls = [];
        $h = $this->handler($tq, ['rateLimit' => false, 'getLoginUser' => function () {
            return 'Alice@Example.com';
        }, 'onAuthenticated' => function ($req, $res, array $info) use (&$calls) {
            $calls[] = $info;
        }]);
        $res = $this->call($h, 'POST', '/offline/totp', ['externalUsername' => 'victim@example.com', 'code' => 'ABCDEFG']);
        $this->assertSame(['status' => 'success', 'approved' => true], $res->getBody());
        $this->assertSame([['externalUsername' => 'alice@example.com', 'via' => 'offline-totp']], $calls);
    }

    // ── offline sign ─────────────────────────────────────────────────────

    public function testOfflineRoutesAreOffWithoutFirstFactor(): void
    {
        $tq = $this->mockClient();
        $tq->offline->expects($this->never())->method($this->anything());
        $h = $this->handler($tq, ['rateLimit' => false]);
        foreach ([['/offline/challenge', ['externalUsername' => 'victim@example.com']], ['/offline/verify', ['challengeId' => 'c1', 'code' => 'AAAAAAA']], ['/offline/totp', ['externalUsername' => 'victim@example.com', 'code' => 'AAAAAAA']]] as [$path, $body]) {
            $res = $this->call($h, 'POST', $path, $body);
            $this->assertSame(403, $res->getStatus(), $path);
            $this->assertSame('OFFLINE_REQUIRES_FIRST_FACTOR', $res->getBody()['error']);
        }
    }

    public function testOfflineChallengeForTypedUserWhenExplicitlyAllowed(): void
    {
        $tq = $this->mockClient();
        $tq->offline->expects($this->once())->method('challenge')
            ->with('user@example.com', 'LOGIN', ['Action' => 'Sign in'], '203.0.113.7', 'Mozilla/5.0', null, true, 'req_1')
            ->willReturn(['challengeId' => 'c1', 'qr' => 'TQ1.a.b', 'qrDataUrl' => 'data:', 'expiresAt' => 't', 'expiresInSeconds' => 120, 'totpAvailable' => true, 'internal' => 'x']);
        $h = $this->handler($tq, ['allowOfflineWithoutFirstFactor' => true, 'getDetails' => function () {
            return ['Action' => 'Sign in'];
        }]);
        $res = $this->call($h, 'POST', '/offline/challenge', ['externalUsername' => 'User@Example.com', 'requestId' => 'req_1'], ['User-Agent' => 'Mozilla/5.0']);
        $this->assertSame(200, $res->getStatus());
        $this->assertSame(['challengeId' => 'c1', 'qr' => 'TQ1.a.b', 'qrDataUrl' => 'data:', 'expiresAt' => 't', 'expiresInSeconds' => 120, 'totpAvailable' => true], $res->getBody());
    }

    public function testOfflineVerifyAuthenticatesTheUserTouchQueReturned(): void
    {
        $tq = $this->mockClient();
        $tq->offline->method('verify')->with('c1', 'ABC-DEFG')->willReturn(['approved' => true, 'challengeId' => 'c1', 'externalUsername' => 'user@example.com', 'type' => 'LOGIN']);
        $calls = [];
        $h = $this->handler($tq, ['allowOfflineWithoutFirstFactor' => true, 'onAuthenticated' => function ($req, $res, array $info) use (&$calls) {
            $calls[] = $info;
        }]);
        $res = $this->call($h, 'POST', '/offline/verify', ['challengeId' => 'c1', 'code' => 'ABC-DEFG', 'externalUsername' => 'victim@example.com']);
        $this->assertSame(['status' => 'success', 'approved' => true, 'requestId' => 'c1'], $res->getBody());
        $this->assertSame([['externalUsername' => 'user@example.com', 'requestId' => 'c1', 'via' => 'offline']], $calls);
    }

    public function testOfflineVerifyWrongCodeAndOtherFailures(): void
    {
        $tq = $this->mockClient();
        $tq->offline->method('verify')->willReturnOnConsecutiveCalls(
            ['approved' => false, 'reason' => 'invalid_code', 'attemptsLeft' => 4],
            ['approved' => false, 'reason' => 'expired', 'attemptsLeft' => null]
        );
        $called = false;
        $h = $this->handler($tq, ['allowOfflineWithoutFirstFactor' => true, 'onAuthenticated' => function () use (&$called) {
            $called = true;
        }]);
        $wrong = $this->call($h, 'POST', '/offline/verify', ['challengeId' => 'c1', 'code' => 'AAAAAAA']);
        $this->assertSame(401, $wrong->getStatus());
        $this->assertSame(['approved' => false, 'reason' => 'invalid_code', 'attemptsLeft' => 4], $wrong->getBody());
        $expired = $this->call($h, 'POST', '/offline/verify', ['challengeId' => 'c1', 'code' => 'AAAAAAA']);
        $this->assertSame(400, $expired->getStatus());
        $this->assertSame(['approved' => false, 'reason' => 'expired'], $expired->getBody());
        $this->assertFalse($called);
    }

    public function testOfflineCodeForAnotherUserOpensNoSessionWithFirstFactor(): void
    {
        $tq = $this->mockClient();
        $tq->offline->method('verify')->willReturn(['approved' => true, 'challengeId' => 'c1', 'externalUsername' => 'someone.else@example.com', 'type' => 'LOGIN']);
        $called = false;
        $h = $this->handler($tq, ['rateLimit' => false, 'getLoginUser' => function () {
            return 'alice@example.com';
        }, 'onAuthenticated' => function () use (&$called) {
            $called = true;
        }]);
        $res = $this->call($h, 'POST', '/offline/verify', ['challengeId' => 'c1', 'code' => 'AAAAAAA']);
        $this->assertSame(401, $res->getStatus());
        $this->assertSame(['approved' => false, 'reason' => 'invalid_code'], $res->getBody());
        $this->assertFalse($called);
    }

    // ── passkeys ─────────────────────────────────────────────────────────

    public function testPasskeyAuthenticateVerify(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->method('primaryVerify')->with('att_1', ['id' => 'x'])->willReturnOnConsecutiveCalls(
            ['success' => true, 'externalUsername' => 'user@example.com', 'requestId' => 'req_2'],
            ['success' => false, 'requiresStepUp' => true],
            ['success' => false]
        );
        $calls = [];
        $h = $this->handler($tq, ['onAuthenticated' => function ($req, $res, array $info) use (&$calls) {
            $calls[] = $info;
        }]);
        $body = ['attemptId' => 'att_1', 'response' => ['id' => 'x']];
        $this->assertSame(['status' => 'success', 'requestId' => 'req_2'], $this->call($h, 'POST', '/passkey/authenticate/verify', $body)->getBody());
        $this->assertSame([['externalUsername' => 'user@example.com', 'requestId' => 'req_2', 'via' => 'passkey']], $calls);
        $this->assertSame(['requiresStepUp' => true], $this->call($h, 'POST', '/passkey/authenticate/verify', $body)->getBody());
        $failed = $this->call($h, 'POST', '/passkey/authenticate/verify', $body);
        $this->assertSame(401, $failed->getStatus());
        $this->assertSame(['error' => 'verification_failed'], $failed->getBody());
        $this->assertCount(1, $calls);
    }

    public function testPasskeyLoginVerifyOpensSessionOnlyForTheUserTouchQueApproved(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->method('authenticateVerify')->with('req_9', [])->willReturnOnConsecutiveCalls(
            ['success' => true, 'message' => 'approved', 'externalUsername' => 'attacker@example.com', 'requestId' => 'req_9'],
            ['success' => true, 'message' => 'approved']
        );
        $calls = [];
        $h = $this->handler($tq, ['onAuthenticated' => function ($req, $res, array $info) use (&$calls) {
            $calls[] = $info;
        }]);
        $res = $this->call($h, 'POST', '/passkey/login/verify', ['requestId' => 'req_9', 'externalUsername' => 'victim@example.com']);
        $this->assertSame(200, $res->getStatus());
        $this->assertSame([['externalUsername' => 'attacker@example.com', 'requestId' => 'req_9', 'via' => 'passkey']], $calls);

        // Older API that does not name the user: never opens a session.
        $res = $this->call($h, 'POST', '/passkey/login/verify', ['requestId' => 'req_9', 'externalUsername' => 'victim@example.com']);
        $this->assertSame(['success' => true, 'message' => 'approved'], $res->getBody());
        $this->assertCount(1, $calls);
    }

    public function testPasskeyLoginVerifyUserMismatchIs401WithFirstFactor(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->method('authenticateVerify')->willReturn(['success' => true, 'message' => 'ok', 'externalUsername' => 'other@example.com', 'requestId' => 'r']);
        $called = false;
        $h = $this->handler($tq, ['rateLimit' => false, 'getLoginUser' => function () {
            return 'alice@example.com';
        }, 'onAuthenticated' => function () use (&$called) {
            $called = true;
        }]);
        $res = $this->call($h, 'POST', '/passkey/login/verify', ['requestId' => 'r', 'response' => []]);
        $this->assertSame(401, $res->getStatus());
        $this->assertSame(['error' => 'verification_failed'], $res->getBody());
        $this->assertFalse($called);
    }

    public function testPasskeyRelaysUseTheRightClientMethods(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->expects($this->once())->method('primaryOptions')->with('user@example.com')->willReturn(['attemptId' => 'att_1', 'options' => []]);
        $tq->webauthn->expects($this->once())->method('authenticateOptions')->with('req_9')->willReturn(['challenge' => 'c']);
        $tq->webauthn->expects($this->once())->method('registerOptions')->with('user@example.com', true)->willReturn(['challenge' => 'r']);
        $tq->webauthn->expects($this->once())->method('registerVerify')->with('user@example.com', ['id' => 'x'], 'Laptop')->willReturn(['verified' => true]);
        $h = $this->handler($tq);
        $this->assertSame('att_1', $this->call($h, 'POST', '/passkey/authenticate/options', ['email' => 'User@Example.com'])->getBody()['attemptId']);
        $this->assertSame(['challenge' => 'c'], $this->call($h, 'POST', '/passkey/login/options', ['requestId' => 'req_9'])->getBody());
        $this->assertSame(['challenge' => 'r'], $this->call($h, 'POST', '/passkey/register/options')->getBody());
        $this->assertSame(['verified' => true], $this->call($h, 'POST', '/passkey/register/verify', ['response' => ['id' => 'x'], 'label' => 'Laptop'])->getBody());
    }

    // ── error mapping ────────────────────────────────────────────────────

    public function testClientRangeErrorForwardsOnlyTheMachineReadableCode(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->method('listCredentials')->willReturnOnConsecutiveCalls(
            $this->throwException(new TouchQueAPIException('Internal detail for tenant 42', 404, ['code' => 'not_found', 'error' => 'Internal detail for tenant 42'])),
            $this->throwException(new TouchQueAPIException('Bad request', 400, ['error' => 'invalid_input'])),
            $this->throwException(new TouchQueAPIException('Unknown API Error', 422, []))
        );
        $h = $this->handler($tq);
        $res = $this->call($h, 'GET', '/passkey/credentials');
        $this->assertSame(404, $res->getStatus());
        $this->assertSame(['error' => 'not_found'], $res->getBody());
        $this->assertStringNotContainsString('tenant', $res->toJson());
        $this->assertSame(['error' => 'invalid_input'], $this->call($h, 'GET', '/passkey/credentials')->getBody());
        $this->assertSame(['error' => 'request_failed'], $this->call($h, 'GET', '/passkey/credentials')->getBody());
    }

    public function testServerErrorsAndNetworkFailuresAre502(): void
    {
        $tq = $this->mockClient();
        $tq->webauthn->method('listCredentials')->willReturnOnConsecutiveCalls(
            $this->throwException(new TouchQueAPIException('db exploded at 10.0.0.5', 500, ['error' => 'db exploded at 10.0.0.5'])),
            $this->throwException(new TouchQueNetworkException('Network error: connection refused'))
        );
        $h = $this->handler($tq);
        foreach ([1, 2] as $_) {
            $res = $this->call($h, 'GET', '/passkey/credentials');
            $this->assertSame(502, $res->getStatus());
            $this->assertSame(['error' => 'relay_error'], $res->getBody());
        }
    }

    // ── rate limiting ────────────────────────────────────────────────────

    public function testLoginIsCappedPerUsernameAcrossIps(): void
    {
        $tq = $this->realClient();
        $victim = self::user('bombed');
        self::$api->link($victim);
        $h = $this->handler($tq, ['rateLimit' => ['perUser' => 3, 'perIp' => 100]]);
        $statuses = [];
        for ($i = 0; $i < 5; $i++) {
            $res = $this->call($h, 'POST', '/login', ['externalUsername' => $victim], [], "198.51.100.$i");
            $statuses[] = $res->getStatus();
            if ($res->getStatus() === 429) {
                $this->assertGreaterThan(0, (int)$res->getHeader('Retry-After'));
                $this->assertSame('RATE_LIMITED', $res->getBody()['error']);
                $this->assertSame((int)$res->getHeader('Retry-After'), $res->getBody()['retryAfter']);
            }
        }
        $this->assertSame([202, 202, 202, 429, 429], $statuses);
        // The 30 s de-duplication folds repeats into one pending request; the limiter stopped the rest.
        $this->assertSame(3, $this->loginPushesFor($victim));
    }

    public function testPollingASentPushIsNotCountedAgainstThePushLimit(): void
    {
        // The browser polls every 1.5 s; with the default limiter the 6th poll
        // used to be a 429 while the push was still on the phone.
        $tq = $this->realClient();
        $user = self::user('poller');
        self::$api->link($user);
        $h = $this->handler($tq, []);
        $first = $this->call($h, 'POST', '/login', ['externalUsername' => $user]);
        $this->assertSame(202, $first->getStatus());
        $token = $first->getBody()['token'];
        for ($i = 0; $i < 10; $i++) {
            if ($i === 9) {
                self::$api->approve();
            }
            $res = $this->call($h, 'POST', '/login', ['externalUsername' => $user], ['X-TouchQue-Token' => $token]);
            $this->assertSame($i === 9 ? 200 : 202, $res->getStatus(), "poll $i");
        }
        // New attempts still are: 4 more starts fill the per-user budget of 5.
        for ($i = 0; $i < 4; $i++) {
            $this->call($h, 'POST', '/login', ['externalUsername' => $user]);
        }
        $this->assertSame(429, $this->call($h, 'POST', '/login', ['externalUsername' => $user])->getStatus());
        $this->assertSame(429, $this->call($h, 'POST', '/login', ['externalUsername' => $user], ['X-TouchQue-Token' => 'forged'])->getStatus());
    }

    public function testAddingAPasskeyNeedsThePhone(): void
    {
        // A passkey approves requests on its own, so a stolen session of the partner
        // app must not be able to add one for a user with a linked phone.
        $tq = $this->realClient();
        $user = self::user('enrol');
        $h = $this->handler($tq, ['getUserId' => static function () use ($user) {
            return $user;
        }]);
        $res = $this->call($h, 'POST', '/passkey/register/options', []);
        $this->assertSame(200, $res->getStatus());
        $this->assertSame('reg-challenge', $res->getBody()['challenge']);

        self::$api->link($user);
        $first = $this->call($h, 'POST', '/passkey/register/options', []);
        $this->assertSame(202, $first->getStatus());
        $this->assertSame('waiting', $first->getBody()['touchque']['state']);
        $this->assertSame('47', $first->getBody()['touchque']['number']);
        $token = ['X-TouchQue-Token' => $first->getBody()['token']];
        $this->assertSame(202, $this->call($h, 'POST', '/passkey/register/options', [], $token)->getStatus());
        self::$api->approve();
        $done = $this->call($h, 'POST', '/passkey/register/options', [], $token);
        $this->assertSame(200, $done->getStatus());
        $this->assertSame('reg-challenge', $done->getBody()['challenge']);
        $this->assertNotSame(200, $this->call($h, 'POST', '/passkey/register/options', [], $token)->getStatus());
    }

    public function testOneIpSprayingUsernamesIsCappedPerIp(): void
    {
        $tq = $this->mockClient();
        $tq->offline->expects($this->exactly(4))->method('challenge')->willReturn(['challengeId' => 'c1']);
        $h = $this->handler($tq, ['allowOfflineWithoutFirstFactor' => true, 'rateLimit' => ['perIp' => 4, 'perUser' => 100]]);
        $statuses = [];
        for ($i = 0; $i < 6; $i++) {
            $statuses[] = $this->call($h, 'POST', '/offline/challenge', ['externalUsername' => "u$i@example.com"])->getStatus();
        }
        $this->assertSame([200, 200, 200, 200, 429, 429], $statuses);
    }

    public function testOfflineCodeGuessingIsCappedPerIp(): void
    {
        $tq = $this->mockClient();
        $tq->offline->method('verify')->willReturn(['approved' => false, 'reason' => 'invalid_code', 'attemptsLeft' => 3]);
        $h = $this->handler($tq, ['allowOfflineWithoutFirstFactor' => true, 'rateLimit' => ['perIp' => 3]]);
        $statuses = [];
        $last = null;
        for ($i = 0; $i < 5; $i++) {
            $last = $this->call($h, 'POST', '/offline/verify', ['challengeId' => 'c1', 'code' => 'AAAAAAA']);
            $statuses[] = $last->getStatus();
        }
        $this->assertSame([401, 401, 401, 429, 429], $statuses);
        $this->assertGreaterThan(0, (int)$last->getHeader('Retry-After'));
    }

    public function testRateLimitFalseTurnsTheLimiterOff(): void
    {
        $tq = $this->mockClient();
        $tq->offline->method('verify')->willReturn(['approved' => false, 'reason' => 'invalid_code']);
        $h = $this->handler($tq, ['allowOfflineWithoutFirstFactor' => true, 'rateLimit' => false]);
        for ($i = 0; $i < 30; $i++) {
            $this->assertSame(401, $this->call($h, 'POST', '/offline/verify', ['challengeId' => 'c1', 'code' => 'x'])->getStatus());
        }
    }

    public function testFixedWindowLimiterDefaultsAndWindowReset(): void
    {
        $limiter = new FixedWindowLimiter();
        $this->assertSame([60000, 20, 5], [$limiter->windowMs(), $limiter->perIp(), $limiter->perUser()]);
        $now = 1000000;
        for ($i = 0; $i < 5; $i++) {
            $this->assertSame(0, $limiter->hit('k', 5, $now));
        }
        $this->assertSame(60, $limiter->hit('k', 5, $now));
        $this->assertSame(31, $limiter->hit('k', 5, $now + 29500));
        $this->assertSame(1, $limiter->hit('k', 5, $now + 59999));
        $this->assertSame(0, $limiter->hit('k', 5, $now + 60000));
    }

    public function testCustomStoreIsUsed(): void
    {
        $store = new class implements RateLimitStore {
            public array $keys = [];
            private MemoryRateLimitStore $inner;

            public function __construct()
            {
                $this->inner = new MemoryRateLimitStore();
            }

            public function hit(string $key, int $windowMs, int $nowMs): array
            {
                $this->keys[] = $key;
                return $this->inner->hit($key, $windowMs, $nowMs);
            }
        };
        $tq = $this->mockClient();
        $tq->webauthn->method('primaryOptions')->willReturn(['attemptId' => 'a']);
        $h = $this->handler($tq, ['rateLimit' => ['store' => $store, 'perUser' => 1]]);
        $this->assertSame(200, $this->call($h, 'POST', '/passkey/authenticate/options', ['email' => 'A@b.com'])->getStatus());
        $this->assertSame(429, $this->call($h, 'POST', '/passkey/authenticate/options', ['email' => 'a@B.com'], [], '198.51.100.9')->getStatus());
        $this->assertSame(['ip|passkey-options|203.0.113.7', 'user|passkey-options|a@b.com', 'ip|passkey-options|198.51.100.9', 'user|passkey-options|a@b.com'], $store->keys);
    }

    public function testMemoryStoreStaysBounded(): void
    {
        $store = new MemoryRateLimitStore(10);
        $store->hit('k0', 60000, 1000);
        $this->assertSame(2, $store->hit('k0', 60000, 1000)['count']);
        for ($i = 1; $i < 25; $i++) {
            $store->hit("k$i", 60000, 1000);
        }
        // Still inside its window, but the oldest keys were dropped to stay bounded.
        $this->assertSame(1, $store->hit('k0', 60000, 1000)['count']);
        $this->assertSame(2, $store->hit('k24', 60000, 1000)['count']);
    }
}
