<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Guard;
use Touchque\Steps;
use Touchque\Touchque;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueException;
use Touchque\Resources\Auth;
use Touchque\Resources\Login;

/**
 * Contract tests against the shared fake Touchque API — a real HTTP round
 * trip, so request signing is verified too (not just mocked). Same
 * scenarios as the Node/Python SDKs' step-up tests.
 */
class ContractTest extends TestCase
{
    private static ?FakeApi $api = null;

    public static function setUpBeforeClass(): void
    {
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

    public function testWaitingStepCarriesTheTelemetryToken(): void
    {
        // R1-04: the browser can only post behavioural signals with this token.
        self::$api->link('tel@acme.com');
        $tq = $this->client();
        $this->assertArrayNotHasKey('telemetryToken', $tq->start('LOGIN', 'tel@acme.com'));
        self::$api->opts(['telemetry' => true]);
        try {
            $this->assertSame('tt_test', $tq->start('LOGIN', 'tel@acme.com')['telemetryToken']);
        } finally {
            self::$api->opts(['telemetry' => false]);
        }
    }

    public function testStartCheckCompleteFullFlow(): void
    {
        self::$api->link('jane@acme.com');
        $tq = $this->client();

        $step = $tq->start('SEND_MONEY', 'jane@acme.com', ['Amount' => '250 EUR'], 'tx-9');
        $this->assertSame('waiting', $step['state']);
        $this->assertSame('47', $step['number']); // SEND_MONEY is critical in the fake API
        $this->assertSame([['label' => 'Amount', 'value' => '250 EUR']], $step['details']);

        $this->assertSame('waiting', $tq->check($step['requestId'])['state']);
        self::$api->approve();
        $this->assertSame('approved', $tq->check($step['requestId'])['state']);

        $approval = $tq->complete($step['requestId'], 'jane@acme.com', 'SEND_MONEY', ['Amount' => '250 EUR'], 'tx-9');
        $this->assertSame(['phishingResistant' => false, 'method' => 'push'], $approval['assurance']);

        $this->expectException(\Throwable::class);
        $tq->complete($step['requestId'], 'jane@acme.com', 'SEND_MONEY', ['Amount' => '250 EUR'], 'tx-9');
    }

    public function testCompleteRefusesADifferentAmount(): void
    {
        self::$api->link('jane2@acme.com');
        $tq = $this->client();
        $step = $tq->start('SEND_MONEY', 'jane2@acme.com', ['Amount' => '250 EUR']);
        self::$api->approve($step['requestId']);
        $this->expectException(TouchqueException::class);
        $tq->complete($step['requestId'], 'jane2@acme.com', 'SEND_MONEY', ['Amount' => '9999 EUR']);
    }

    public function testUnknownActionIsAClearConfigError(): void
    {
        self::$api->link('jane3@acme.com');
        $tq = $this->client();
        $this->expectException(TouchqueConfigException::class);
        $this->expectExceptionMessageMatches('/NOT_DEFINED/');
        $tq->start('NOT_DEFINED', 'jane3@acme.com');
    }

    public function testActionTypesDefineCreatesAndUpdates(): void
    {
        $tq = $this->client();
        $tq->actionTypes->define('EXPORT', 'Export data', null, true);
        $calls = self::$api->calls();
        $body = null;
        foreach ($calls as $c) {
            if ($c['path'] === '/action-types') {
                $body = $c['body'];
            }
        }
        $this->assertSame(['type' => 'EXPORT', 'name' => 'Export data', 'critical' => true], $body);
    }

    public function testGuardFullFlowViaRun(): void
    {
        self::$api->link('guard@acme.com');
        self::$api->opts(['numberMatch' => true]);
        $tq = $this->client();

        $first = Guard::run($tq, 'guard@acme.com', 'LOGIN');
        $this->assertSame(202, $first['status']);
        $this->assertSame('waiting', $first['body']['touchque']['state']);
        $this->assertSame('47', $first['body']['touchque']['number']);
        $token = $first['body']['token'];

        $still = Guard::run($tq, 'guard@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertSame(202, $still['status']);

        self::$api->approve();
        $done = Guard::run($tq, 'guard@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertSame(200, $done['status']);
        $this->assertSame('push', $done['approved']['assurance']['method']);

        $replay = Guard::run($tq, 'guard@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertArrayNotHasKey('approved', $replay);
        $this->assertContains($replay['status'], [403, 408, 409]);
    }

    public function testGuardEnrollThenOfflineCode(): void
    {
        $tq = $this->client();

        $first = Guard::run($tq, 'new-offline@acme.com', 'LOGIN');
        $this->assertSame(202, $first['status']);
        $this->assertSame('enroll', $first['body']['touchque']['state']);
        $this->assertStringStartsWith('data:image/png;base64,', $first['body']['touchque']['enroll']['qrCodeDataUrl']);

        self::$api->link('new-offline@acme.com');
        $token = $first['body']['token'];
        $waiting = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $token);
        $this->assertSame('waiting', $waiting['body']['touchque']['state']);

        $off = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $waiting['body']['token'], true);
        $this->assertSame('offline', $off['body']['touchque']['state']);
        $this->assertSame('data:image/png;base64,OFFLINE', $off['body']['touchque']['offline']['qrDataUrl']);

        $wrong = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, 'ZZZZ999');
        $this->assertSame(4, $wrong['body']['touchque']['offline']['attemptsLeft']);

        $ok = Guard::run($tq, 'new-offline@acme.com', 'LOGIN', null, null, null, null, $wrong['body']['token'], false, 'ABCD123');
        $this->assertSame(200, $ok['status']);
        $this->assertSame(['phishingResistant' => false, 'method' => 'offline_code'], $ok['approved']['assurance']);
    }

    public function testGuardPhoneRejectKillsTheOfflineQr(): void
    {
        $tq = $this->client();
        self::$api->link('reject-offline@acme.com');

        $start = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN');
        $off = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $start['body']['token'], true);
        $this->assertSame('offline', $off['body']['touchque']['state']);
        // The QR is linked to the push the user started.
        $qrCalls = array_values(array_filter(self::$api->calls(), fn ($c) => $c['path'] === '/offline/challenge'));
        $this->assertSame($start['body']['touchque']['requestId'], end($qrCalls)['body']['requestId']);

        // While the QR is up the page keeps polling; nothing changes until the phone answers.
        $poll = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token']);
        $this->assertSame(202, $poll['status']);
        $this->assertSame('offline', $poll['body']['touchque']['state']);
        $this->assertSame($off['body']['touchque']['offline']['challengeId'], $poll['body']['touchque']['offline']['challengeId']);

        self::$api->reject(); // the user taps Reject on the phone

        $rejected = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $poll['body']['token']);
        $this->assertSame(403, $rejected['status']);
        $this->assertSame('rejected', $rejected['body']['touchque']['state']);
        // Even the right code from the QR already on screen does not finish it…
        $late = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, 'ABCD123');
        $this->assertSame('rejected', $late['body']['touchque']['state']);
        $this->assertSame('request_rejected', $late['body']['touchque']['reason']);
        // …nor the time-based code…
        $totp = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, '123456', 'totp');
        $this->assertSame('rejected', $totp['body']['touchque']['state']);
        // …and pressing offline mode again gets no QR for that sign-in.
        $again = Guard::run($tq, 'reject-offline@acme.com', 'LOGIN', null, null, null, null, $start['body']['token'], true);
        $this->assertSame('rejected', $again['body']['touchque']['state']);
    }

    public function testGuardOfflineQrCarriesTheNumberForMatching(): void
    {
        $tq = $this->client();
        self::$api->link('nm-offline@acme.com');
        self::$api->opts(['numberMatch' => true]);
        try {
            $start = Guard::run($tq, 'nm-offline@acme.com', 'LOGIN');
            $this->assertSame('47', $start['body']['touchque']['number']);
            $off = Guard::run($tq, 'nm-offline@acme.com', 'LOGIN', null, null, null, null, $start['body']['token'], true);
            $this->assertSame('47', $off['body']['touchque']['offline']['challengeCode']);
        } finally {
            self::$api->opts(['numberMatch' => false]);
        }
    }

    public function testGuardFrozenRateLimitedBlocked(): void
    {
        self::$api->link('blocked@acme.com');
        $tq = $this->client();

        self::$api->opts(['frozen' => true]);
        $frozen = Guard::run($tq, 'blocked@acme.com', 'LOGIN');
        $this->assertSame(423, $frozen['status']);
        $this->assertSame(900, $frozen['body']['touchque']['retryAfter']);

        self::$api->opts(['frozen' => false, 'rateLimited' => true]);
        $limited = Guard::run($tq, 'blocked@acme.com', 'LOGIN');
        $this->assertSame(429, $limited['status']);

        self::$api->opts(['rateLimited' => false, 'blocked' => 'geo_policy']);
        $blocked = Guard::run($tq, 'blocked@acme.com', 'LOGIN');
        $this->assertSame(403, $blocked['status']);
        $this->assertSame(['state' => 'blocked', 'reason' => 'geo_policy', 'caseCode' => 'REF-USE'], $blocked['body']['touchque']);
    }

    // ── Vishing Shield ──────────────────────────────────────────────────

    private function cleanOpts(array $extra = []): void
    {
        self::$api->opts($extra + ['blocked' => false, 'frozen' => false, 'rateLimited' => false, 'numberMatch' => false, 'passkeyOnly' => false, 'canary' => false]);
    }

    public function testFirstWaitingStepCarriesTheMirrorCanaryPollsDoNot(): void
    {
        $this->cleanOpts(['canary' => true]);
        self::$api->link('canary@acme.com');
        $tq = $this->client();
        try {
            $first = Guard::run($tq, 'canary@acme.com', 'LOGIN');
            $this->assertStringEndsWith('.gif', $first['body']['touchque']['canary']['url']);
            $poll = Guard::run($tq, 'canary@acme.com', 'LOGIN', null, null, null, null, $first['body']['token']);
            $this->assertSame('waiting', $poll['body']['touchque']['state']);
            $this->assertArrayNotHasKey('canary', $poll['body']['touchque']);
        } finally {
            $this->cleanOpts();
        }
    }

    public function testPushTappedDuringACallBecomesPasskeyRequiredAlsoFromTheOfflineQr(): void
    {
        $this->cleanOpts();
        self::$api->link('oncall@acme.com');
        $tq = $this->client();
        $first = Guard::run($tq, 'oncall@acme.com', 'LOGIN');
        $rid = $first['body']['touchque']['requestId'];
        $off = Guard::run($tq, 'oncall@acme.com', 'LOGIN', null, null, null, null, $first['body']['token'], true);
        $this->assertSame('offline', $off['body']['touchque']['state']);
        self::$api->escalate($rid);
        $poll = Guard::run($tq, 'oncall@acme.com', 'LOGIN', null, null, null, null, $off['body']['token']);
        $this->assertSame(202, $poll['status']);
        $this->assertSame('passkey_required', $poll['body']['touchque']['state']);
        $this->assertSame($rid, $poll['body']['touchque']['requestId']);
        $typed = Guard::run($tq, 'oncall@acme.com', 'LOGIN', null, null, null, null, $off['body']['token'], false, 'ABCD123');
        $this->assertSame('passkey_required', $typed['body']['touchque']['state']);
    }

    public function testProvisionalApprovalAndTheCriticalActionLock(): void
    {
        $this->cleanOpts();
        self::$api->link('prov@acme.com');
        $tq = $this->client();
        $step = $tq->start('LOGIN', 'prov@acme.com');
        self::$api->approve($step['requestId'], 'DEVICE', true);
        $approval = $tq->complete($step['requestId'], 'prov@acme.com', 'LOGIN');
        $this->assertTrue($approval['provisional']);
        $this->assertFalse($approval['revoked']);
        $this->assertSame(['state' => 'blocked', 'reason' => 'provisional', 'caseCode' => 'REF-USE'], $tq->start('SEND_MONEY', 'prov@acme.com'));
        self::$api->reconfirm($step['requestId']);
        $this->assertSame('waiting', $tq->start('SEND_MONEY', 'prov@acme.com')['state']);
    }

    public function testAnApprovalTakenBackIsNeverUsed(): void
    {
        $this->cleanOpts();
        self::$api->link('revoke@acme.com');
        $tq = $this->client();
        $first = Guard::run($tq, 'revoke@acme.com', 'LOGIN');
        $rid = $first['body']['touchque']['requestId'];
        self::$api->approve($rid);
        self::$api->revoke($rid, 'COACHED');
        $done = Guard::run($tq, 'revoke@acme.com', 'LOGIN', null, null, null, null, $first['body']['token']);
        $this->assertSame(408, $done['status']);
        $this->assertSame(['state' => 'expired', 'reason' => 'revoked'], $done['body']['touchque']);
    }

    // ── First-time QR: one per enrollment ──────────────────────────────────

    /** The calls the fake API got after the first $from. */
    private static function callsSince(int $from): array
    {
        return array_map(fn ($c) => $c['method'] . ' ' . $c['path'], array_slice(self::$api->calls(), $from));
    }

    public function testAnEnrollPollKeepsTheQrWithoutANewSecret(): void
    {
        $this->cleanOpts();
        $tq = $this->client();
        $user = 'enroll-keep@acme.com';
        $first = Guard::run($tq, $user, 'LOGIN');
        $this->assertSame(202, $first['status']);
        $qr = $first['body']['touchque']['enroll'];
        $this->assertSame(['data:image/png;base64,QR-' . $user, ['r1']], [$qr['qrCodeDataUrl'], $qr['recoveryCodes']]);
        $expiresAt = Steps::isoMs($qr['expiresAt']);
        $this->assertNotNull($expiresAt, 'the API\'s ISO 8601 expiresAt is kept');
        $this->assertTrue(Guard::isStatusPoll($tq, $user, 'LOGIN', null, null, $first['body']['token']));

        $from = count(self::$api->calls());
        $poll = Guard::run($tq, $user, 'LOGIN', null, null, null, null, $first['body']['token']);
        $this->assertSame(202, $poll['status']);
        // No enroll object: the page keeps the QR and the recovery codes it shows.
        $this->assertSame(['state' => 'enroll', 'expiresAt' => Steps::isoOf($expiresAt)], $poll['body']['touchque']);
        // Only the link state is read: no new secret, no reset, no push.
        $this->assertSame(['GET /users/' . rawurlencode($user)], self::callsSince($from));

        $again = Guard::run($tq, $user, 'LOGIN', null, null, null, null, $poll['body']['token']);
        $this->assertSame($poll['body']['touchque'], $again['body']['touchque']);
        $this->assertTrue(Guard::isStatusPoll($tq, $user, 'LOGIN', null, null, $poll['body']['token']));
        $this->assertFalse(Guard::isStatusPoll($tq, $user, 'SEND_MONEY', null, null, $poll['body']['token']));
        $this->assertFalse(Guard::isStatusPoll($tq, 'other@acme.com', 'LOGIN', null, null, $poll['body']['token']));
    }

    public function testLinkingDuringTheEnrollPollSendsThePush(): void
    {
        $this->cleanOpts();
        $tq = $this->client();
        $user = 'enroll-link@acme.com';
        $first = Guard::run($tq, $user, 'LOGIN');
        $this->assertSame('enroll', $first['body']['touchque']['state']);
        self::$api->link($user);
        $poll = Guard::run($tq, $user, 'LOGIN', null, null, null, null, $first['body']['token']);
        $this->assertSame(202, $poll['status']);
        $this->assertSame('waiting', $poll['body']['touchque']['state']);
        $this->assertNotEmpty($poll['body']['touchque']['requestId']);
    }

    public function testAnEnrollQrCloseToItsExpiryIsReplaced(): void
    {
        $this->cleanOpts();
        self::$api->opts(['secretTtlMs' => 10000]); // less than the 15 s the guard keeps in hand
        try {
            $tq = $this->client();
            $user = 'enroll-short@acme.com';
            $first = Guard::run($tq, $user, 'LOGIN');
            $this->assertSame('data:image/png;base64,QR-' . $user, $first['body']['touchque']['enroll']['qrCodeDataUrl']);
            $poll = Guard::run($tq, $user, 'LOGIN', null, null, null, null, $first['body']['token']);
            $this->assertSame(202, $poll['status']);
            $this->assertSame('enroll', $poll['body']['touchque']['state']);
            $this->assertSame(['data:image/png;base64,QR2-' . $user, ['r2']], [$poll['body']['touchque']['enroll']['qrCodeDataUrl'], $poll['body']['touchque']['enroll']['recoveryCodes']]);
        } finally {
            self::$api->opts(['secretTtlMs' => null]);
        }
    }

    public function testAnEnrollTokenIsAStatusPollOnlyWhileTheQrIsUp(): void
    {
        $tq = $this->client();
        try {
            self::$api->opts(['secretTtlMs' => 60000]); // 45 s before the 15 s margin
            $up = Guard::run($tq, 'enroll-up@acme.com', 'LOGIN');
            $this->assertTrue(Guard::isStatusPoll($tq, 'enroll-up@acme.com', 'LOGIN', null, null, $up['body']['token']));

            self::$api->opts(['secretTtlMs' => 10000]); // inside the margin: the next poll renews the QR
            $expiring = Guard::run($tq, 'enroll-expiring@acme.com', 'LOGIN');
            $this->assertFalse(Guard::isStatusPoll($tq, 'enroll-expiring@acme.com', 'LOGIN', null, null, $expiring['body']['token']));
        } finally {
            self::$api->opts(['secretTtlMs' => null]);
        }
    }

    /** Guard::run() with only a token and the $beforeStart hook. */
    private static function runWithHook(Touchque $tq, string $user, ?string $token, callable $beforeStart): array
    {
        return Guard::run($tq, $user, 'LOGIN', null, null, null, null, $token, false, null, null, true, null, false, null, $beforeStart);
    }

    public function testBeforeStartRunsOnlyWhenAnEnrollPollStartsAfterAll(): void
    {
        $this->cleanOpts();
        $tq = $this->client();
        $user = 'enroll-hook@acme.com';
        $calls = 0;
        $refused = ['status' => 429, 'body' => ['error' => 'RATE_LIMITED']];
        $refuse = function () use (&$calls, $refused): array {
            $calls++;
            return $refused;
        };
        $goOn = function () use (&$calls): ?array {
            $calls++;
            return null;
        };

        $first = self::runWithHook($tq, $user, null, $refuse);
        $this->assertSame('enroll', $first['body']['touchque']['state']);
        $keep = self::runWithHook($tq, $user, $first['body']['token'], $refuse);
        $this->assertSame('enroll', $keep['body']['touchque']['state']);
        $this->assertArrayNotHasKey('enroll', $keep['body']['touchque']);
        $this->assertSame(0, $calls, 'never for a first attempt or a poll that keeps the QR');

        // Linked: the poll would push. The hook answers instead, and nothing starts.
        self::$api->link($user);
        $from = count(self::$api->calls());
        $this->assertSame($refused, self::runWithHook($tq, $user, $first['body']['token'], $refuse));
        $this->assertSame(['GET /users/' . rawurlencode($user)], self::callsSince($from));
        $waiting = self::runWithHook($tq, $user, $first['body']['token'], $goOn);
        $this->assertSame('waiting', $waiting['body']['touchque']['state']);
        $this->assertSame(2, $calls);

        // A QR inside the margin would be renewed: the hook comes first there too.
        self::$api->opts(['secretTtlMs' => 10000]);
        try {
            $other = 'enroll-hook-renew@acme.com';
            $first = Guard::run($tq, $other, 'LOGIN');
            $from = count(self::$api->calls());
            $this->assertSame($refused, self::runWithHook($tq, $other, $first['body']['token'], $refuse));
            $this->assertSame(['GET /users/' . rawurlencode($other)], self::callsSince($from), 'no new secret');
            $renewed = self::runWithHook($tq, $other, $first['body']['token'], $goOn);
            $this->assertSame('data:image/png;base64,QR2-' . $other, $renewed['body']['touchque']['enroll']['qrCodeDataUrl']);
            $this->assertSame(4, $calls);
        } finally {
            self::$api->opts(['secretTtlMs' => null]);
        }
    }

    public function testABeforeStartAnswerThatIsNoResultFailsClosed(): void
    {
        $this->cleanOpts();
        $tq = $this->client();
        $user = 'enroll-hook-bad@acme.com';
        $first = Guard::run($tq, $user, 'LOGIN');
        self::$api->link($user);
        foreach ([true, 'refused', ['error' => 'RATE_LIMITED'], ['status' => 429]] as $bad) {
            $from = count(self::$api->calls());
            try {
                self::runWithHook($tq, $user, $first['body']['token'], fn () => $bad);
                $this->fail('a refusal that is not a result must not let the start go ahead: ' . json_encode($bad));
            } catch (\InvalidArgumentException $e) {
                $this->assertSame(['GET /users/' . rawurlencode($user)], self::callsSince($from), 'nothing started');
            }
        }
    }

    public function testEnrollOffSaysWhyAndIsNoStatusPoll(): void
    {
        $tq = $this->client();
        // $enroll = false (a pre-auth relay): "not linked", no QR, so no expiry in the token.
        $step = Guard::run($tq, 'enroll-none@acme.com', 'LOGIN', null, null, null, null, null, false, null, null, false);
        $this->assertSame(202, $step['status']);
        $this->assertSame(['state' => 'enroll', 'reason' => 'enrollment_off'], $step['body']['touchque']);
        $this->assertFalse(Guard::isStatusPoll($tq, 'enroll-none@acme.com', 'LOGIN', null, null, $step['body']['token']));
        // A 202 step, not a refusal: no state headers.
        $this->assertSame(['Cache-Control' => 'no-store'], Guard::response($step)['headers']);
    }

    // ── Waiting polls repeat expiresAt ─────────────────────────────────────

    /** The claims of a guard token signed with the fake API's secret. */
    private static function claims(string $token): array
    {
        return Steps::verifyGuardToken('test_secret', $token);
    }

    public function testWaitingPollsCarryTheRequestsExpiresAt(): void
    {
        $this->cleanOpts();
        $user = 'expiry-poll@acme.com';
        self::$api->link($user);
        $tq = $this->client();
        $poll = fn (string $token, bool $offline = false) => Guard::run($tq, $user, 'LOGIN', null, null, null, null, $token, $offline);

        $first = Guard::run($tq, $user, 'LOGIN');
        $rx = Steps::isoMs($first['body']['touchque']['expiresAt']);
        $this->assertNotNull($rx);
        $this->assertSame($rx, self::claims($first['body']['token'])['rx'], 'the token carries the request\'s expiry');
        $expiresAt = Steps::isoOf($rx);

        $second = $poll($first['body']['token']);
        $third = $poll($second['body']['token']);
        foreach ([$second, $third] as $answer) {
            $this->assertSame([202, 'waiting', $expiresAt], [$answer['status'], $answer['body']['touchque']['state'], $answer['body']['touchque']['expiresAt']]);
            $this->assertSame($rx, self::claims($answer['body']['token'])['rx']);
        }

        // The offline QR next to the push carries it on.
        $off = $poll($third['body']['token'], true);
        $this->assertSame('offline', $off['body']['touchque']['state']);
        $this->assertSame($rx, self::claims($off['body']['token'])['rx']);
        $kept = $poll($off['body']['token']);
        $this->assertSame([$rx, 'offline'], [self::claims($kept['body']['token'])['rx'], $kept['body']['touchque']['state']]);

        // A tap during a call moves the push to a passkey and Touchque extends it (180 s): the switch from the
        // offline QR answers the live expiry, not the first one, and the new token keeps it.
        self::$api->escalate($first['body']['touchque']['requestId']);
        $passkey = $poll($kept['body']['token']);
        $live = Steps::isoMs($passkey['body']['touchque']['expiresAt']);
        $this->assertSame('passkey_required', $passkey['body']['touchque']['state']);
        $this->assertGreaterThan($rx + 100000, $live, 'the extended expiry, not the first one');
        $this->assertSame($live, self::claims($passkey['body']['token'])['rx']);
        $again = $poll($passkey['body']['token']);
        $this->assertSame(['passkey_required', Steps::isoOf($live)], [$again['body']['touchque']['state'], $again['body']['touchque']['expiresAt']]);
    }

    public function testAPushMovedToAPasskeyAnswersItsExtendedExpiry(): void
    {
        $this->cleanOpts();
        $user = 'expiry-escalated@acme.com';
        self::$api->link($user);
        $tq = $this->client();
        $first = Guard::run($tq, $user, 'LOGIN');
        $rx = Steps::isoMs($first['body']['touchque']['expiresAt']);
        self::$api->escalate($first['body']['touchque']['requestId']);
        $poll = Guard::run($tq, $user, 'LOGIN', null, null, null, null, $first['body']['token']);
        $live = Steps::isoMs($poll['body']['touchque']['expiresAt']);
        $this->assertSame('passkey_required', $poll['body']['touchque']['state']);
        $this->assertGreaterThan($rx + 100000, $live);
        $this->assertSame($live, self::claims($poll['body']['token'])['rx']);
    }

    public function testWithoutALiveExpiryAPollFallsBackToTheToken(): void
    {
        // A status answer without expiresAt (an older API): the token's rx; without rx either, none (5.1).
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        $tq->login = $this->createMock(Login::class);
        $tq->login->method('status')->willReturn(['status' => 'PENDING']);
        $rx = (int)(microtime(true) * 1000) + 60000;
        $claims = ['u' => 'old@acme.com', 'a' => 'LOGIN', 'd' => '', 'r' => null, 'st' => 'waiting', 'rid' => 'r1',
            'n' => null, 'oc' => null, 'exp' => (int)(microtime(true) * 1000) + 600000, 'rx' => $rx];
        $poll = Guard::run($tq, 'old@acme.com', 'LOGIN', null, null, null, null, Steps::signGuardToken('test_secret', $claims));
        $this->assertSame(['waiting', Steps::isoOf($rx)], [$poll['body']['touchque']['state'], $poll['body']['touchque']['expiresAt']]);
        $this->assertSame($rx, self::claims($poll['body']['token'])['rx']);

        unset($claims['rx']);
        $old = Guard::run($tq, 'old@acme.com', 'LOGIN', null, null, null, null, Steps::signGuardToken('test_secret', $claims));
        $this->assertSame('waiting', $old['body']['touchque']['state']);
        $this->assertArrayNotHasKey('expiresAt', $old['body']['touchque']);
        $this->assertArrayNotHasKey('rx', self::claims($old['body']['token']));
    }

    public function testAPasskeyRequestRepeatsItsExpiresAt(): void
    {
        $this->cleanOpts(['passkeyOnly' => true]);
        try {
            $user = 'expiry-passkey@acme.com';
            self::$api->link($user);
            $tq = $this->client();
            $first = Guard::run($tq, $user, 'LOGIN');
            $this->assertSame('passkey_required', $first['body']['touchque']['state']);
            $expiresAt = Steps::isoOf(Steps::isoMs($first['body']['touchque']['expiresAt']));
            $poll = Guard::run($tq, $user, 'LOGIN', null, null, null, null, $first['body']['token']);
            $this->assertSame(['passkey_required', $expiresAt], [$poll['body']['touchque']['state'], $poll['body']['touchque']['expiresAt']]);
        } finally {
            $this->cleanOpts();
        }
    }

    public function testATokenWithoutRxTakesTheLiveExpiry(): void
    {
        $this->cleanOpts();
        $user = 'expiry-old@acme.com';
        self::$api->link($user);
        $tq = $this->client();
        $first = Guard::run($tq, $user, 'LOGIN');
        $claims = self::claims($first['body']['token']);
        unset($claims['rx']);
        $poll = Guard::run($tq, $user, 'LOGIN', null, null, null, null, Steps::signGuardToken('test_secret', $claims));
        $expiry = Steps::isoMs($first['body']['touchque']['expiresAt']);
        $this->assertSame(['waiting', Steps::isoOf($expiry)], [$poll['body']['touchque']['state'], $poll['body']['touchque']['expiresAt']]);
        $this->assertSame($expiry, self::claims($poll['body']['token'])['rx']);
    }

    public function testTheEnrollExpiryComesFromTtlMsWhenTheApiSendsNoDate(): void
    {
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', 'http://127.0.0.1:9'));
        $tq->login = $this->createMock(Login::class);
        $tq->login->method('request')->willThrowException(new TouchqueAPIException('No linked device', 404, ['code' => 'device_not_linked']));
        $tq->auth = $this->createMock(Auth::class);
        $tq->auth->method('generateSecret')->willReturnOnConsecutiveCalls(
            ['qrCodeDataUrl' => 'data:image/png;base64,QR', 'expiresAt' => 'soon', 'ttlMs' => 60000],
            ['qrCodeDataUrl' => 'data:image/png;base64,QR', 'expiresAt' => 'soon']
        );

        $now = (int)(microtime(true) * 1000);
        $withTtl = Guard::run($tq, 'ttl@acme.com', 'LOGIN');
        $expiresAt = Steps::isoMs($withTtl['body']['touchque']['enroll']['expiresAt']);
        $this->assertGreaterThanOrEqual($now + 60000, $expiresAt);
        $this->assertLessThan($now + 65000, $expiresAt);
        $this->assertTrue(Guard::isStatusPoll($tq, 'ttl@acme.com', 'LOGIN', null, null, $withTtl['body']['token']));

        // Neither a date nor a lifetime: no expiry, and polls start again as before.
        $none = Guard::run($tq, 'ttl@acme.com', 'LOGIN');
        $this->assertNull($none['body']['touchque']['enroll']['expiresAt']);
        $this->assertFalse(Guard::isStatusPoll($tq, 'ttl@acme.com', 'LOGIN', null, null, $none['body']['token']));
    }
}
