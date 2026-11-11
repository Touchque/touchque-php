<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\AgentKeys;
use Touchque\ApprovalToken;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueApprovalException;
use Touchque\Exceptions\TouchqueApprovalMismatchException;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Touchque;
use Touchque\TouchqueAgent;

/**
 * AI agents in the PHP SDK: management calls send what the shared vectors
 * (fixtures/agent-vectors.json) say, and TouchqueAgent signs in with its own
 * key against the shared fake API, which checks the private_key_jwt
 * assertion and the DPoP proofs like the real API.
 */
class AgentsTest extends TestCase
{
    private static FakeApi $api;
    private static array $vectors;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
        self::$vectors = json_decode((string)file_get_contents(__DIR__ . '/../fixtures/agent-vectors.json'), true);
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    private function client(): Touchque
    {
        return new Touchque(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    private function agent(string $id, $key, ?string $kid = null): TouchqueAgent
    {
        return new TouchqueAgent($id, $key, $kid, self::$api->baseUrl);
    }

    public function testThumbprintAndAthVectors(): void
    {
        foreach (self::$vectors['thumbprints'] as $v) {
            $this->assertSame($v['thumbprint'], AgentKeys::thumbprint($v['jwk']));
        }
        foreach (self::$vectors['ath'] as $v) {
            $this->assertSame($v['ath'], AgentKeys::b64url(hash('sha256', $v['accessToken'], true)));
        }
    }

    public function testGenerate(): void
    {
        $ec = AgentKeys::generate();
        $this->assertSame('ES256', $ec['publicJwk']['alg']);
        $this->assertSame(AgentKeys::thumbprint($ec['publicJwk']), $ec['publicJwk']['kid']);
        $this->assertArrayNotHasKey('d', $ec['publicJwk']);
        $this->assertSame('Ed25519', AgentKeys::generate('EdDSA')['publicJwk']['crv']);
    }

    public function testManagementCallVectors(): void
    {
        $tq = $this->client();
        $k1 = AgentKeys::generate();
        $k2 = AgentKeys::generate('EdDSA');
        $id = '';
        $ag = $tq->agents;
        foreach (self::$vectors['calls'] as $v) {
            $a = $v['args'];
            switch ($v['name']) {
                case 'create':
                    $id = $ag->create($a['name'], $a['allowedTypes'], ['publicKey' => $k1['publicJwk'], 'ownerEmail' => $a['ownerEmail'], 'platform' => $a['platform'], 'reviewInDays' => $a['reviewInDays']])['id'];
                    break;
                case 'list': $ag->list($a['status']); break;
                case 'get': $ag->get($id); break;
                case 'update': $ag->update($id, ['reviewInDays' => $a['reviewInDays'], 'description' => $a['description']]); break;
                case 'addKey': $ag->addKey($id, $k2['publicJwk']); break;
                case 'removeKey': $ag->removeKey($id, $k2['publicJwk']['kid']); break;
                case 'suspend': $ag->suspend($id, $a['reason']); break;
                case 'resume': $ag->resume($id); break;
                case 'setPolicy': $ag->setPolicy($id, $a['policy']); break;
                case 'getWorkspacePolicy': $ag->getWorkspacePolicy(); break;
                case 'listEvents': $ag->listEvents($a['after'], null, $a['limit']); break;
                case 'setWorkspacePolicy': $ag->setWorkspacePolicy($a['policy']); break;
                case 'listBlocks': $ag->listBlocks($id); break;
                case 'killSwitch': $ag->setKillSwitch($a['engaged'], $a['reason']); break;
                case 'killSwitchOff': $ag->setKillSwitch($a['engaged']); break;
                case 'revoke': $ag->revoke($id); break;
            }
            $calls = self::$api->calls();
            $call = end($calls);
            $want = json_decode(strtr(json_encode($v, JSON_UNESCAPED_SLASHES), [
                '"{publicKey}"' => json_encode($k1['publicJwk'], JSON_UNESCAPED_SLASHES),
                '"{publicKey2}"' => json_encode($k2['publicJwk'], JSON_UNESCAPED_SLASHES),
                '{id}' => $id,
                '{kid}' => rawurlencode($k2['publicJwk']['kid']),
            ]), true);
            $this->assertSame($want['method'], $call['method'], $v['name']);
            $this->assertSame($want['path'], $call['path'], $v['name']);
            if (isset($want['query'])) {
                $this->assertSame($want['path'] . '?' . $want['query'], $call['url']);
            }
            if (isset($want['body'])) {
                $this->assertEquals($want['body'], $call['body'], $v['name']);
            }
        }
        $this->expectException(TouchqueConfigException::class);
        $ag->create('x', ['LOGIN'], ['publicKey' => $k1['privateJwk']]);
    }

    public function testAgentSignsInWithItsOwnKey(): void
    {
        $tq = $this->client();
        foreach (['ES256', 'EdDSA'] as $alg) {
            $keys = AgentKeys::generate($alg);
            $created = $tq->agents->create("agent $alg", ['LOGIN'], ['publicKey' => $keys['publicJwk']]);
            foreach ([$keys['privateJwk'], json_encode($keys['privateJwk'])] as $privateKey) {
                $me = $this->agent($created['id'], $privateKey)->me();
                $this->assertSame($created['id'], $me['agent']['id']);
                $this->assertSame('agent:read approvals:request approvals:read vault:read', $me['scope']);
            }
        }
        // An EC key as PEM too
        $keys = AgentKeys::generate();
        $created = $tq->agents->create('pem', ['LOGIN'], ['publicKey' => $keys['publicJwk']]);
        $pem = AgentKeys::ecPem(AgentKeys::b64urlDecode($keys['privateJwk']['d']), AgentKeys::b64urlDecode($keys['privateJwk']['x']), AgentKeys::b64urlDecode($keys['privateJwk']['y']));
        $this->assertSame($created['id'], $this->agent($created['id'], $pem)->me()['agent']['id']);
    }

    public function testTokenVault(): void
    {
        $tq = $this->client();
        $keys = AgentKeys::generate();
        $created = $tq->agents->create('calendar', ['LOGIN'], ['publicKey' => $keys['publicJwk']]);
        $agent = $this->agent($created['id'], $keys['privateJwk']);
        $conn = $tq->agents->vault->putConnection('google', ['provider' => 'google', 'clientId' => 'acme.apps.googleusercontent.com', 'clientSecret' => 'g-secret', 'agentIds' => [$created['id']]]);
        $this->assertTrue($conn['hasClientSecret']);
        $tq->agents->vault->deposit('google', 'jane@example.com', ['accessToken' => 'ya29.jane', 'refreshToken' => '1//jane', 'expiresIn' => 3599, 'scope' => 'calendar.readonly']);
        $this->assertStringNotContainsString('ya29', json_encode($tq->agents->vault->listAccounts('jane@example.com')));
        $this->assertSame(['access_token' => 'ya29.jane', 'token_type' => 'Bearer', 'expires_in' => 3599, 'scope' => 'calendar.readonly', 'connection' => 'google'], $agent->getConnectionToken('jane@example.com', 'google'));
        try {
            $agent->getConnectionToken('john@example.com', 'google');
            $this->fail('expected not_connected');
        } catch (\Touchque\Exceptions\TouchqueAPIException $e) {
            $this->assertSame('not_connected', $e->getErrorCode());
        }
        $tq->agents->vault->removeAccount('google', 'jane@example.com');
        $this->assertSame(['removed' => true, 'tokensDeleted' => 0], $tq->agents->vault->removeConnection('google'));
    }

    public function testTokenIsReused(): void
    {
        $tq = $this->client();
        $keys = AgentKeys::generate();
        $created = $tq->agents->create('reuse', ['LOGIN'], ['publicKey' => $keys['publicJwk']]);
        $count = static fn () => count(array_filter(self::$api->calls(), static fn ($c) => $c['path'] === '/agents/token'));
        $before = $count();
        $agent = $this->agent($created['id'], $keys['privateJwk']);
        $agent->me();
        $agent->me();
        $this->assertSame(1, $count() - $before);
    }

    public function testRefusalsCarryTheReason(): void
    {
        $tq = $this->client();
        $keys = AgentKeys::generate();
        $created = $tq->agents->create('refused', ['LOGIN'], ['publicKey' => $keys['publicJwk']]);
        $agent = $this->agent($created['id'], $keys['privateJwk']);
        $agent->me();
        $tq->agents->suspend($created['id'], 'looping');
        try {
            $agent->me();
            $this->fail('expected a refusal');
        } catch (TouchqueAPIException $e) {
            $this->assertSame(403, $e->getStatus());
            $this->assertSame('agent_blocked', $e->getErrorCode());
            $this->assertSame('suspended', $e->getReason());
        }
        try {
            $this->agent($created['id'], $keys['privateJwk'])->me();
            $this->fail('expected a refusal');
        } catch (TouchqueAPIException $e) {
            $this->assertSame('unauthorized_client', $e->getErrorCode());
            $this->assertSame('suspended', $e->getReason());
        }
        $tq->agents->resume($created['id']);
        $stranger = AgentKeys::generate();
        try {
            $this->agent($created['id'], $stranger['privateJwk'], $keys['publicJwk']['kid'])->me();
            $this->fail('expected a refusal');
        } catch (TouchqueAPIException $e) {
            $this->assertSame(401, $e->getStatus());
            $this->assertSame('invalid_client', $e->getErrorCode());
        }
        $tq->agents->setKillSwitch(true, 'incident');
        try {
            $agent->me();
            $this->fail('expected a refusal');
        } catch (TouchqueAPIException $e) {
            $this->assertSame('workspace_paused', $e->getReason());
        }
        $tq->agents->setKillSwitch(false);
        $this->assertSame($created['id'], $agent->me()['agent']['id']);
    }

    public function testConfigurationErrors(): void
    {
        $key = AgentKeys::generate()['privateJwk'];
        foreach ([['nope', $key, null], ['agt_abcdefghijkmnpqrstuv', 'not a key', null], ['agt_abcdefghijkmnpqrstuv', $key, 'http://api.example.com']] as [$id, $k, $url]) {
            try {
                new TouchqueAgent($id, $k, null, $url);
                $this->fail('expected a configuration error');
            } catch (TouchqueConfigException $e) {
                $this->assertNotEmpty($e->getMessage());
            }
        }
    }

    public function testApprovalTokenVectors(): void
    {
        $v = self::$vectors['approvalToken'];
        $claims = ApprovalToken::verifyWith($v['token'], $v['jwks'], $v['audience'], [], $v['verifyAt']);
        $this->assertSame($v['claims']['sub'], $claims['sub']);
        $own = $v['audience'];
        foreach ([[$v['tampered'], $own, $v['verifyAt']], [$v['wrongType'], $own, $v['verifyAt']], [$v['token'], 'touchque:workspace:other', $v['verifyAt']], [$v['token'], $own, $v['claims']['exp'] + 60]] as [$token, $aud, $at]) {
            try {
                ApprovalToken::verifyWith($token, $v['jwks'], $aud, [], $at);
                $this->fail('expected a refusal');
            } catch (TouchqueApprovalMismatchException $e) {
                $this->assertNotEmpty($e->getMessage());
            }
        }
        // The audience is required, and a token without aud is refused.
        foreach ([
            [$v['token'], $v['jwks'], 'touchque:workspace:other', 'another workspace'],
            [$v['token'], $v['jwks'], null, 'audience is required'],
            [$v['token'], $v['jwks'], '', 'audience is required'],
            [$v['noAudience']['token'], $v['noAudience']['jwks'], $own, 'names no workspace'],
        ] as [$token, $jwks, $aud, $want]) {
            try {
                ApprovalToken::verifyWith($token, $jwks, $aud, [], $v['verifyAt']);
                $this->fail('expected a refusal: ' . $want);
            } catch (TouchqueApprovalMismatchException $e) {
                $this->assertStringContainsString($want, $e->getMessage());
            }
        }
        foreach (self::$vectors['matching'] as $m) {
            $this->assertSame($m['matches'], ApprovalToken::matches($v['claims']['authorization_details'], $m['expect']), $m['name']);
        }
    }

    public function testAskWaitRedeem(): void
    {
        $tq = $this->client();
        $user = 'agent-approvals@example.com';
        self::$api->link($user);
        $tq->actionTypes->define('PAY_INVOICE', null, null, false);
        $keys = AgentKeys::generate();
        $created = $tq->agents->create('Invoice bot', ['PAY_INVOICE'], ['publicKey' => $keys['publicJwk']]);
        $agent = $this->agent($created['id'], $keys['privateJwk']);
        $payment = self::$vectors['approvalToken']['claims']['authorization_details'][0];

        $ask = $agent->requestApproval($user, 'PAY_INVOICE', [$payment], ['reason' => 'October rent']);
        $this->assertSame('pending', $ask['status']);
        $this->assertSame('47', $ask['challengeCode']);
        self::$api->approve($ask['approvalId']);
        $token = $agent->waitForApproval($ask['approvalId'], 10, 0.5)['approvalToken'];
        // requireApproval: ask and wait in one call, the number shown while the phone waits.
        $shown = null;
        $required = $agent->requireApproval($user, 'PAY_INVOICE', [$payment], [], function (array $s) use (&$shown) {
            $shown = $s['challengeCode'];
            self::$api->approve($s['approvalId']);
        }, 10);
        $this->assertSame('47', $shown);
        $this->assertNotEmpty($required['approvalToken']);

        // The workspace's own audience comes from GET /agents/approval-audience; another one is refused.
        $this->assertSame('touchque:workspace:fake-workspace', $tq->agents->approvalAudience());
        $claims = $tq->agents->verifyApprovalToken($token, null, ['user' => $user, 'authorizationDetails' => $payment]);
        $this->assertSame($created['id'], $claims['act']['sub']);
        try {
            $tq->agents->verifyApprovalToken($token, 'touchque:workspace:other');
            $this->fail('expected another workspace');
        } catch (TouchqueApprovalMismatchException $e) {
            $this->assertStringContainsString('another workspace', $e->getMessage());
        }
        try {
            $tq->agents->redeemApproval($token, ['authorizationDetails' => array_merge($payment, ['instructedAmount' => ['currency' => 'TRY', 'amount' => '5000.00']])]);
            $this->fail('expected a mismatch');
        } catch (TouchqueApprovalMismatchException $e) {
            $this->assertStringContainsString('differ', $e->getMessage());
        }
        $approval = $tq->agents->redeemApproval($token, ['user' => $user, 'type' => 'PAY_INVOICE', 'authorizationDetails' => ['type' => 'payment_initiation', 'instructedAmount' => ['currency' => 'try', 'amount' => '500']]]);
        $this->assertSame($ask['approvalId'], $approval['id']);
        try {
            $tq->agents->redeemApproval($token);
            $this->fail('expected already_redeemed');
        } catch (TouchqueAPIException $e) {
            $this->assertSame('already_redeemed', $e->getErrorCode());
        }

        $ask2 = $agent->requestApproval($user, 'PAY_INVOICE', [$payment], ['presence' => 'background']);
        $this->assertArrayNotHasKey('challengeCode', $ask2);
        self::$api->reject($ask2['approvalId']);
        try {
            $agent->waitForApproval($ask2['approvalId'], 10, 0.5);
            $this->fail('expected a rejection');
        } catch (TouchqueApprovalException $e) {
            $this->assertSame('rejected', $e->getStatus());
        }
    }

    public function testBlocksListedAndLifted(): void
    {
        $tq = $this->client();
        $keys = AgentKeys::generate();
        $a = $tq->agents->create('blocked', ['LOGIN'], ['publicKey' => $keys['publicJwk']]);
        $ch = curl_init(self::$api->baseUrl . '/__test/agent-block');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode(['agentId' => $a['id'], 'user' => 'jane@example.com']), CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ['Content-Type: application/json']]);
        curl_exec($ch);
        $this->assertSame('not_me', $tq->agents->listBlocks($a['id'])[0]['reason']);
        $tq->agents->liftBlock($a['id'], 'jane@example.com');
        $calls = self::$api->calls();
        $this->assertSame("/agents/{$a['id']}/blocks/jane%40example.com", end($calls)['path']);
        $this->assertSame([], $tq->agents->listBlocks($a['id']));
    }

    public function testMandates(): void
    {
        $tq = $this->client();
        $user = 'agent-mandates@example.com';
        self::$api->link($user);
        $tq->actionTypes->define('PAY_INVOICE', null, null, false);
        $keys = AgentKeys::generate();
        $created = $tq->agents->create('Mandate bot', ['PAY_INVOICE'], ['publicKey' => $keys['publicJwk']]);
        $agent = $this->agent($created['id'], $keys['privateJwk']);
        $payment = self::$vectors['approvalToken']['claims']['authorization_details'][0];
        $mandate = $agent->requestMandate($user, 'PAY_INVOICE', 2, ['currency' => 'TRY', 'amount' => '1000'], ['validFor' => 3600]);
        $this->assertSame('pending', $mandate['status']);
        $requests = json_decode((string)file_get_contents(self::$api->baseUrl . '/__test/requests'), true);
        self::$api->approve(end($requests)['id']);
        $this->assertSame('active', $agent->getMandate($mandate['mandateId'])['status']);
        $used = $agent->requestApproval($user, 'PAY_INVOICE', [$payment], ['mandateId' => $mandate['mandateId']]);
        $this->assertSame('approved', $used['status']);
        $this->assertSame(1, $used['mandate']['usedCount']);
        $this->assertSame($mandate['mandateId'], $tq->agents->listMandates($created['id'], $user)[0]['mandateId']);
        $this->assertSame('revoked', $tq->agents->revokeMandate($created['id'], $mandate['mandateId'])['status']);
        try {
            $agent->requestApproval($user, 'PAY_INVOICE', [$payment], ['mandateId' => $mandate['mandateId']]);
            $this->fail('expected mandate_revoked');
        } catch (TouchqueAPIException $e) {
            $this->assertSame('mandate_revoked', $e->getErrorCode());
        }
    }
}
