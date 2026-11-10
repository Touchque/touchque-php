<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\AgentKeys;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\TouchQueOrgAgent;

/**
 * An organization's AI agent on TouchQue SSO against the shared fake API's
 * /sso/token: its own key or its platform's token, a DPoP proof, and calls to
 * an app that checks the proof against the token's key.
 */
class OrgAgentTest extends TestCase
{
    private const APP = 'tqapp_paymentsapi0000000000';
    private static FakeApi $api;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    /** @return array{0:int,1:array} */
    private function resource(array $headers): array
    {
        $ch = curl_init(self::$api->baseUrl . '/__test/resource');
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = "{$k}: {$v}";
        }
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $lines]);
        $raw = curl_exec($ch);
        return [(int)curl_getinfo($ch, CURLINFO_HTTP_CODE), json_decode((string)$raw, true) ?? []];
    }

    public function testOwnKeyTokenAndCalls(): void
    {
        $keys = AgentKeys::generate();
        $id = 'oagt_abcdefghijkmnpqrstuv';
        self::$api->post('/__test/org-agent', ['agentId' => $id, 'publicKey' => $keys['publicJwk'], 'audiences' => [self::APP], 'scopes' => ['invoices:read', 'payments:create']]);
        $agent = new TouchQueOrgAgent(['agentId' => $id, 'privateKey' => $keys['privateJwk'], 'issuer' => self::$api->baseUrl]);
        $token = $agent->getToken(['scope' => 'invoices:read']);
        $this->assertSame(['DPoP', 300, 'invoices:read'], [$token['tokenType'], $token['expiresIn'], $token['scope']]);
        $this->assertSame($token, $agent->getToken(['scope' => 'invoices:read']));
        $headers = $agent->authorization('GET', self::$api->baseUrl . '/__test/resource', ['scope' => 'invoices:read']);
        [$status, $body] = $this->resource($headers);
        $this->assertSame(200, $status);
        $this->assertSame(['ok' => true, 'sub' => $id, 'aud' => self::APP, 'via' => 'key'], $body);
        $this->assertSame(401, $this->resource($headers)[0]); // a proof is for one request
        try {
            $agent->getToken(['scope' => 'payments:refund']);
            $this->fail('expected invalid_scope');
        } catch (TouchQueAPIException $e) {
            $this->assertSame('invalid_scope', $e->getErrorCode());
        }
    }

    public function testPlatformToken(): void
    {
        $id = 'oagt_bbbbbbbbbbbbbbbbbbbb';
        self::$api->post('/__test/org-agent', ['agentId' => $id, 'workload' => ['subject' => 'repo:acme/payments:ref:refs/heads/main', 'audience' => 'touchque'], 'audiences' => [self::APP], 'scopes' => ['invoices:read']]);
        $api = self::$api;
        $agent = new TouchQueOrgAgent(['agentId' => $id, 'issuer' => $api->baseUrl, 'assertion' => static fn () => $api->post('/__test/workload-token', ['sub' => 'repo:acme/payments:ref:refs/heads/main', 'aud' => 'touchque'])['token']]);
        [, $body] = $this->resource($agent->authorization('GET', $api->baseUrl . '/__test/resource'));
        $this->assertSame('workload', $body['via']);
        $wrong = new TouchQueOrgAgent(['agentId' => $id, 'issuer' => $api->baseUrl, 'assertion' => static fn () => $api->post('/__test/workload-token', ['sub' => 'repo:evil/x', 'aud' => 'touchque'])['token']]);
        $this->expectException(TouchQueAPIException::class);
        $wrong->getToken();
    }

    public function testForAMember(): void
    {
        $keys = AgentKeys::generate();
        $id = 'oagt_cccccccccccccccccccc';
        self::$api->post('/__test/org-agent', ['agentId' => $id, 'publicKey' => $keys['publicJwk'], 'audiences' => [self::APP], 'scopes' => ['payments:create'], 'delegation' => ['token_exchange', 'ciba']]);
        $agent = new TouchQueOrgAgent(['agentId' => $id, 'privateKey' => $keys['privateJwk'], 'issuer' => self::$api->baseUrl]);
        $url = self::$api->baseUrl . '/__test/resource';
        $call = fn (string $t): array => $this->resource(['Authorization' => 'DPoP ' . $t, 'DPoP' => $agent->dpopProof('GET', $url, $t)])[1];
        $exchanged = $agent->exchangeToken('member:ada@acme.com');
        $this->assertSame('ada@acme.com', $call($exchanged['accessToken'])['sub']);
        $google = $agent->getConnectionToken('member:ada@acme.com', 'google', 'email');
        $this->assertSame(['accessToken' => 'ya29.ada@acme.com', 'tokenType' => 'Bearer', 'expiresIn' => 3599, 'scope' => 'email', 'connection' => 'google'], $google);
        try {
            $agent->getConnectionToken('member:ada@acme.com', 'github');
            $this->fail('expected invalid_grant');
        } catch (TouchQueAPIException $e) {
            $this->assertSame('invalid_grant', $e->getErrorCode());
        }

        $payment = ['type' => 'payment_initiation', 'instructedAmount' => ['currency' => 'TRY', 'amount' => '500.00']];
        $ask = $agent->askMember('ada@acme.com', ['bindingMessage' => 'Pay invoice 42', 'authorizationDetails' => [$payment]]);
        $this->assertSame(['42', 1], [$ask['bindingCode'], $ask['interval']]);
        self::$api->post('/__test/ciba-answer', ['authReqId' => $ask['authReqId'], 'approve' => true]);
        $approved = $agent->waitForMember($ask);
        $this->assertSame([$payment], $approved['authorizationDetails']);
        $this->assertSame($id, $call($approved['accessToken'])['act']);

        // A shared account: the member's extension opens it; the agent learns only how it ended.
        self::$api->post('/__test/org-agent', ['agentId' => $id, 'publicKey' => $keys['publicJwk'], 'audiences' => [self::APP], 'scopes' => ['payments:create'], 'delegation' => ['token_exchange', 'ciba'], 'sharedAccounts' => ['k3JInstagramAcme01']]);
        $shared = $agent->askToOpenSharedAccount('k3JInstagramAcme01', 'ada@acme.com', 'Post the launch photo');
        $this->assertSame('waiting_member', $shared['status']);
        $this->assertStringContainsString('/agent-ask?ask=' . $shared['askId'], $shared['openUrl']);
        self::$api->post('/__test/shared-ask-answer', ['askId' => $shared['askId'], 'status' => 'declined']);
        $this->assertSame(['status' => 'declined', 'reason' => null, 'caseCode' => null], $agent->waitForSharedAccount($shared, 50));

        $no = $agent->askMember('ada@acme.com');
        self::$api->post('/__test/ciba-answer', ['authReqId' => $no['authReqId'], 'approve' => false]);
        try {
            $agent->waitForMember($no);
            $this->fail('expected access_denied');
        } catch (TouchQueAPIException $e) {
            $this->assertSame('access_denied', $e->getErrorCode());
        }
    }

    public function testConfigurationMistakes(): void
    {
        $this->expectException(TouchQueConfigException::class);
        new TouchQueOrgAgent(['agentId' => 'oagt_abcdefghijkmnpqrstuv', 'issuer' => 'http://sso.example.com', 'assertion' => static fn () => 'x']);
    }
}
