<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\AgentCard;
use TouchQue\AgentKeys;
use TouchQue\CrossAppAccess;
use TouchQue\Exceptions\TouchQueAgentCardException;
use TouchQue\Exceptions\TouchQueIdJagException;
use TouchQue\IdJagVerifier;

/**
 * Cross App Access (ID-JAG) and A2A agent card signatures against the shared
 * fake API: an app trades a member's ID token for an ID-JAG at the identity
 * provider and redeems it; an authorization server checks one (issuer,
 * audience, client, expiry, typ, once); a card signed in RFC 8785 form by the
 * fake (JavaScript) verifies here with keys from its own host and fails when
 * changed or pointed elsewhere.
 */
class CrossAppAccessTest extends TestCase
{
    private static FakeApi $api;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    private function verifier(): IdJagVerifier
    {
        return new IdJagVerifier(['issuer' => self::$api->baseUrl . '/idp', 'audience' => 'https://rs.example']);
    }

    private static function reason(callable $fn): string
    {
        try {
            $fn();
            return 'accepted';
        } catch (TouchQueIdJagException $e) {
            return $e->getMessage();
        }
    }

    public function testRequestRedeemAndVerify(): void
    {
        $idp = self::$api->baseUrl . '/idp';
        $jag = CrossAppAccess::requestIdJag(['issuer' => $idp, 'clientId' => 'tqapp_test', 'clientSecret' => 'tqs_test', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example', 'resource' => 'https://rs.example/files']);
        $this->assertSame('files:read', $jag['scope']);
        try {
            CrossAppAccess::requestIdJag(['issuer' => $idp, 'clientId' => 'tqapp_test', 'clientSecret' => 'wrong', 'idToken' => 'idtoken:ada', 'audience' => 'https://rs.example']);
            $this->fail('accepted');
        } catch (TouchQueIdJagException $e) {
            $this->assertSame(['invalid_client', 401], [$e->error, $e->status]);
        }
        $v = $this->verifier();
        $claims = $v->verify($jag['assertion'], 'acme-at-rs');
        $this->assertSame(['ada', 'acme-at-rs', ['files:read'], 'https://rs.example/files'], [$claims['sub'], $claims['clientId'], $claims['scopes'], $claims['resource']]);
        $this->assertSame('already used', self::reason(fn () => $v->verify($jag['assertion'], 'acme-at-rs')));
        $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => self::$api->baseUrl . '/rs/token', 'clientId' => 'acme-at-rs', 'assertion' => $jag['assertion']]);
        $this->assertSame('Bearer', $tokens['token_type']);
    }

    public function testRefusals(): void
    {
        $v = $this->verifier();
        $mint = fn (array $claims = [], ?string $typ = null) => self::$api->post('/__test/id-jag', ['claims' => (object)$claims] + ($typ ? ['typ' => $typ] : []))['assertion'];
        $this->assertSame('issued to another client', self::reason(fn () => $v->verify($mint(), 'someone-else')));
        $this->assertSame('not for this authorization server', self::reason(fn () => $v->verify($mint(['aud' => 'https://evil.example']), 'acme-at-rs')));
        $this->assertSame('not for this authorization server', self::reason(fn () => $v->verify($mint(['aud' => ['https://rs.example', 'https://b.example']]), 'acme-at-rs')));
        $this->assertSame('another issuer', self::reason(fn () => $v->verify($mint(['iss' => 'https://evil.example']), 'acme-at-rs')));
        $this->assertSame('not an ID-JAG (typ oauth-id-jag+jwt)', self::reason(fn () => $v->verify($mint([], 'at+jwt'), 'acme-at-rs')));
        $this->assertSame('expired', self::reason(fn () => $v->verify($mint(['exp' => time() - 600]), 'acme-at-rs')));
        [$h, $b, $s] = explode('.', $mint());
        $forged = AgentKeys::b64url(json_encode(['sub' => 'mallory'] + json_decode(AgentKeys::b64urlDecode($b), true)));
        $this->assertSame('signature does not verify', self::reason(fn () => $v->verify("{$h}.{$forged}.{$s}", 'acme-at-rs')));
    }

    private static function code(callable $fn): string
    {
        try {
            $fn();
            return 'verified';
        } catch (TouchQueAgentCardException $e) {
            return $e->error;
        }
    }

    public function testAgentCards(): void
    {
        $url = self::$api->baseUrl . '/.well-known/agent-card.json';
        $card = file_get_contents($url);
        $this->assertSame(['kid' => 'a2a-1', 'alg' => 'ES256', 'keySource' => 'jku'], AgentCard::verify($card, ['cardUrl' => $url]));
        $this->assertSame('invalid_signature', self::code(fn () => AgentCard::verify(file_get_contents($url . '?tamper=1'), ['cardUrl' => $url])));
        $this->assertSame('untrusted_key', self::code(fn () => AgentCard::verify($card, ['cardUrl' => 'https://agent.example/.well-known/agent-card.json'])));
        $this->assertSame('unsigned', self::code(fn () => AgentCard::verify('{"name":"x"}')));

        $pair = sodium_crypto_sign_keypair();
        $signed = AgentCard::sign('{"name":"Mine","url":"https://mine.example/a2a","skills":[]}', sodium_crypto_sign_secretkey($pair), 'k1');
        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => AgentKeys::b64url(sodium_crypto_sign_publickey($pair)), 'kid' => 'k1'];
        $this->assertSame(['kid' => 'k1', 'alg' => 'EdDSA', 'keySource' => 'keys'], AgentCard::verify($signed, ['keys' => [$jwk]]));
        $this->assertSame('invalid_signature', self::code(fn () => AgentCard::verify(str_replace('mine.example', 'evil.example', $signed), ['keys' => [$jwk]])));

        $value = json_decode('{"€":"Euro","\r":"CR","😀":"smile","1":"one","a":[1e21,1e-7,0.5,-0,"tab\there",1e-5,100.0]}', false);
        $this->assertSame('{"\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\there",0.00001,100],"€":"Euro","😀":"smile"}', AgentCard::canonicalJson($value));
    }
}
