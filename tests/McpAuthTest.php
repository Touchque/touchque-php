<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\AgentKeys;
use TouchQue\Exceptions\TouchQueMcpAuthException;
use TouchQue\McpAuth;

/**
 * McpAuth (an MCP server whose authorization server is TouchQue SSO) against
 * the shared fake API's MCP issuer: metadata, audience, issuer, expiry, scopes
 * per tool, DPoP-bound tokens and their proofs.
 */
class McpAuthTest extends TestCase
{
    private const RESOURCE = 'https://mcp.acme.example/mcp';
    private static FakeApi $api;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        self::$api->close();
    }

    private function token(array $claims = []): string
    {
        return self::$api->post('/__test/mcp-token', $claims + ['aud' => self::RESOURCE, 'scope' => 'tickets:read'])['token'];
    }

    private function auth(): McpAuth
    {
        return new McpAuth(['issuer' => self::$api->baseUrl . '/mcp-as', 'resource' => self::RESOURCE, 'tools' => ['search_tickets' => 'tickets:read', 'delete_ticket' => 'tickets:delete']]);
    }

    private function refused(callable $fn): TouchQueMcpAuthException
    {
        try {
            $fn();
        } catch (TouchQueMcpAuthException $e) {
            return $e;
        }
        $this->fail('expected a refusal');
    }

    public function testMetadataTokensAndScopes(): void
    {
        $auth = $this->auth();
        $this->assertSame(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], $auth->metadataPaths());
        $this->assertSame([self::$api->baseUrl . '/mcp-as'], $auth->protectedResourceMetadata()['authorization_servers']);
        $claims = $auth->verify('POST', self::RESOURCE, ['Authorization' => 'Bearer ' . $this->token()]);
        $this->assertSame(['user-1', ['tickets:read'], false, 'https://tool.example/client.json'], [$claims['sub'], $claims['scopes'], $claims['dpopBound'], $claims['clientId']]);
        $auth->requireTool($claims, 'search_tickets');
        $e = $this->refused(fn () => $auth->requireTool($claims, 'delete_ticket'));
        $this->assertSame(403, $e->status);
        $this->assertStringContainsString('scope="tickets:delete"', $e->wwwAuthenticate);
        $e = $this->refused(fn () => $auth->verify('POST', self::RESOURCE, []));
        $this->assertSame([401, 'Bearer resource_metadata="https://mcp.acme.example/.well-known/oauth-protected-resource/mcp"'], [$e->status, $e->wwwAuthenticate]);
        foreach ([['aud' => 'https://other.example/mcp'], ['iss' => 'https://evil.example/mcp'], ['expiresIn' => -120], ['typ' => 'JWT']] as $bad) {
            $e = $this->refused(fn () => $auth->verify('POST', self::RESOURCE, ['Authorization' => 'Bearer ' . $this->token($bad)]));
            $this->assertSame('invalid_token', $e->error);
        }
    }

    public function testDpopBound(): void
    {
        $auth = $this->auth();
        $keys = AgentKeys::generate();
        $jwk = $keys['publicJwk'];
        unset($jwk['kid'], $jwk['alg']);
        $token = $this->token(['jkt' => AgentKeys::thumbprint($jwk)]);
        $d = AgentKeys::b64urlDecode($keys['privateJwk']['d']);
        $pem = AgentKeys::ecPem($d, AgentKeys::b64urlDecode($jwk['x']), AgentKeys::b64urlDecode($jwk['y']));
        $proof = function (string $htu = self::RESOURCE) use ($jwk, $token, $pem): string {
            $h = AgentKeys::b64url(json_encode(['typ' => 'dpop+jwt', 'alg' => 'ES256', 'jwk' => $jwk]));
            $p = AgentKeys::b64url(json_encode(['htm' => 'POST', 'htu' => $htu, 'iat' => time(), 'jti' => bin2hex(random_bytes(12)), 'ath' => AgentKeys::b64url(hash('sha256', $token, true))], JSON_UNESCAPED_SLASHES));
            openssl_sign("{$h}.{$p}", $der, $pem, OPENSSL_ALGO_SHA256);
            return "{$h}.{$p}." . AgentKeys::b64url(AgentKeys::derToRaw($der));
        };
        $this->refused(fn () => $auth->verify('POST', self::RESOURCE, ['Authorization' => 'Bearer ' . $token]));
        $good = $proof();
        $this->assertTrue($auth->verify('POST', self::RESOURCE, ['Authorization' => 'DPoP ' . $token, 'DPoP' => $good])['dpopBound']);
        $this->assertSame('invalid_dpop_proof', $this->refused(fn () => $auth->verify('POST', self::RESOURCE, ['Authorization' => 'DPoP ' . $token, 'DPoP' => $good]))->error);
        $this->refused(fn () => $auth->verify('POST', self::RESOURCE, ['Authorization' => 'DPoP ' . $token, 'DPoP' => $proof('https://other.example/mcp')]));
    }
}
