<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\HostedLogin\HostedLogin;
use Touchque\HostedLogin\HostedLoginException;
use Touchque\HostedLogin\MyAccount;
use Touchque\HostedLogin\MyAccountException;

/** Touchque Login client against an in-process fake tenant. */
class HostedLoginTest extends TestCase
{
    private const ISSUER = 'https://acme.login.touchque.com';
    private const CLIENT = 'client-123';
    private static $key;
    private static $other;
    private array $codes = [];
    private array $posts = [];
    private ?string $nonceOverride = null;
    private $signWith = null;

    public static function setUpBeforeClass(): void
    {
        self::$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::$other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    private static function b64u(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    private function jwt(array $payload, string $typ = 'JWT', $key = null): string
    {
        $input = self::b64u(json_encode(['alg' => 'RS256', 'typ' => $typ, 'kid' => 'k1'])) . '.' . self::b64u(json_encode($payload));
        openssl_sign($input, $sig, $key ?? self::$key, OPENSSL_ALGO_SHA256);
        return $input . '.' . self::b64u($sig);
    }

    private function login(array $extra = []): HostedLogin
    {
        return new HostedLogin(array_merge([
            'domain' => self::ISSUER, 'clientId' => self::CLIENT, 'redirectUri' => 'https://app/cb',
            'transport' => function (string $method, string $url, array $headers, ?string $body) {
                $path = parse_url($url, PHP_URL_PATH);
                if ($path === '/.well-known/jwks.json') {
                    $d = openssl_pkey_get_details(self::$key)['rsa'];
                    return [200, json_encode(['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'n' => self::b64u($d['n']), 'e' => self::b64u($d['e'])]]])];
                }
                if ($path === '/oauth/token') {
                    parse_str($body, $f);
                    $this->posts[] = ['fields' => $f, 'headers' => $headers];
                    $now = time();
                    if ($f['grant_type'] === 'authorization_code') {
                        [$challenge, $nonce] = $this->codes[$f['code']] ?? [null, null];
                        if ($challenge !== self::b64u(hash('sha256', $f['code_verifier'], true))) {
                            return [400, json_encode(['error' => 'invalid_grant'])];
                        }
                        $at = $this->jwt(['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => ['https://api.acme.test'], 'exp' => $now + 300, 'iat' => $now, 'client_id' => self::CLIENT, 'scope' => 'openid read:orders'], 'at+jwt');
                        $id = $this->jwt(['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => self::CLIENT, 'exp' => $now + 300, 'iat' => $now, 'nonce' => $this->nonceOverride ?? $nonce, 'email' => 'a@acme.test', 'at_hash' => self::b64u(substr(hash('sha256', $at, true), 0, 16))], 'JWT', $this->signWith);
                        return [200, json_encode(['access_token' => $at, 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'openid', 'id_token' => $id, 'refresh_token' => 'tqr_1'])];
                    }
                    if ($f['grant_type'] === 'refresh_token') {
                        return [200, json_encode(['access_token' => 'x', 'token_type' => 'Bearer', 'expires_in' => 300, 'refresh_token' => 'tqr_2'])];
                    }
                }
                return [404, '{}'];
            },
        ], $extra));
    }

    private function authorize(string $url): array
    {
        parse_str(parse_url($url, PHP_URL_QUERY), $q);
        $code = 'code-' . count($this->codes);
        $this->codes[$code] = [$q['code_challenge'], $q['nonce']];
        return ['code' => $code, 'state' => $q['state']];
    }

    public function testExchangeTokenAndCiba(): void
    {
        $posts = [];
        $polls = 0;
        $login = new HostedLogin([
            'domain' => self::ISSUER, 'clientId' => self::CLIENT, 'clientSecret' => 's3cret',
            'transport' => function (string $method, string $url, array $headers, ?string $body) use (&$posts, &$polls) {
                parse_str((string) $body, $f);
                $posts[] = ['path' => parse_url($url, PHP_URL_PATH), 'fields' => $f, 'headers' => $headers];
                if (parse_url($url, PHP_URL_PATH) === '/bc-authorize') {
                    return [200, json_encode(['auth_req_id' => 'req-1', 'expires_in' => 300, 'interval' => 0, 'binding_code' => '42'])];
                }
                if (($f['requested_token_type'] ?? null) === HostedLogin::CONNECTION_TOKEN_TYPE) {
                    return [200, json_encode(['access_token' => 'ya29.g', 'token_type' => 'Bearer', 'expires_in' => 3500, 'scope' => 'openid email', 'connection' => $f['connection']])];
                }
                if ($f['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange') {
                    return [200, json_encode(['access_token' => 'at-x', 'token_type' => 'Bearer', 'expires_in' => 120, 'issued_token_type' => 'urn:ietf:params:oauth:token-type:access_token'])];
                }
                $polls++;
                if ($polls === 1) {
                    return [400, json_encode(['error' => 'authorization_pending'])];
                }
                if ($f['auth_req_id'] === 'denied') {
                    return [400, json_encode(['error' => 'access_denied'])];
                }
                return [200, json_encode(['access_token' => 'at-c', 'token_type' => 'Bearer', 'expires_in' => 300, 'authorization_details' => [['type' => 'payment_initiation']]])];
            },
        ]);
        $ex = $login->exchangeToken('user-at', 'https://api.acme.test', 'payments:create');
        $this->assertSame(['at-x', 'urn:ietf:params:oauth:token-type:access_token'], [$ex['accessToken'], $ex['issuedTokenType']]);
        $this->assertSame('user-at', $posts[0]['fields']['subject_token']);
        $ask = $login->askUser('ada@acme.test', 'openid payments:create', ['bindingMessage' => 'Pay invoice 42', 'authorizationDetails' => [['type' => 'payment_initiation']]]);
        $this->assertSame(['req-1', '42'], [$ask['authReqId'], $ask['bindingCode']]);
        $this->assertSame([['type' => 'payment_initiation']], json_decode($posts[1]['fields']['authorization_details'], true));
        $approved = $login->waitForUser($ask);
        $this->assertSame([['type' => 'payment_initiation']], $approved['authorizationDetails']);
        $polls = 0;
        try {
            $login->waitForUser(['authReqId' => 'denied'] + $ask);
            $this->fail('expected access_denied');
        } catch (\Touchque\HostedLogin\HostedLoginException $e) {
            $this->assertSame('access_denied', $e->getErrorCode());
        }
        $vaulted = $login->getConnectionToken('user-at', 'google', 'email');
        $this->assertSame(['ya29.g', 'google'], [$vaulted['accessToken'], $vaulted['connection']]);
        $last = end($posts)['fields'];
        $this->assertSame('email', $last['scope']);
        $this->assertArrayNotHasKey('audience', $last);
    }

    public function testAPlaintextIssuerIsRefusedExceptOnThisMachine(): void
    {
        foreach (['http://localhost:4000', 'http://127.0.0.1:4000', 'http://[::1]:4000', 'http://acme.login.localhost:3000'] as $domain) {
            $this->assertSame($domain, (new HostedLogin(['domain' => $domain . '/', 'clientId' => self::CLIENT]))->getIssuer(), $domain);
        }
        $this->assertSame(self::ISSUER, (new HostedLogin(['domain' => 'acme.login.touchque.com', 'clientId' => self::CLIENT]))->getIssuer());
        try {
            new HostedLogin(['domain' => 'http://acme.login.touchque.com', 'clientId' => self::CLIENT]);
            $this->fail('a plaintext issuer must be refused');
        } catch (HostedLoginException $e) {
            $this->assertSame('config', $e->getErrorCode());
        }
        $this->expectException(MyAccountException::class);
        new MyAccount('http://localhost.evil.test', 'at');
    }

    public function testAuthorizationUrl(): void
    {
        $req = (new HostedLogin(['domain' => 'acme.login.touchque.com', 'clientId' => self::CLIENT, 'redirectUri' => 'https://app/cb', 'audience' => 'https://api.acme.test']))->authorizationUrl(['screenHint' => 'signup']);
        parse_str(parse_url($req['url'], PHP_URL_QUERY), $q);
        $this->assertStringStartsWith(self::ISSUER . '/authorize?', $req['url']);
        $this->assertSame(self::b64u(hash('sha256', $req['codeVerifier'], true)), $q['code_challenge']);
        $this->assertSame('S256', $q['code_challenge_method']);
        $this->assertSame($req['state'], $q['state']);
        $this->assertSame('signup', $q['screen_hint']);
        $this->assertSame('https://api.acme.test', $q['audience']);
    }

    public function testCallbackRefreshAccessToken(): void
    {
        $login = $this->login(['clientSecret' => 's3cret']);
        $req = $login->authorizationUrl();
        $got = $this->authorize($req['url']);
        $tokens = $login->handleCallback('https://app/cb?' . http_build_query($got + ['iss' => self::ISSUER]), $req['state'], $req['nonce'], $req['codeVerifier']);
        $this->assertSame('usr_1', $tokens['claims']['sub']);
        $this->assertSame('tqr_1', $tokens['refreshToken']);
        $this->assertContains('Authorization: Basic ' . base64_encode(self::CLIENT . ':s3cret'), $this->posts[0]['headers']);
        $this->assertSame('tqr_2', $login->refresh('tqr_1')['refreshToken']);
        $this->assertSame('usr_1', $login->verifyAccessToken($tokens['accessToken'], 'https://api.acme.test', ['read:orders'])['sub']);
        try {
            $login->verifyAccessToken($tokens['accessToken'], 'https://api.acme.test', ['write:orders']);
            $this->fail('scope');
        } catch (HostedLoginException $e) {
            $this->assertSame('insufficient_scope', $e->getErrorCode());
        }
        $this->expectException(HostedLoginException::class);
        $login->verifyAccessToken($tokens['idToken'], self::CLIENT);
    }

    public function testIssThisIssuerOrNoneIsAcceptedAForeignOrEmptyOneIsRefusedBeforeTheExchange(): void
    {
        $login = $this->login();
        $req = $login->authorizationUrl();
        $got = $this->authorize($req['url']);
        $refused = [];
        foreach (['https://evil', self::ISSUER . '.evil', self::ISSUER . '/', ''] as $iss) {
            $refused[] = $got + ['iss' => $iss];
        }
        $refused[] = 'https://app/cb?' . http_build_query($got) . '&iss=';
        $refused[] = $got + ['iss' => ['https://evil']];
        // A foreign error answer is reported as the issuer mismatch, not as its own error.
        $refused[] = ['error' => 'access_denied', 'state' => $req['state'], 'iss' => 'https://evil'];
        foreach ($refused as $params) {
            try {
                $login->handleCallback($params, $req['state'], $req['nonce'], $req['codeVerifier']);
                $this->fail('issuer_mismatch');
            } catch (HostedLoginException $e) {
                $this->assertSame('issuer_mismatch', $e->getErrorCode());
            }
        }
        $this->assertSame([], $this->posts);
        $this->assertSame('usr_1', $login->handleCallback($got + ['iss' => self::ISSUER], $req['state'], $req['nonce'], $req['codeVerifier'])['claims']['sub']);
        // No iss (an older server), also as a framework's null for a missing field.
        $older = $login->authorizationUrl();
        $this->assertSame('usr_1', $login->handleCallback($this->authorize($older['url']) + ['iss' => null], $older['state'], $older['nonce'], $older['codeVerifier'])['claims']['sub']);
        $older = $login->authorizationUrl();
        $this->assertSame('usr_1', $login->handleCallback('https://app/cb?' . http_build_query($this->authorize($older['url'])), $older['state'], $older['nonce'], $older['codeVerifier'])['claims']['sub']);
    }

    public function testRefusals(): void
    {
        $login = $this->login();
        $req = $login->authorizationUrl();
        $got = $this->authorize($req['url']);
        foreach ([[['code' => $got['code'], 'state' => 'x'], 'state_mismatch'], [['error' => 'access_denied', 'state' => $req['state']], 'access_denied'], [$got + ['iss' => 'https://evil'], 'issuer_mismatch']] as [$params, $code]) {
            try {
                $login->handleCallback($params, $req['state'], $req['nonce'], $req['codeVerifier']);
                $this->fail($code);
            } catch (HostedLoginException $e) {
                $this->assertSame($code, $e->getErrorCode());
            }
        }
        $this->nonceOverride = 'replayed';
        $req2 = $login->authorizationUrl();
        try {
            $login->handleCallback($this->authorize($req2['url']), $req2['state'], $req2['nonce'], $req2['codeVerifier']);
            $this->fail('nonce');
        } catch (HostedLoginException $e) {
            $this->assertSame('nonce_mismatch', $e->getErrorCode());
        }
        $this->nonceOverride = null;
        $this->signWith = self::$other;
        $req3 = $login->authorizationUrl();
        $this->expectExceptionMessage('Bad signature');
        $login->handleCallback($this->authorize($req3['url']), $req3['state'], $req3['nonce'], $req3['codeVerifier']);
    }
}
