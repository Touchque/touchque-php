<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Exceptions\TouchqueIdJagException;

/**
 * Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
 * draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
 * organization's identity provider (Touchque SSO) decides which of its apps
 * may reach which other service for its members; the app trades a member's ID
 * token for an ID-JAG there, then the ID-JAG for an access token at the other
 * service's authorization server, with no consent screen per member.
 *
 *   $jag = CrossAppAccess::requestIdJag(['issuer' => 'https://sso.touchque.com', 'clientId' => $id, 'clientSecret' => $secret,
 *                                        'idToken' => $idToken, 'audience' => 'https://auth.files.example']);
 *   $tokens = CrossAppAccess::redeemIdJag(['tokenEndpoint' => 'https://auth.files.example/token', 'clientId' => 'acme',
 *                                          'clientSecret' => $filesSecret, 'assertion' => $jag['assertion']]);
 *
 * Your own authorization server takes them with IdJagVerifier.
 */
final class CrossAppAccess
{
    public const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
    public const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
    public const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    /** @internal https, or http on this machine (tests). */
    public static function safeUrl(string $url): bool
    {
        $u = parse_url($url);
        $host = $u['host'] ?? '';
        return ($u['scheme'] ?? '') === 'https' || (($u['scheme'] ?? '') === 'http' && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true));
    }

    /** @internal The identity provider's OpenID configuration, checked against its issuer. */
    public static function discover(string $issuer): array
    {
        $meta = McpAuth::getJson(rtrim($issuer, '/') . '/.well-known/openid-configuration');
        if (($meta['issuer'] ?? null) !== $issuer) {
            throw new TouchqueConfigException("the identity provider's metadata does not match its issuer");
        }
        return $meta;
    }

    private static function postForm(string $url, array $form, ?array $basic): array
    {
        if (!self::safeUrl($url)) {
            throw new TouchqueConfigException("{$url} must be an https URL");
        }
        $headers = ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'];
        if ($basic !== null) {
            $headers[] = 'Authorization: Basic ' . base64_encode(rawurlencode($basic[0]) . ':' . rawurlencode($basic[1]));
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false, CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query(array_filter($form, static fn ($v) => $v !== null), '', '&', PHP_QUERY_RFC3986),
            CURLOPT_HTTPHEADER => $headers,
        ]);
        $raw = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $data = is_string($raw) ? (json_decode($raw, true) ?? []) : [];
        if ($raw === false || $status >= 400) {
            throw new TouchqueIdJagException((string)($data['error'] ?? 'server_error'), (string)($data['error_description'] ?? "{$url} answered {$status}"), $status ?: null);
        }
        return $data;
    }

    private static function scopeText($scope): ?string
    {
        return is_array($scope) ? implode(' ', $scope) : $scope;
    }

    /**
     * Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic).
     * Options: issuer or tokenEndpoint, clientId, clientSecret, idToken, audience, resource?, scope?.
     * Returns ['assertion' => …, 'expiresIn' => …, 'scope' => …].
     */
    public static function requestIdJag(array $o): array
    {
        $endpoint = $o['tokenEndpoint'] ?? null;
        if (!$endpoint) {
            if (empty($o['issuer'])) {
                throw new TouchqueConfigException('requestIdJag needs issuer or tokenEndpoint');
            }
            $endpoint = self::discover($o['issuer'])['token_endpoint'] ?? null;
            if (!is_string($endpoint)) {
                throw new TouchqueConfigException('the identity provider names no token_endpoint');
            }
        }
        $data = self::postForm($endpoint, [
            'grant_type' => self::TOKEN_EXCHANGE_GRANT, 'requested_token_type' => self::ID_JAG_TOKEN_TYPE,
            'subject_token' => $o['idToken'] ?? '', 'subject_token_type' => self::ID_TOKEN_TYPE, 'audience' => $o['audience'] ?? '',
            'resource' => $o['resource'] ?? null, 'scope' => self::scopeText($o['scope'] ?? null),
        ], [$o['clientId'] ?? '', $o['clientSecret'] ?? '']);
        if (($data['issued_token_type'] ?? null) !== self::ID_JAG_TOKEN_TYPE || !is_string($data['access_token'] ?? null)) {
            throw new TouchqueIdJagException('invalid_response', 'the identity provider did not answer with an ID-JAG');
        }
        return ['assertion' => $data['access_token'], 'expiresIn' => $data['expires_in'] ?? null, 'scope' => $data['scope'] ?? null];
    }

    /**
     * Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer).
     * Options: tokenEndpoint, clientId, clientSecret?, assertion, resource?, scope?.
     */
    public static function redeemIdJag(array $o): array
    {
        $secret = $o['clientSecret'] ?? null;
        return self::postForm($o['tokenEndpoint'] ?? '', [
            'grant_type' => self::JWT_BEARER_GRANT, 'assertion' => $o['assertion'] ?? '',
            'resource' => $o['resource'] ?? null, 'scope' => self::scopeText($o['scope'] ?? null),
            'client_id' => $secret ? null : ($o['clientId'] ?? ''),
        ], $secret ? [$o['clientId'] ?? '', $secret] : null);
    }
}
