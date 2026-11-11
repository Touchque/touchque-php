<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueConfigException;

/** Key helpers for AI agents (TouchqueAgent): new key pairs, RFC 7638 thumbprints. */
final class AgentKeys
{
    public static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function b64urlDecode(string $text): string
    {
        return (string)base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
    }

    /** RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid). */
    public static function thumbprint(array $jwk): string
    {
        $members = ($jwk['kty'] ?? '') === 'EC'
            ? ['crv' => $jwk['crv'], 'kty' => 'EC', 'x' => $jwk['x'], 'y' => $jwk['y']]
            : ['crv' => $jwk['crv'], 'kty' => $jwk['kty'], 'x' => $jwk['x']];
        return self::b64url(hash('sha256', json_encode($members, JSON_UNESCAPED_SLASHES), true));
    }

    /**
     * A new key pair for an agent: ES256 (P-256, default) or EdDSA (Ed25519).
     * `['privateJwk' => ..., 'publicJwk' => ...]`, kid = the RFC 7638 thumbprint.
     * Register publicJwk; keep privateJwk where the agent runs.
     */
    public static function generate(string $alg = 'ES256'): array
    {
        if ($alg === 'EdDSA') {
            $seed = random_bytes(32);
            $pair = sodium_crypto_sign_seed_keypair($seed);
            $public = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::b64url(sodium_crypto_sign_publickey($pair))];
            $d = $seed;
        } elseif ($alg === 'ES256') {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            $ec = openssl_pkey_get_details($key)['ec'];
            $pad = static fn (string $b): string => str_pad($b, 32, "\0", STR_PAD_LEFT);
            $public = ['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64url($pad($ec['x'])), 'y' => self::b64url($pad($ec['y']))];
            $d = $pad($ec['d']);
        } else {
            throw new TouchqueConfigException('alg must be ES256 or EdDSA');
        }
        $kid = self::thumbprint($public);
        return [
            'privateJwk' => $public + ['d' => self::b64url($d), 'kid' => $kid, 'alg' => $alg],
            'publicJwk' => $public + ['kid' => $kid, 'alg' => $alg],
        ];
    }

    /** A P-256 private key as a SEC1 PEM, for ext-openssl. */
    public static function ecPem(string $d, string $x, string $y): string
    {
        $d = str_pad($d, 32, "\0", STR_PAD_LEFT);
        $der = "\x30\x77\x02\x01\x01\x04\x20" . $d
            . "\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
            . "\xa1\x44\x03\x42\x00\x04" . str_pad($x, 32, "\0", STR_PAD_LEFT) . str_pad($y, 32, "\0", STR_PAD_LEFT);
        return "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n";
    }

    /** A P-256 public key as a SubjectPublicKeyInfo PEM, for ext-openssl. */
    public static function ecPublicPem(string $x, string $y): string
    {
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04"
            . str_pad($x, 32, "\0", STR_PAD_LEFT) . str_pad($y, 32, "\0", STR_PAD_LEFT);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** JOSE's raw r||s as an ECDSA DER signature. */
    public static function rawToDer(string $raw): string
    {
        $int = static function (string $b): string {
            $b = ltrim($b, "\0");
            if ($b === '' || ord($b[0]) & 0x80) {
                $b = "\0" . $b;
            }
            return "\x02" . chr(strlen($b)) . $b;
        };
        $body = $int(substr($raw, 0, 32)) . $int(substr($raw, 32, 32));
        return "\x30" . chr(strlen($body)) . $body;
    }

    /** An ECDSA DER signature as JOSE's raw r||s (64 bytes for P-256). */
    public static function derToRaw(string $der): string
    {
        $pos = 2; // SEQUENCE tag + length (short form for P-256)
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            $len = ord($der[$pos + 1]);
            $int = ltrim(substr($der, $pos + 2, $len), "\0");
            $out .= str_pad($int, 32, "\0", STR_PAD_LEFT);
            $pos += 2 + $len;
        }
        return $out;
    }
}
