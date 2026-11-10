<?php

namespace TouchQue;

/**
 * A code the person types back on the phone (`$tq->login->request(..., reply: [...])`): a sign-in
 * code another service sent them (a text message, WhatsApp, e-mail). Each request gets a one-time
 * P-256 key pair; its public key goes with the request, the phone encrypts what was typed to it,
 * and only you can open it: TouchQue stores and hands back nothing but the ciphertext
 * (`$tq->login->status($requestId)['reply']['ct']`).
 *
 * ECDH P-256, HKDF-SHA256 (salt: the request id, info `touchque-code-reply-v1`), AES-256-GCM
 * (additional data `touchque-code-reply:<request id>`), as
 * `v1.<the phone's one-time key, x9.63>.<nonce|ciphertext|tag>`, base64url. Needs ext-openssl.
 */
final class CodeReply
{
    private const INFO = 'touchque-code-reply-v1';
    /** SubjectPublicKeyInfo prefix of an uncompressed P-256 point. */
    private const SPKI_P256 = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /**
     * A one-time key pair for one request: send `publicKey` (the uncompressed P-256 point,
     * base64url) as the reply's `key`, keep `privateKey` (PKCS#8 DER, base64url) server-side.
     *
     * @return array{publicKey: string, privateKey: string}
     */
    public static function newKey(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new Exceptions\TouchQueConfigException('Could not make a P-256 key (is ext-openssl built with EC?)');
        }
        $ec = openssl_pkey_get_details($key)['ec'];
        $point = "\x04" . str_pad($ec['x'], 32, "\0", STR_PAD_LEFT) . str_pad($ec['y'], 32, "\0", STR_PAD_LEFT);
        return ['publicKey' => self::b64($point), 'privateKey' => self::b64(self::pkcs8($pem))];
    }

    /**
     * The PKCS#8 DER of an exported P-256 key. Before PHP 8.1 openssl_pkey_export() writes an EC
     * key in the SEC1 form (`EC PRIVATE KEY`), which open() could not read back: wrap it.
     */
    private static function pkcs8(string $pem): string
    {
        $der = (string)base64_decode(preg_replace('/-----[A-Z ]+-----|\s/', '', $pem));
        if (strpos($pem, '-----BEGIN EC PRIVATE KEY-----') === false) {
            return $der;
        }
        // PrivateKeyInfo: version 0, AlgorithmIdentifier (id-ecPublicKey, prime256v1), the SEC1 key.
        $info = hex2bin('020100301306072a8648ce3d020106082a8648ce3d030107') . "\x04" . self::derLength(strlen($der)) . $der;
        return "\x30" . self::derLength(strlen($info)) . $info;
    }

    private static function derLength(int $length): string
    {
        return $length < 0x80 ? chr($length) : ($length < 0x100 ? "\x81" . chr($length) : "\x82" . pack('n', $length));
    }

    /** The code the person typed, or null when `$ct` does not open with this key for this request. */
    public static function open(string $privateKey, string $requestId, string $ct): ?string
    {
        if (!preg_match('/^v1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/', $ct, $m)) {
            return null;
        }
        $epk = self::unb64($m[1]);
        $box = self::unb64($m[2]);
        if (strlen($epk) !== 65 || $epk[0] !== "\x04" || strlen($box) < 12 + 16 + 1) {
            return null;
        }
        $priv = openssl_pkey_get_private(self::pem('PRIVATE KEY', self::unb64($privateKey)));
        $peer = openssl_pkey_get_public(self::pem('PUBLIC KEY', hex2bin(self::SPKI_P256) . $epk));
        if ($priv === false || $peer === false) {
            return null;
        }
        $shared = openssl_pkey_derive($peer, $priv, 32);
        if ($shared === false) {
            return null;
        }
        $key = hash_hkdf('sha256', $shared, 32, self::INFO, $requestId);
        $code = openssl_decrypt(substr($box, 12, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($box, 0, 12), substr($box, -16),
            'touchque-code-reply:' . $requestId);
        if ($code === false) {
            return null;
        }
        $code = trim($code);
        return preg_match('/^[A-Za-z0-9 -]{4,20}$/', $code) ? $code : null;
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN {$label}-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END {$label}-----\n";
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function unb64(string $text): string
    {
        return (string)base64_decode(strtr($text, '-_', '+/'), false);
    }
}
