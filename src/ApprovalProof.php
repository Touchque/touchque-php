<?php

namespace TouchQue;

/**
 * Verifies the device-signed proof of an approval ("what you see is what you
 * sign"). When the user's phone holds a hardware key (Secure Enclave /
 * Android Keystore), every approval is signed by it over the request id, the
 * action type, the number-match code and a digest of the transaction details
 * the user was shown. The proof arrives in the SUCCESS webhook
 * (`approvalProof`) and in `login->status($id)['approvalProof']`. Verifying it
 * does not require trusting TouchQue: it proves the enrolled phone signed
 * exactly these details. Needs ext-openssl.
 */
final class ApprovalProof
{
    private const MESSAGE_PREFIX = 'touchque-approve:v2';
    /** DER SubjectPublicKeyInfo header for an uncompressed P-256 (prime256v1) point. */
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /**
     * Returns true only if `$proof` was signed by the device key over exactly
     * the request, action type, challenge code and details you expect.
     *
     * Options:
     *  - requestId (string, required): the id login->request() returned
     *  - type (string, required): the action type you sent, e.g. 'WITHDRAW'
     *  - details (array|null): the details you sent, exactly as you sent them
     *  - challengeCode (string|null): the number-match code, when used
     *  - expectedPublicKey (string|null): pin the device — the base64 public
     *    key you stored for this user (e.g. `$proof['publicKey']` of their
     *    first verified approval). Required unless allowUnpinnedKey is true.
     *  - allowUnpinnedKey (bool): accept whatever key the proof carries.
     *    Without a pin the proof only shows that *some* key signed these
     *    details. Only for trust-on-first-use: store the key, pin it after.
     *
     * Fails closed and never throws for malformed input; returns false.
     *
     * @param array<string, mixed>|null $proof
     * @param array<string, mixed> $options
     */
    public static function verify(?array $proof, array $options): bool
    {
        if (!function_exists('openssl_verify')) {
            throw new \RuntimeException('ApprovalProof::verify needs the openssl PHP extension (ext-openssl).');
        }
        try {
            if ($proof === null || ($proof['version'] ?? null) !== 'v2' || ($proof['algorithm'] ?? null) !== 'ECDSA-P256-SHA256') {
                return false;
            }
            $publicKey = $proof['publicKey'] ?? null;
            $message = $proof['message'] ?? null;
            $signature = $proof['signature'] ?? null;
            if (!is_string($publicKey) || !is_string($message) || !is_string($signature)) {
                return false;
            }
            $expectedKey = $options['expectedPublicKey'] ?? null;
            if (is_string($expectedKey) && $expectedKey !== '') {
                if (!hash_equals($expectedKey, $publicKey)) {
                    return false;
                }
            } elseif (($options['allowUnpinnedKey'] ?? false) !== true) {
                return false;
            }

            $expectedMessage = implode("\n", [
                self::MESSAGE_PREFIX,
                (string)($options['requestId'] ?? ''),
                (string)($options['type'] ?? ''),
                isset($options['challengeCode']) ? (string)$options['challengeCode'] : '',
                Steps::detailsDigest($options['details'] ?? null),
            ]);
            if (!hash_equals($expectedMessage, $message)) {
                return false;
            }

            $raw = base64_decode($publicKey, true);
            if ($raw === false || strlen($raw) !== 65 || $raw[0] !== "\x04") {
                return false;
            }
            $der = hex2bin(self::P256_SPKI_PREFIX) . $raw;
            $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
            $key = @openssl_pkey_get_public($pem);
            if ($key === false) {
                return false; // not a point on P-256
            }
            $sig = base64_decode($signature, true);
            if ($sig === false || $sig === '') {
                return false;
            }
            return @openssl_verify($message, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
