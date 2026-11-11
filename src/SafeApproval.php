<?php

namespace Touchque;

use Touchque\Exceptions\TouchqueConfigException;

/**
 * Safe Guard approvals, checked without trusting Touchque. The approver's phone decodes the raw
 * Safe transaction itself and signs, with a P-256 key only its biometrics unlock, a 105-byte
 * approval that TouchqueSafeGuard checks on chain:
 *
 *   index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)
 *
 * over the SHA-256 of the 149-byte message
 *
 *   "TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20) | subject (32) | expiresAt (8) | displayDigest (32)
 *
 * where subject is the Safe transaction hash (EIP-712, purpose 1 `approve`) or, for a change the
 * guard schedules, the governance hash (purpose 2 `schedule`). `verify()` makes the guard's check
 * off chain: both hashes are computed here from the raw fields, so a co-signer (or your own
 * server) refuses an approval of anything else, whoever relayed it. Needs ext-openssl to verify.
 *
 * A target is `['chainId' => ..., 'safe' => ..., 'guard' => ..., 'tx' => ['to', 'value', 'data',
 * 'operation', 'safeTxGas', 'baseGas', 'gasPrice', 'gasToken', 'refundReceiver', 'nonce']]`;
 * large integers as decimal strings.
 */
final class SafeApproval
{
    private const MAGIC = 'TQG1';
    private const PURPOSES = ['approve' => 1, 'schedule' => 2];
    /** The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day. */
    private const MAX_APPROVAL_TTL = 86400;
    /** OpenZeppelin P256 (the guard) refuses s above N/2. */
    private const HALF_N = '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8';
    /** SubjectPublicKeyInfo prefix of an uncompressed P-256 point. */
    private const SPKI_P256 = '3059301306072a8648ce3d020106082a8648ce3d030107034200';
    private const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
    private const RC = [
        '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000', '000000000000808b', '0000000080000001',
        '8000000080008081', '8000000000008009', '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
        '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003', '8000000000008002', '8000000000000080',
        '000000000000800a', '800000008000000a', '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
    ];
    /** Rotation of lane x + 5y. */
    private const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

    /** The Safe transaction hash (EIP-712, domain = chainId + the Safe): what the owners sign and an ordinary approval covers. */
    public static function safeTxHash(array $target): string
    {
        $t = self::target($target);
        $domain = self::keccak256(self::keccak256('EIP712Domain(uint256 chainId,address verifyingContract)') . $t['chainId'] . self::pad($t['safe']));
        $struct = self::keccak256(
            self::keccak256('SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)')
            . self::pad($t['to']) . $t['value'] . self::keccak256($t['data']) . $t['operation'] . $t['safeTxGas'] . $t['baseGas']
            . $t['gasPrice'] . self::pad($t['gasToken']) . self::pad($t['refundReceiver']) . $t['nonce']
        );
        return '0x' . bin2hex(self::keccak256("\x19\x01" . $domain . $struct));
    }

    /** What the guard schedules a governance change under: the change itself, without the nonce or gas fields. */
    public static function governanceHash(array $target): string
    {
        $t = self::target($target);
        return '0x' . bin2hex(self::keccak256(
            self::keccak256('TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)')
            . $t['chainId'] . self::pad($t['safe']) . self::pad($t['to']) . $t['value'] . self::keccak256($t['data']) . $t['operation']
        ));
    }

    /**
     * The 149-byte message the phone signs (its SHA-256 is what the guard verifies), as 0x hex.
     *
     * @param string $purpose 'approve' or 'schedule'
     * @param int|string $chainId
     * @param int|string $expiresAt Unix seconds
     */
    public static function message(string $purpose, $chainId, string $guard, string $safe, string $subject, $expiresAt, string $displayDigest): string
    {
        if (!isset(self::PURPOSES[$purpose])) {
            throw new TouchqueConfigException("SafeApproval: purpose is 'approve' or 'schedule'.");
        }
        return '0x' . bin2hex(
            self::MAGIC . chr(self::PURPOSES[$purpose]) . self::uint($chainId, 'chainId', 8, 32) . self::address($guard, 'guard')
            . self::address($safe, 'safe') . self::hex($subject, 'subject', 32) . self::uint($expiresAt, 'expiresAt', 8, 8)
            . self::hex($displayDigest, 'displayDigest', 32)
        );
    }

    /**
     * SHA-256 of the rows as "label\x1Fvalue" joined by "\x1E" (UTF-8), as 0x hex: the digest an approval carries.
     *
     * @param array<array{label: string, value: string}> $rows
     */
    public static function displayDigest(array $rows): string
    {
        $parts = [];
        foreach ($rows as $row) {
            $parts[] = $row['label'] . "\x1F" . $row['value'];
        }
        return '0x' . hash('sha256', implode("\x1E", $parts));
    }

    /**
     * Checks a phone's Safe Guard approval the way TouchqueSafeGuard does, without trusting the
     * server that relayed it. The key comes from the guard's approver list on chain: `x || y`
     * (128 hex characters) or `['x' => ..., 'y' => ...]`.
     *
     * Options: `purpose` ('approve', the default: an ordinary transaction for `execTransaction`; or
     * 'schedule': a change the guard time-locks, which must be named, since the governance hash
     * covers no nonce or gas fields), `approverIndex` (the approval must name it), `displayDigest` or
     * `rows` (from your own decoding: the rows the phone must have shown), `now` (Unix seconds or a
     * DateTimeInterface).
     *
     * Returns `['valid', 'reason', 'purpose', 'approverIndex', 'expiresAt', 'displayDigest',
     * 'safeTxHash', 'governanceHash']`; `reason` is null when valid, else `approval_malformed`,
     * `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s`
     * or `signature_invalid`. Throws only when `$target` is not a Safe transaction.
     *
     *     $status = $tq->safeGuard->status($requestId);
     *     $check = SafeApproval::verify($myTx, $status['safeTx']['approval'], $approverKeyFromChain, ['approverIndex' => 0]);
     *     if (!$check['valid']) throw new RuntimeException("approval refused: {$check['reason']}");
     *
     * @param string|array $publicKey
     */
    public static function verify(array $target, $approval, $publicKey, array $options = []): array
    {
        $t = self::target($target);
        $hashes = ['safeTxHash' => self::safeTxHash($target), 'governanceHash' => self::governanceHash($target)];
        $parsed = ['approverIndex' => null, 'expiresAt' => null, 'displayDigest' => null];
        $refuse = function (string $reason) use (&$parsed, $hashes): array {
            return ['valid' => false, 'reason' => $reason, 'purpose' => null] + $parsed + $hashes;
        };
        if (!is_string($approval) || !preg_match('/^(0x)?[0-9a-fA-F]{210}$/', $approval)) {
            return $refuse('approval_malformed');
        }
        $b = hex2bin(self::strip0x($approval));
        $expires = substr($b, 1, 8);
        $expiresAt = unpack('J', $expires)[1];
        $parsed = ['approverIndex' => ord($b[0]), 'expiresAt' => $expiresAt, 'displayDigest' => '0x' . bin2hex(substr($b, 9, 32))];
        $key = self::publicKey($publicKey);
        if ($key === null) {
            return $refuse('public_key_invalid');
        }
        if (isset($options['approverIndex']) && (int) $options['approverIndex'] !== $parsed['approverIndex']) {
            return $refuse('approver_index_mismatch');
        }
        $now = self::seconds($options['now'] ?? null);
        // An expiry above PHP_INT_MAX reads as negative: expired.
        if ($expiresAt < $now || $expiresAt > $now + self::MAX_APPROVAL_TTL) {
            return $refuse('approval_expired');
        }
        $expected = $options['displayDigest'] ?? (isset($options['rows']) ? self::displayDigest($options['rows']) : null);
        if ($expected !== null && '0x' . strtolower(self::strip0x((string) $expected)) !== $parsed['displayDigest']) {
            return $refuse('rows_differ');
        }
        $r = substr($b, 41, 32);
        $s = substr($b, 73, 32);
        if (strcmp($s, hex2bin(self::HALF_N)) > 0) {
            return $refuse('high_s');
        }
        $der = self::derInteger($r) . self::derInteger($s);
        $der = "\x30" . chr(strlen($der)) . $der;
        // Only the purpose asked for: an approval to schedule a change is never one to execute.
        $purpose = $options['purpose'] ?? 'approve';
        $message = self::message(
            $purpose, self::wordToDecimal($t['chainId']), '0x' . bin2hex($t['guard']), '0x' . bin2hex($t['safe']),
            $purpose === 'approve' ? $hashes['safeTxHash'] : $hashes['governanceHash'], (string) $expiresAt, $parsed['displayDigest']
        );
        if (openssl_verify(hex2bin(substr($message, 2)), $der, $key, OPENSSL_ALGO_SHA256) === 1) {
            return ['valid' => true, 'reason' => null, 'purpose' => $purpose] + $parsed + $hashes;
        }
        return $refuse('signature_invalid');
    }

    /**
     * The owners' Safe signatures with the approvals appended (approvals by index | count | "TQG1"):
     * the `signatures` argument of `execTransaction` for an ordinary transaction.
     *
     * @param string[] $approvals
     */
    public static function withApprovals(string $ownerSignatures, array $approvals): string
    {
        $items = self::approvals($approvals);
        return '0x' . bin2hex(self::hex($ownerSignatures, 'ownerSignatures') . implode('', $items) . chr(count($items)) . self::MAGIC);
    }

    /**
     * The call data of `guard.schedule(safe, governanceHash, approvals)`, which starts a governance change's waiting time.
     *
     * @param string[] $approvals
     */
    public static function scheduleCall(string $safe, string $governanceHash, array $approvals): string
    {
        $joined = implode('', self::approvals($approvals));
        $padding = str_repeat("\0", (32 - strlen($joined) % 32) % 32);
        return '0x' . bin2hex(
            substr(self::keccak256('schedule(address,bytes32,bytes)'), 0, 4) . self::pad(self::address($safe, 'safe'))
            . self::hex($governanceHash, 'governanceHash', 32) . self::uint(96, 'offset', 32, 32)
            . self::uint(strlen($joined), 'length', 32, 32) . $joined . $padding
        );
    }

    // ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) on 64-bit lanes ──

    private static function rotl(int $v, int $n): int
    {
        return $n === 0 ? $v : (($v << $n) | (($v >> (64 - $n)) & ~(-1 << $n)));
    }

    private static function keccak256(string $data): string
    {
        static $rc = null;
        if ($rc === null) {
            $rc = array_map(function (string $h): int {
                return unpack('J', hex2bin($h))[1];
            }, self::RC);
        }
        $rate = 136;
        $padded = $data . str_repeat("\0", $rate - strlen($data) % $rate);
        $padded[strlen($data)] = chr(ord($padded[strlen($data)]) ^ 0x01);
        $last = strlen($padded) - 1;
        $padded[$last] = chr(ord($padded[$last]) ^ 0x80);
        $a = array_fill(0, 25, 0);
        for ($off = 0, $n = strlen($padded); $off < $n; $off += $rate) {
            for ($k = 0; $k < 17; $k++) {
                $a[$k] ^= unpack('P', substr($padded, $off + 8 * $k, 8))[1];
            }
            foreach ($rc as $round) {
                $c = [];
                for ($x = 0; $x < 5; $x++) {
                    $c[$x] = $a[$x] ^ $a[$x + 5] ^ $a[$x + 10] ^ $a[$x + 15] ^ $a[$x + 20];
                }
                for ($x = 0; $x < 5; $x++) {
                    $d = $c[($x + 4) % 5] ^ self::rotl($c[($x + 1) % 5], 1);
                    for ($y = 0; $y < 25; $y += 5) {
                        $a[$x + $y] ^= $d;
                    }
                }
                $b = [];
                for ($x = 0; $x < 5; $x++) {
                    for ($y = 0; $y < 5; $y++) {
                        $b[$y + 5 * ((2 * $x + 3 * $y) % 5)] = self::rotl($a[$x + 5 * $y], self::ROT[$x + 5 * $y]);
                    }
                }
                for ($y = 0; $y < 25; $y += 5) {
                    for ($x = 0; $x < 5; $x++) {
                        $a[$x + $y] = $b[$x + $y] ^ (~$b[($x + 1) % 5 + $y] & $b[($x + 2) % 5 + $y]);
                    }
                }
                $a[0] ^= $round;
            }
        }
        return pack('P', $a[0]) . pack('P', $a[1]) . pack('P', $a[2]) . pack('P', $a[3]);
    }

    // ── Field parsing: the partner's own data, so a wrong field throws ──

    private static function target(array $target): array
    {
        $tx = $target['tx'] ?? null;
        if (!is_array($tx)) {
            throw new TouchqueConfigException("SafeApproval: pass ['chainId', 'safe', 'guard', 'tx' => ['to', 'value', 'data', 'operation', ..., 'nonce']].");
        }
        $operation = $tx['operation'] ?? 0;
        if ($operation !== 0 && $operation !== 1) {
            throw new TouchqueConfigException('SafeApproval: tx.operation must be 0 (call) or 1 (delegatecall).');
        }
        return [
            'chainId' => self::uint($target['chainId'] ?? null, 'chainId', 8, 32),
            'safe' => self::address($target['safe'] ?? null, 'safe'),
            'guard' => self::address($target['guard'] ?? null, 'guard'),
            'to' => self::address($tx['to'] ?? null, 'tx.to'),
            'value' => self::uint($tx['value'] ?? 0, 'tx.value', 32, 32),
            'data' => self::hex($tx['data'] ?? '0x', 'tx.data'),
            'operation' => self::uint($operation, 'tx.operation', 1, 32),
            'safeTxGas' => self::uint($tx['safeTxGas'] ?? 0, 'tx.safeTxGas', 32, 32),
            'baseGas' => self::uint($tx['baseGas'] ?? 0, 'tx.baseGas', 32, 32),
            'gasPrice' => self::uint($tx['gasPrice'] ?? 0, 'tx.gasPrice', 32, 32),
            'gasToken' => self::address($tx['gasToken'] ?? self::ZERO_ADDRESS, 'tx.gasToken'),
            'refundReceiver' => self::address($tx['refundReceiver'] ?? self::ZERO_ADDRESS, 'tx.refundReceiver'),
            'nonce' => self::uint($tx['nonce'] ?? null, 'tx.nonce', 32, 32),
        ];
    }

    /**
     * A non-negative integer (int or decimal string) as `$size` big-endian bytes, at most `$maxBytes` significant.
     *
     * @param mixed $value
     */
    private static function uint($value, string $field, int $maxBytes, int $size): string
    {
        $dec = is_int($value) && $value >= 0 ? (string) $value : (is_string($value) ? $value : '');
        if (!preg_match('/^(0|[1-9][0-9]*)$/', $dec)) {
            throw new TouchqueConfigException("SafeApproval: $field must be a non-negative integer (a decimal string for large values).");
        }
        $bytes = '';
        while ($dec !== '0') {
            $rem = 0;
            $quotient = '';
            for ($i = 0, $n = strlen($dec); $i < $n; $i++) {
                $cur = $rem * 10 + (ord($dec[$i]) - 48);
                $digit = intdiv($cur, 256);
                $rem = $cur % 256;
                if ($quotient !== '' || $digit > 0) {
                    $quotient .= chr(48 + $digit);
                }
            }
            $bytes = chr($rem) . $bytes;
            $dec = $quotient === '' ? '0' : $quotient;
        }
        if (strlen($bytes) > $maxBytes) {
            throw new TouchqueConfigException("SafeApproval: $field is too large.");
        }
        return str_pad($bytes, $size, "\0", STR_PAD_LEFT);
    }

    /** A 32-byte word as a decimal string (for the chain id, at most 8 bytes). */
    private static function wordToDecimal(string $word): string
    {
        $v = unpack('J', substr($word, 24, 8))[1];
        return $v >= 0 ? (string) $v : sprintf('%u', $v);
    }

    /** @param mixed $value */
    private static function address($value, string $field): string
    {
        if (!is_string($value) || !preg_match('/^0x[0-9a-fA-F]{40}$/', $value)) {
            throw new TouchqueConfigException("SafeApproval: $field must be an address (0x and 40 hex characters).");
        }
        return hex2bin(substr($value, 2));
    }

    /** @param mixed $value */
    private static function hex($value, string $field, ?int $size = null): string
    {
        if (!is_string($value) || !preg_match('/^0x([0-9a-fA-F]{2})*$/', $value) || ($size !== null && strlen($value) !== 2 + 2 * $size)) {
            throw new TouchqueConfigException("SafeApproval: $field must be 0x-prefixed hex" . ($size !== null ? " of $size bytes." : '.'));
        }
        return (string) hex2bin(substr($value, 2));
    }

    private static function pad(string $b): string
    {
        return str_pad($b, 32, "\0", STR_PAD_LEFT);
    }

    private static function strip0x(string $s): string
    {
        return strncmp($s, '0x', 2) === 0 ? substr($s, 2) : $s;
    }

    /** @return string[] */
    private static function approvals(array $approvals): array
    {
        if (count($approvals) < 1 || count($approvals) > 255) {
            throw new TouchqueConfigException('SafeApproval: pass 1 to 255 approvals.');
        }
        $out = [];
        foreach (array_values($approvals) as $i => $a) {
            $out[] = self::hex(is_string($a) && strncmp($a, '0x', 2) !== 0 ? "0x$a" : $a, "approvals[$i]", 105);
        }
        usort($out, function (string $a, string $b): int {
            return ord($a[0]) <=> ord($b[0]);
        });
        return $out;
    }

    /**
     * @param string|array $key
     * @return \OpenSSLAsymmetricKey|resource|null
     */
    private static function publicKey($key)
    {
        $xy = is_array($key)
            ? self::strip0x((string) ($key['x'] ?? '')) . self::strip0x((string) ($key['y'] ?? ''))
            : self::strip0x((string) $key);
        if (!preg_match('/^[0-9a-fA-F]{128}$/', $xy)) {
            return null;
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(hex2bin(self::SPKI_P256 . '04' . $xy)), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        return $key === false ? null : $key;
    }

    private static function derInteger(string $b): string
    {
        $b = ltrim($b, "\0");
        if ($b === '' || (ord($b[0]) & 0x80)) {
            $b = "\0" . $b;
        }
        return "\x02" . chr(strlen($b)) . $b;
    }

    /** @param mixed $now */
    private static function seconds($now): int
    {
        if ($now instanceof \DateTimeInterface) {
            return $now->getTimestamp();
        }
        return $now === null ? time() : (int) $now;
    }
}
