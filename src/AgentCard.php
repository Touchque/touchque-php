<?php

namespace TouchQue;

use TouchQue\Exceptions\TouchQueAgentCardException;

/**
 * A2A agent card signatures (A2A 1.0 §8.4): before your agent trusts another
 * agent's card (its name, URL, skills), check that whoever controls its keys
 * signed exactly this card. Each entry of `signatures` is a JWS (RFC 7515)
 * over the card in RFC 8785 canonical form without `signatures`; the
 * protected header names alg, kid and optionally jku (where the keys are).
 *
 *   $json = file_get_contents('https://agent.example/.well-known/agent-card.json');
 *   AgentCard::verify($json, ['cardUrl' => 'https://agent.example/.well-known/agent-card.json']);
 *
 * Pass the card as the raw JSON you received (an empty {} and [] look the same
 * in a PHP array). Keys come from 'keys' (a JWKS you trust) or from the
 * header's jku, but jku is only followed on the card's own host (or a host in
 * 'trustedJkuHosts'): a card that points at keys on a host of its choosing
 * proves nothing. Signers must leave out fields at their default values (A2A
 * §8.4.1); the card is checked as received.
 */
final class AgentCard
{
    private const FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS;

    /** A number as ECMAScript's Number::toString writes it (RFC 8785 §3.2.2.3). */
    public static function esNumber(float $value): string
    {
        if (is_nan($value) || is_infinite($value)) {
            throw new TouchQueAgentCardException('malformed', 'a number is not finite');
        }
        if ($value == 0.0) {
            return '0';
        }
        $sign = $value < 0 ? '-' : '';
        $old = ini_get('serialize_precision');
        ini_set('serialize_precision', '-1');
        $text = json_encode(abs($value));
        ini_set('serialize_precision', (string)$old);
        [$mantissa, $exp] = array_pad(preg_split('/[eE]/', (string)$text), 2, '0');
        [$int, $frac] = array_pad(explode('.', $mantissa), 2, '');
        $digits = $int . $frac;
        $n = strlen($int) + (int)$exp;
        $trimmed = ltrim($digits, '0');
        $n -= strlen($digits) - strlen($trimmed);
        $digits = rtrim($trimmed, '0');
        $k = strlen($digits);
        if ($k <= $n && $n <= 21) {
            $out = $digits . str_repeat('0', $n - $k);
        } elseif (0 < $n && $n <= 21) {
            $out = substr($digits, 0, $n) . '.' . substr($digits, $n);
        } elseif (-6 < $n && $n <= 0) {
            $out = '0.' . str_repeat('0', -$n) . $digits;
        } else {
            $x = $n - 1;
            $out = $digits[0] . ($k > 1 ? '.' . substr($digits, 1) : '') . 'e' . ($x >= 0 ? '+' : '-') . abs($x);
        }
        return $sign . $out;
    }

    private static function utf16(string $s): string
    {
        return mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    /** RFC 8785 (JSON Canonicalization Scheme) of a value decoded with json_decode($json, false). */
    public static function canonicalJson($value): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_string($value)) {
            return json_encode($value, self::FLAGS);
        }
        if (is_int($value)) {
            return (string)$value;
        }
        if (is_float($value)) {
            return self::esNumber($value);
        }
        if (is_array($value) && ($value === [] || array_keys($value) === range(0, count($value) - 1))) {
            return '[' . implode(',', array_map([self::class, 'canonicalJson'], $value)) . ']';
        }
        if (is_object($value) || is_array($value)) {
            $o = (array)$value;
            $keys = array_map('strval', array_keys($o));
            usort($keys, static fn ($a, $b) => strcmp(self::utf16($a), self::utf16($b)));
            $parts = [];
            foreach ($keys as $k) {
                $parts[] = json_encode($k, self::FLAGS) . ':' . self::canonicalJson($o[$k]);
            }
            return '{' . implode(',', $parts) . '}';
        }
        throw new TouchQueAgentCardException('malformed', 'cannot canonicalize ' . gettype($value));
    }

    private static function decode(string $json): \stdClass
    {
        $c = json_decode($json, false);
        if (!$c instanceof \stdClass) {
            throw new TouchQueAgentCardException('malformed', 'the card is not a JSON object');
        }
        return $c;
    }

    private static function payload(\stdClass $card): string
    {
        $rest = clone $card;
        unset($rest->signatures);
        return AgentKeys::b64url(self::canonicalJson($rest));
    }

    private static function hostOf(?string $url): ?string
    {
        if (!$url || !CrossAppAccess::safeUrl($url)) {
            return null;
        }
        $u = parse_url($url);
        return $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
    }

    /**
     * Checks the card's signatures: ['kid', 'alg', 'keySource' => 'keys' | 'jku'], or TouchQueAgentCardException.
     * Options: cardUrl?, keys? (a list of JWKs or ['keys' => […]]), trustedJkuHosts?.
     */
    public static function verify(string $cardJson, array $options = []): array
    {
        $c = self::decode($cardJson);
        $sigs = $c->signatures ?? null;
        if (!is_array($sigs) || !$sigs) {
            throw new TouchQueAgentCardException('unsigned', 'the card has no signatures');
        }
        $given = $options['keys']['keys'] ?? ($options['keys'] ?? []);
        $cardHost = self::hostOf($options['cardUrl'] ?? null);
        $payload = self::payload($c);
        $last = new TouchQueAgentCardException('invalid_signature', 'no signature verifies');
        foreach ($sigs as $s) {
            if (!$s instanceof \stdClass || !is_string($s->protected ?? null) || !is_string($s->signature ?? null)) {
                continue;
            }
            $head = json_decode(AgentKeys::b64urlDecode($s->protected), true);
            if (!is_array($head)) {
                continue;
            }
            $alg = $head['alg'] ?? '';
            if (!in_array($alg, ['RS256', 'ES256', 'EdDSA'], true) || !is_string($head['kid'] ?? null) || isset($head['crit'])) {
                continue;
            }
            if (array_key_exists('typ', $head) && $head['typ'] !== 'JOSE') {
                continue;
            }
            $jwk = null;
            foreach ($given as $k) {
                if (($k['kid'] ?? null) === $head['kid']) {
                    $jwk = $k;
                    break;
                }
            }
            $source = 'keys';
            if ($jwk === null && is_string($head['jku'] ?? null)) {
                $jkuHost = self::hostOf($head['jku']);
                if (!$jkuHost || ($jkuHost !== $cardHost && !in_array($jkuHost, $options['trustedJkuHosts'] ?? [], true))) {
                    $last = new TouchQueAgentCardException('untrusted_key', "jku {$head['jku']} is not on the card's host");
                    continue;
                }
                try {
                    foreach ((McpAuth::getJson($head['jku'])['keys'] ?? []) as $k) {
                        if (($k['kid'] ?? null) === $head['kid']) {
                            $jwk = $k;
                            break;
                        }
                    }
                } catch (\Throwable $e) {
                    $last = new TouchQueAgentCardException('keys_unavailable', "the keys at {$head['jku']} could not be read: " . $e->getMessage());
                    continue;
                }
                $source = 'jku';
            }
            if ($jwk === null) {
                if ($last->error === 'invalid_signature') {
                    $last = new TouchQueAgentCardException('untrusted_key', "no trusted key {$head['kid']}");
                }
                continue;
            }
            if (McpAuth::verifySignature($s->protected . '.' . $payload, AgentKeys::b64urlDecode($s->signature), $alg, $jwk)) {
                return ['kid' => $head['kid'], 'alg' => $alg, 'keySource' => $source];
            }
            $last = new TouchQueAgentCardException('invalid_signature', 'the signature does not match the card');
        }
        throw $last;
    }

    /**
     * Signs a card you publish: the card JSON with one more entry in `signatures`.
     * $privateKey is a PEM (EC P-256 or RSA) or, for EdDSA, a 64-byte sodium secret key.
     */
    public static function sign(string $cardJson, string $privateKey, string $kid, ?string $jku = null): string
    {
        $c = self::decode($cardJson);
        if (strlen($privateKey) === 64 && strpos($privateKey, '-----BEGIN') === false && function_exists('sodium_crypto_sign_detached')) {
            $alg = 'EdDSA';
        } else {
            $key = openssl_pkey_get_private($privateKey);
            $type = $key ? (openssl_pkey_get_details($key)['type'] ?? null) : null;
            $alg = $type === OPENSSL_KEYTYPE_EC ? 'ES256' : ($type === OPENSSL_KEYTYPE_RSA ? 'RS256' : null);
            if ($alg === null) {
                throw new TouchQueAgentCardException('malformed', 'the key must be EC P-256, Ed25519 or RSA');
            }
        }
        $protected = AgentKeys::b64url(json_encode(array_filter(['alg' => $alg, 'typ' => 'JOSE', 'kid' => $kid, 'jku' => $jku]), self::FLAGS));
        $input = $protected . '.' . self::payload($c);
        if ($alg === 'EdDSA') {
            $sig = sodium_crypto_sign_detached($input, $privateKey);
        } else {
            openssl_sign($input, $der, $key, OPENSSL_ALGO_SHA256);
            $sig = $alg === 'ES256' ? AgentKeys::derToRaw($der) : $der;
        }
        $c->signatures = array_merge($c->signatures ?? [], [(object)['protected' => $protected, 'signature' => AgentKeys::b64url($sig)]]);
        return json_encode($c, self::FLAGS);
    }
}
