<?php

namespace Touchque\Http;

use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Exceptions\TouchqueFeatureException;
use Touchque\Exceptions\TouchqueNetworkException;

class HttpClient
{
    private const SDK_VERSION = '5.0.0';
    private Config $config;

    /** @internal The SDK's own log (silent unless the Config has a logger or debug). */
    public function log(string $level, string $message): void
    {
        $this->config->log($level, $message);
    }

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function post(string $endpoint, array $body): array
    {
        return $this->send('POST', $endpoint, self::encode($body));
    }

    public function put(string $endpoint, array $body): array
    {
        return $this->send('PUT', $endpoint, self::encode($body));
    }

    public function patch(string $endpoint, array $body): array
    {
        return $this->send('PATCH', $endpoint, self::encode($body));
    }

    /** JSON with `{}` for an empty body (never `[]`). */
    private static function encode(array $body): string
    {
        $bodyStr = json_encode($body === [] ? new \stdClass() : $body);
        if ($bodyStr === false) {
            throw new \InvalidArgumentException('Invalid JSON body provided.');
        }
        return $bodyStr;
    }

    public function get(string $endpoint, array $params = []): array
    {
        $pathWithQuery = $endpoint . self::buildQuery($params);
        return $this->send('GET', $pathWithQuery, '');
    }

    /** A GET whose answer is a file (CSV or JSON lines), returned as text. */
    public function getText(string $endpoint): string
    {
        return $this->send('GET', $endpoint, '', true);
    }

    public function delete(string $endpoint): array
    {
        return $this->send('DELETE', $endpoint, '');
    }

    /** Deterministic query string: keys sorted, booleans as `true`/`false`, `?`-prefixed (or ''). */
    private static function buildQuery(array $params): string
    {
        $params = array_filter($params, static fn ($v) => $v !== null);
        if (empty($params)) {
            return '';
        }
        ksort($params);
        // http_build_query() would send 1/0, which the API reads as no filter at all.
        $params = array_map(static fn ($v) => is_bool($v) ? ($v ? 'true' : 'false') : $v, $params);
        return '?' . http_build_query($params);
    }

    /** @return array|string the decoded JSON, or the body as text when $asText */
    private function send(string $method, string $pathWithQuery, string $bodyStr, bool $asText = false)
    {
        $url = $this->config->getBaseUrl() . $pathWithQuery;
        $timestamp = (string)(time() * 1000);
        $nonce = bin2hex(random_bytes(16));
        $signature = $this->signRequest($method, $pathWithQuery, $bodyStr, $timestamp, $nonce);

        $headers = [
            'x-api-key: ' . $this->config->getApiKey(),
            'x-signature: ' . $signature,
            'x-timestamp: ' . $timestamp,
            'x-nonce: ' . $nonce,
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: touchque-php-sdk/' . self::SDK_VERSION,
        ];

        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT_MS => $this->config->getTimeout(),
            // An API endpoint should never redirect; following one could replay
            // the signed auth headers to another host.
            CURLOPT_FOLLOWLOCATION => false,
        ];
        if ($method === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $bodyStr;
        } elseif ($method === 'PUT' || $method === 'PATCH') {
            $opts[CURLOPT_CUSTOMREQUEST] = $method;
            $opts[CURLOPT_POSTFIELDS] = $bodyStr;
        } elseif ($method === 'DELETE') {
            $opts[CURLOPT_CUSTOMREQUEST] = 'DELETE';
        }
        curl_setopt_array($ch, $opts);

        $raw = curl_exec($ch);
        $error = curl_error($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        if (\PHP_VERSION_ID < 80000) {
            curl_close($ch); // no-op + deprecated on PHP >= 8.0
        }

        if ($error || $raw === false) {
            throw new TouchqueNetworkException('Network error: ' . $error);
        }

        $headerText = substr($raw, 0, $headerSize);
        $body = substr($raw, $headerSize);
        $responseData = json_decode($body, true) ?? [];

        // A redirect is not followed (see above) and is never an answer: a 3xx is an error too, or a
        // wrong baseUrl would read as an empty success.
        if ($statusCode >= 300) {
            $errorMessage = $responseData['error'] ?? $responseData['message']
                ?? ($statusCode < 400 ? "Unexpected redirect (HTTP {$statusCode}) from the API: check the baseUrl" : 'Unknown API Error');
            $retryAfter = $responseData['retryAfter'] ?? self::readRetryAfterHeader($headerText);
            if ($retryAfter !== null) {
                $responseData['retryAfter'] = (int)$retryAfter;
            }
            throw TouchqueFeatureException::fromResponse($errorMessage, $statusCode, $responseData);
        }

        return $asText ? $body : $responseData;
    }

    private static function readRetryAfterHeader(string $headerText): ?int
    {
        if (preg_match('/^Retry-After:\s*(\d+)/mi', $headerText, $m)) {
            return (int)$m[1];
        }
        return null;
    }

    private function signRequest(string $method, string $pathWithQuery, string $body, string $timestamp, string $nonce): string
    {
        $bodyHash = hash('sha256', $body);
        $message = strtoupper($method) . ':' . $pathWithQuery . ':' . $timestamp . ':' . $nonce . ':' . $bodyHash;
        return hash_hmac('sha256', $message, $this->config->getApiSecret());
    }
}
