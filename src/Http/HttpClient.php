<?php

namespace TouchQue\Http;

use TouchQue\Config;
use TouchQue\Exceptions\TouchQueAPIException;
use TouchQue\Exceptions\TouchQueNetworkException;

class HttpClient
{
    private const SDK_VERSION = '2.0.0';

    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function post(string $endpoint, array $body): array
    {
        $bodyStr = json_encode($body);
        if ($bodyStr === false) {
            throw new \InvalidArgumentException('Invalid JSON body provided.');
        }
        return $this->send('POST', $endpoint, $bodyStr);
    }

    public function get(string $endpoint, array $params = []): array
    {
        $pathWithQuery = $endpoint . self::buildQuery($params);
        return $this->send('GET', $pathWithQuery, '');
    }

    public function delete(string $endpoint): array
    {
        return $this->send('DELETE', $endpoint, '');
    }

    /** Deterministic query string: keys sorted, `?`-prefixed (or ''). */
    private static function buildQuery(array $params): string
    {
        $params = array_filter($params, static fn ($v) => $v !== null);
        if (empty($params)) {
            return '';
        }
        ksort($params);
        return '?' . http_build_query($params);
    }

    private function send(string $method, string $pathWithQuery, string $bodyStr): array
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
            throw new TouchQueNetworkException('Network error: ' . $error);
        }

        $headerText = substr($raw, 0, $headerSize);
        $body = substr($raw, $headerSize);
        $responseData = json_decode($body, true) ?? [];

        if ($statusCode >= 400) {
            $errorMessage = $responseData['error'] ?? $responseData['message'] ?? 'Unknown API Error';
            $retryAfter = $responseData['retryAfter'] ?? self::readRetryAfterHeader($headerText);
            if ($retryAfter !== null) {
                $responseData['retryAfter'] = (int)$retryAfter;
            }
            throw new TouchQueAPIException($errorMessage, $statusCode, $responseData);
        }

        return $responseData;
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
