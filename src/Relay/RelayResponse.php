<?php

namespace TouchQue\Relay;

/**
 * What RelayHandler wants sent back: an HTTP status, a JSON body and headers.
 * Framework adapters turn it into their own response (see
 * TouchQue\Laravel\TouchQueRelay); in plain PHP call send().
 *
 * `onAuthenticated` receives the pending success response and may change it
 * (e.g. addHeader('Set-Cookie', ...)); the handler sets the body afterwards.
 */
class RelayResponse
{
    private int $status;
    private array $body;
    /** @var array<string, array{name: string, values: string[]}> keyed by lower-case name */
    private array $headers = [];

    public function __construct(int $status = 200, array $body = [], array $headers = [])
    {
        $this->status = $status;
        $this->body = $body;
        foreach ($headers as $name => $value) {
            $this->setHeader((string)$name, (string)$value);
        }
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function setStatus(int $status): self
    {
        $this->status = $status;
        return $this;
    }

    /** The JSON body as an array (always a JSON object on the wire). */
    public function getBody(): array
    {
        return $this->body;
    }

    public function setBody(array $body): self
    {
        $this->body = $body;
        return $this;
    }

    /** Sets a header, replacing any value it had. */
    public function setHeader(string $name, string $value): self
    {
        $this->headers[strtolower($name)] = ['name' => $name, 'values' => [$value]];
        return $this;
    }

    /** Adds a header value, keeping existing ones (e.g. several Set-Cookie). */
    public function addHeader(string $name, string $value): self
    {
        $key = strtolower($name);
        if (!isset($this->headers[$key])) {
            $this->headers[$key] = ['name' => $name, 'values' => []];
        }
        $this->headers[$key]['values'][] = $value;
        return $this;
    }

    /** Case-insensitive; the first value, or null. */
    public function getHeader(string $name): ?string
    {
        return $this->headers[strtolower($name)]['values'][0] ?? null;
    }

    /**
     * @return array<string, string|string[]> name => value (a list when a header has several values)
     */
    public function getHeaders(): array
    {
        $out = [];
        foreach ($this->headers as $h) {
            $out[$h['name']] = count($h['values']) === 1 ? $h['values'][0] : $h['values'];
        }
        return $out;
    }

    /** The body encoded as JSON (an empty body is `{}`). */
    public function toJson(): string
    {
        $json = json_encode($this->body === [] ? new \stdClass() : $this->body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return $json === false ? '{}' : $json;
    }

    /** Emits status, headers and body with PHP's own functions (plain PHP / no framework). */
    public function send(): void
    {
        if (!headers_sent()) {
            http_response_code($this->status);
            header('Content-Type: application/json; charset=utf-8');
            foreach ($this->headers as $h) {
                foreach ($h['values'] as $i => $value) {
                    header($h['name'] . ': ' . $value, $i === 0);
                }
            }
        }
        echo $this->toJson();
    }
}
