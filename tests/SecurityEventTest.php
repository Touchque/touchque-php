<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Exceptions\TouchQueSecurityEventException;
use TouchQue\SecurityEventVerifier;

/**
 * Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json),
 * discovery through /.well-known/ssf-configuration, and a poll (RFC 8936).
 */
class SecurityEventTest extends TestCase
{
    /** @var resource|null */
    private $process = null;
    /** @var resource|null the transmitter's stdout: one JSON line per poll it answered */
    private $polled = null;

    protected function tearDown(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }

    private static function vectors(): array
    {
        return json_decode(file_get_contents(__DIR__ . '/../fixtures/security-event-vectors.json'), true);
    }

    private function verifier(): SecurityEventVerifier
    {
        $v = self::vectors();
        return new SecurityEventVerifier(['issuer' => $v['issuer'], 'audience' => $v['audience'], 'jwks' => $v['jwks']]);
    }

    public function testReadsEveryValidVector(): void
    {
        foreach (self::vectors()['valid'] as $v) {
            $this->assertEquals($v['expect'], $this->verifier()->verify($v['token']), $v['name']);
        }
    }

    public function testRefusesEveryInvalidVector(): void
    {
        foreach (self::vectors()['invalid'] as $v) {
            try {
                $this->verifier()->verify($v['token']);
                $this->fail("{$v['name']} was accepted");
            } catch (TouchQueSecurityEventException $e) {
                $this->assertSame($v['error'], $e->error, $v['name']);
            }
        }
    }

    public function testShortNames(): void
    {
        $this->assertStringEndsWith('/caep/event-type/session-revoked', SecurityEventVerifier::TYPES['session-revoked']);
    }

    /**
     * A transmitter on 127.0.0.1: its ssf-configuration (issuer = its own base URL), its JWKS
     * (the vectors' keys) and a poll endpoint that answers with the first valid vector. /ssf/poll/gone
     * answers 401 like a revoked stream token.
     */
    private function transmitter(): string
    {
        $code = <<<'PHP'
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
$base = 'http://' . stream_socket_get_name($server, false);
echo parse_url($base, PHP_URL_PORT), "\n";
while ($conn = @stream_socket_accept($server, 30)) {
    $path = explode(' ', trim((string)fgets($conn)))[1] ?? '';
    $headers = [];
    while (($line = fgets($conn)) !== false && trim($line) !== '') {
        [$k, $v] = array_pad(explode(':', $line, 2), 2, '');
        $headers[strtolower(trim($k))] = trim($v);
    }
    $body = isset($headers['content-length']) ? (string)stream_get_contents($conn, (int)$headers['content-length']) : '';
    $status = 200;
    if ($path === '/.well-known/ssf-configuration') {
        $out = json_encode(['issuer' => $base, 'jwks_uri' => "{$base}/jwks"]);
    } elseif ($path === '/jwks') {
        $out = $argv[1];
    } elseif ($path === '/ssf/poll/gone') {
        $status = 401;
        $out = '{"error":"authentication_failed"}';
    } else {
        echo json_encode(['auth' => $headers['authorization'] ?? null, 'body' => json_decode($body, true)]), "\n";
        $out = $argv[2];
    }
    fwrite($conn, "HTTP/1.1 {$status} X\r\nContent-Type: application/json\r\nContent-Length: " . strlen($out) . "\r\nConnection: close\r\n\r\n{$out}");
    fclose($conn);
}
PHP;
        $v = self::vectors();
        $answer = json_encode(['sets' => [$v['valid'][0]['expect']['jti'] => $v['valid'][0]['token']], 'moreAvailable' => false]);
        $this->process = proc_open([PHP_BINARY, '-r', $code, json_encode($v['jwks']), $answer], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->polled = $pipes[1];
        $port = (int)trim((string)fgets($pipes[1]));
        $this->assertGreaterThan(0, $port, 'the transmitter did not start');
        return "http://127.0.0.1:{$port}";
    }

    public function testDiscoversTheJwksAndChecksTheIssuerTheSetNames(): void
    {
        $v = self::vectors();
        $base = $this->transmitter();
        $verifier = new SecurityEventVerifier(['issuer' => $base, 'audience' => $v['audience']]);
        // The vectors' issuer is not this one: the signature verifies with the discovered keys, the issuer does not.
        try {
            $verifier->verify($v['valid'][0]['token']);
            $this->fail('another issuer was accepted');
        } catch (TouchQueSecurityEventException $e) {
            $this->assertSame('invalid_issuer', $e->error);
        }
    }

    public function testPollAcknowledgesAndReturnsTheWaitingSets(): void
    {
        $v = self::vectors();
        $base = $this->transmitter();
        $out = SecurityEventVerifier::poll("{$base}/ssf/poll/s1", 'tqssf_x', ['ack' => ['a'], 'maxEvents' => 5]);
        $this->assertSame([$v['valid'][0]['expect']['jti'] => $v['valid'][0]['token']], $out['sets']);
        $this->assertFalse($out['moreAvailable']);
        $this->assertSame(['auth' => 'Bearer tqssf_x', 'body' => ['ack' => ['a'], 'maxEvents' => 5]], json_decode((string)fgets($this->polled), true));
    }

    public function testPollThrowsTheTransmittersErrorCode(): void
    {
        $base = $this->transmitter();
        try {
            SecurityEventVerifier::poll("{$base}/ssf/poll/gone", 'tqssf_x');
            $this->fail('a 401 answer was accepted');
        } catch (TouchQueSecurityEventException $e) {
            $this->assertSame('authentication_failed', $e->error);
        }
    }

    public function testPollRefusesPlainHttpAndAMissingToken(): void
    {
        foreach ([['http://transmitter.example/ssf/poll/s1', 'tqssf_x'], ['https://transmitter.example/ssf/poll/s1', '']] as [$url, $token]) {
            try {
                SecurityEventVerifier::poll($url, $token);
                $this->fail("{$url} was polled");
            } catch (TouchQueConfigException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testRefusesAJwksUriThatIsNotHttpsDiscoveredOrConfigured(): void
    {
        $v = self::vectors();
        $token = $v['valid'][0]['token'];
        $fetched = [];
        $fetch = static function (string $url) use (&$fetched, $v): array {
            $fetched[] = $url;
            return $url === "{$v['issuer']}/.well-known/ssf-configuration" ? ['issuer' => $v['issuer'], 'jwks_uri' => 'http://keys.example/jwks'] : $v['jwks'];
        };
        foreach ([[], ['jwksUri' => 'http://keys.example/jwks']] as $extra) {
            $verifier = new SecurityEventVerifier(['issuer' => $v['issuer'], 'audience' => $v['audience'], 'fetch' => $fetch] + $extra);
            try {
                $verifier->verify($token);
                $this->fail('keys over plain http were used');
            } catch (TouchQueSecurityEventException $e) {
                $this->assertSame('temporarily_unavailable', $e->error);
                $this->assertStringContainsString('http://keys.example/jwks must be an https URL', $e->getMessage());
            }
        }
        // Only the metadata was read; the http JWKS never was.
        $this->assertSame(["{$v['issuer']}/.well-known/ssf-configuration"], $fetched);
    }
}
