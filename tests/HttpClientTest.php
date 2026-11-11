<?php

namespace Touchque\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\Config;
use Touchque\Exceptions\TouchqueAPIException;
use Touchque\Touchque;

/** The HTTP client against a local server that only ever redirects (a wrong baseUrl). */
class HttpClientTest extends TestCase
{
    /** @var resource|null */
    private $process = null;

    protected function tearDown(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }

    /** A server on 127.0.0.1 that answers every request with $status and a Location header. */
    private function redirectingServer(int $status): string
    {
        $code = <<<'PHP'
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
echo parse_url('tcp://' . stream_socket_get_name($server, false), PHP_URL_PORT), "\n";
while ($conn = @stream_socket_accept($server, 30)) {
    while (($line = fgets($conn)) !== false && trim($line) !== '') {
    }
    fwrite($conn, "HTTP/1.1 {$argv[1]} Moved\r\nLocation: https://touchque.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    fclose($conn);
}
PHP;
        $this->process = proc_open([PHP_BINARY, '-r', $code, (string)$status], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $port = (int)trim((string)fgets($pipes[1]));
        $this->assertGreaterThan(0, $port, 'the redirecting server did not start');
        return "http://127.0.0.1:{$port}";
    }

    public function testARedirectIsAnErrorNotAnEmptySuccess(): void
    {
        $tq = new Touchque(new Config('tq_test_key', 'test_secret', $this->redirectingServer(301)));
        try {
            $tq->login->request('ayse@acme.com');
            $this->fail('a 301 answer must throw');
        } catch (TouchqueAPIException $e) {
            $this->assertSame(301, $e->getStatus());
            $this->assertStringContainsString('redirect', $e->getMessage());
        }
    }
}
