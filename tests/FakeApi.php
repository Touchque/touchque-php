<?php

namespace TouchQue\Tests;

/**
 * Spawns the shared Node fake TouchQue API (testing/fake-touchque-api.mjs)
 * for contract tests: verifies this SDK's requests are signed exactly like the
 * real backend expects, using a real HTTP round trip (not mocks).
 */
class FakeApi
{
    private $process;
    public string $baseUrl;

    public static function start(): self
    {
        $script = realpath(__DIR__ . '/../testing/fake-touchque-api.mjs');
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open(['node', $script], $descriptors, $pipes);
        if (!is_resource($process)) {
            throw new \RuntimeException('could not start fake-touchque-api.mjs');
        }
        $line = fgets($pipes[1]);
        $data = json_decode((string)$line, true);
        if (!isset($data['port'])) {
            throw new \RuntimeException('fake-touchque-api.mjs did not report a port: ' . $line);
        }
        $api = new self();
        $api->process = $process;
        $api->baseUrl = "http://127.0.0.1:{$data['port']}";
        return $api;
    }

    private function call(string $path, array $body = []): array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($body),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        ]);
        $res = curl_exec($ch);
        return json_decode((string)$res, true) ?? [];
    }

    public function link(string $user): void
    {
        $this->call('/__test/link', ['user' => $user]);
    }

    public function opts(array $opts): void
    {
        $this->call('/__test/opts', $opts);
    }

    public function approve(?string $id = null, string $via = 'DEVICE'): void
    {
        $this->call('/__test/approve', ['id' => $id, 'via' => $via]);
    }

    public function reject(?string $id = null): void
    {
        $this->call('/__test/reject', ['id' => $id]);
    }

    public function calls(): array
    {
        $ch = curl_init($this->baseUrl . '/__test/calls');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        return json_decode((string)$res, true) ?? [];
    }

    public function close(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }
}
