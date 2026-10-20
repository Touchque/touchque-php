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

    public function approve(?string $id = null, string $via = 'DEVICE', bool $provisional = false): void
    {
        $this->call('/__test/approve', ['id' => $id, 'via' => $via, 'provisional' => $provisional]);
    }

    /** Vishing Shield: the phone tap moved the request to a passkey (still PENDING). */
    public function escalate(?string $id = null): void
    {
        $this->call('/__test/escalate', ['id' => $id]);
    }

    public function revoke(?string $id = null, string $reason = 'COACHED'): void
    {
        $this->call('/__test/revoke', ['id' => $id, 'reason' => $reason]);
    }

    public function reconfirm(?string $id = null): void
    {
        $this->call('/__test/reconfirm', ['id' => $id]);
    }

    public function reject(?string $id = null): void
    {
        $this->call('/__test/reject', ['id' => $id]);
    }

    /** Never Locked Out: move a recovery to VOUCHING, COOLING or COMPLETED. */
    public function recovery(string $to, ?string $id = null): void
    {
        $this->call('/__test/recovery', ['id' => $id, 'to' => $to]);
    }

    /** TouchQue Actions: the dashboard's phone approval of a pending version. */
    public function approveVersion(string $slug, int $number): void
    {
        $this->call('/__test/approve-version', ['slug' => $slug, 'number' => $number]);
    }

    public function calls(): array
    {
        return $this->getJson('/__test/calls') ?? [];
    }

    /** The body of the last POST /risk/check (silent sign-ins), or null. */
    public function lastCheck(): ?array
    {
        return $this->getJson('/__test/last-check');
    }

    /** Forgets every request, linked user, known browser and option. */
    public function reset(): void
    {
        $this->call('/__test/reset');
    }

    private function getJson(string $path): ?array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        $data = json_decode((string)$res, true);
        return is_array($data) ? $data : null;
    }

    public function close(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }
}
