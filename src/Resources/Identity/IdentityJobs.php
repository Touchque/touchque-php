<?php

namespace TouchQue\Resources\Identity;

use TouchQue\Http\HttpClient;

/** `$tq->identity->imports` and `->exports`: bulk user moves running in the background. */
class IdentityJobs
{
    private HttpClient $http;
    private string $kind;

    public function __construct(HttpClient $http, string $kind)
    {
        $this->http = $http;
        $this->kind = $kind;
    }

    /** imports: ['users' => [...], 'upsert' => bool]; exports: ['format' => 'csv'|'json'] */
    public function start(array $body): array
    {
        return $this->http->post('/identity/users-' . $this->kind, $body);
    }

    public function get(string $jobId): array
    {
        return $this->http->get('/identity/users-' . $this->kind . '/' . rawurlencode($jobId));
    }

    /** Exports: the finished file (CSV or JSON lines), as text. */
    public function file(string $jobId): string
    {
        return $this->http->getText('/identity/users-' . $this->kind . '/' . rawurlencode($jobId) . '/file');
    }

    /** Polls until the job is done or failed. */
    public function wait(string $jobId, float $intervalSec = 1.0, float $timeoutSec = 600.0): array
    {
        $end = microtime(true) + $timeoutSec;
        while (true) {
            $job = $this->get($jobId);
            if (($job['status'] ?? '') !== 'running' || microtime(true) > $end) {
                return $job;
            }
            usleep((int) ($intervalSec * 1000000));
        }
    }
}
