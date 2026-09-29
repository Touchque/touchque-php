<?php

namespace TouchQue\Webhook;

/**
 * In-process ReplayCache. Only useful in a long-running worker (Swoole,
 * RoadRunner, a queue consumer); under PHP-FPM each request starts empty, so
 * use a Redis/database-backed ReplayCache there.
 */
class MemoryReplayCache implements ReplayCache
{
    /** @var array<string, int> jti => expiry (unix seconds) */
    private array $seen = [];
    private int $maxEntries;

    public function __construct(int $maxEntries = 100000)
    {
        $this->maxEntries = $maxEntries;
    }

    public function checkAndSet(string $jti, int $ttlSeconds): bool
    {
        $now = time();
        if (isset($this->seen[$jti]) && $this->seen[$jti] > $now) {
            return false;
        }
        if (count($this->seen) >= $this->maxEntries) {
            $this->seen = array_filter($this->seen, static fn (int $exp) => $exp > $now);
            while (count($this->seen) >= $this->maxEntries) {
                array_shift($this->seen);
            }
        }
        $this->seen[$jti] = $now + $ttlSeconds;
        return true;
    }
}
