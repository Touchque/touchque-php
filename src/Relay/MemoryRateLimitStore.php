<?php

namespace TouchQue\Relay;

/**
 * In-process RateLimitStore. Only useful in a long-running worker (Swoole,
 * RoadRunner, ReactPHP, Octane); under PHP-FPM each request starts empty, so
 * use an APCu/Redis-backed RateLimitStore there.
 *
 * Bounded: once $maxEntries keys are held, expired windows are dropped, and
 * if it is still full (a flood of distinct keys) the oldest half goes.
 */
class MemoryRateLimitStore implements RateLimitStore
{
    /** @var array<string, array{count: int, resetAt: int}> */
    private array $entries = [];
    private int $maxEntries;

    public function __construct(int $maxEntries = 50000)
    {
        $this->maxEntries = max(2, $maxEntries);
    }

    public function hit(string $key, int $windowMs, int $nowMs): array
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null || $entry['resetAt'] <= $nowMs) {
            if ($entry === null && count($this->entries) >= $this->maxEntries) {
                $this->prune($nowMs);
            }
            $entry = ['count' => 0, 'resetAt' => $nowMs + $windowMs];
        }
        $entry['count']++;
        $this->entries[$key] = $entry;
        return $entry;
    }

    private function prune(int $nowMs): void
    {
        $this->entries = array_filter($this->entries, static function (array $e) use ($nowMs): bool {
            return $e['resetAt'] > $nowMs;
        });
        // Still full: drop the oldest half rather than grow without bound.
        if (count($this->entries) >= $this->maxEntries) {
            $this->entries = array_slice($this->entries, intdiv($this->maxEntries, 2) + 1, null, true);
        }
    }
}
