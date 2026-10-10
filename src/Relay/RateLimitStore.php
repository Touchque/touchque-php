<?php

namespace TouchQue\Relay;

/**
 * Counter storage for FixedWindowLimiter.
 *
 * hit() must atomically count one hit for $key in its current fixed window
 * and return `['count' => int, 'resetAt' => int]`: the number of hits in that
 * window including this one, and when the window ends (unix milliseconds).
 * A new window (count 1, resetAt = $nowMs + $windowMs) starts when none is
 * open for $key or the open one has ended.
 *
 * PHP usually runs one process per request (PHP-FPM), so the in-memory
 * default (MemoryRateLimitStore) starts empty on every request there and
 * limits nothing. Implement this over a shared store instead: APCu (one
 * host) or Redis (several hosts), e.g. Redis `INCR key` + `PEXPIRE key
 * windowMs` when the count is 1, then `PTTL key` for resetAt.
 */
interface RateLimitStore
{
    /**
     * @return array{count: int, resetAt: int}
     */
    public function hit(string $key, int $windowMs, int $nowMs): array;
}
