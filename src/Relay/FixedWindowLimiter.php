<?php

namespace TouchQue\Relay;

/**
 * Fixed-window rate limiter for RelayHandler's pre-auth routes. It protects
 * your own server (and your TouchQue quota) from scripted abuse of routes
 * anyone on the internet can call.
 *
 * Options (all optional):
 *   windowMs  window length in ms                                   (default 60000)
 *   perIp     requests per client IP per route per window           (default 20)
 *   perUser   requests per username per route per window            (default 5)
 *   store     RateLimitStore holding the counters  (default MemoryRateLimitStore)
 *
 * The counters live in `store`. The in-memory default is per process: under
 * PHP-FPM it starts empty on every request, so pass a shared (APCu/Redis)
 * store there, or rate limit in front of the relay and set `rateLimit` to false.
 */
class FixedWindowLimiter
{
    private int $windowMs;
    private int $perIp;
    private int $perUser;
    private RateLimitStore $store;

    public function __construct(array $options = [])
    {
        $store = $options['store'] ?? null;
        if ($store !== null && !$store instanceof RateLimitStore) {
            throw new \InvalidArgumentException('rateLimit "store" must implement ' . RateLimitStore::class . '.');
        }
        $this->windowMs = (int)($options['windowMs'] ?? 60000);
        $this->perIp = (int)($options['perIp'] ?? 20);
        $this->perUser = (int)($options['perUser'] ?? 5);
        $this->store = $store ?? new MemoryRateLimitStore();
    }

    public function windowMs(): int
    {
        return $this->windowMs;
    }

    public function perIp(): int
    {
        return $this->perIp;
    }

    public function perUser(): int
    {
        return $this->perUser;
    }

    /** Counts one hit. Returns seconds to wait when over $limit, otherwise 0. */
    public function hit(string $key, int $limit, ?int $nowMs = null): int
    {
        $now = $nowMs ?? (int)floor(microtime(true) * 1000);
        $entry = $this->store->hit($key, $this->windowMs, $now);
        if ((int)$entry['count'] <= $limit) {
            return 0;
        }
        return max(1, (int)ceil(((int)$entry['resetAt'] - $now) / 1000));
    }
}
