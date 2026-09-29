<?php

namespace TouchQue\Webhook;

/**
 * Storage for webhook `jti`s already accepted. checkAndSet() must atomically
 * record $jti for $ttlSeconds and return true if it was NOT seen before.
 * PHP usually runs one process per request, so implement this over Redis,
 * APCu or your database (e.g. Redis `SET key 1 NX EX ttl`).
 */
interface ReplayCache
{
    public function checkAndSet(string $jti, int $ttlSeconds): bool;
}
