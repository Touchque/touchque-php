<?php

namespace TouchQue\Exceptions;

/** The API returned an error response (status >= 400). `getCode()` is the
 * HTTP status; `getData()` is the decoded JSON body. */
class TouchQueAPIException extends TouchQueException
{
    /** HTTP status code (e.g. 404, 429, 423). Alias for `getCode()`. */
    public function getStatus(): int
    {
        return $this->getCode();
    }

    /** Machine-readable error code (e.g. "device_not_linked", "unknown_action"). */
    public function getErrorCode(): ?string
    {
        return $this->getData()['code'] ?? null;
    }

    /** Offline sign: why a code was not approved. */
    public function getReason(): ?string
    {
        return $this->getData()['reason'] ?? null;
    }

    /** Offline sign: wrong codes left before the challenge locks. */
    public function getAttemptsLeft(): ?int
    {
        return $this->getData()['attemptsLeft'] ?? null;
    }

    /** Seconds to wait before retrying (429 / 423). */
    public function getRetryAfter(): ?int
    {
        return $this->getData()['retryAfter'] ?? null;
    }
}
