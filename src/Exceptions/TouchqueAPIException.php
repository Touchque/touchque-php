<?php

namespace Touchque\Exceptions;

/** The API returned an error response (status >= 400). `getCode()` is the
 * HTTP status; `getData()` is the decoded JSON body. */
class TouchqueAPIException extends TouchqueException
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

    /**
     * "Why?" case code of a refusal (`K7P-2QX`): show it to the user ("Tell your
     * support team: K7P-2QX"); your team opens the decision by it in the
     * dashboard. Null for other errors.
     */
    public function getCaseCode(): ?string
    {
        $code = $this->getData()['caseCode'] ?? null;
        return is_string($code) ? $code : null;
    }
}
