<?php

namespace TouchQue\Exceptions;

/**
 * A correctly signed webhook with this `jti` was already accepted. Usually a
 * TouchQue retry of a delivery you processed: answer 200 so it stops, but
 * don't run your side effects again. Extends the signature exception, so
 * existing catch blocks still reject it.
 */
class TouchQueWebhookReplayException extends TouchQueWebhookSignatureException
{
    private string $jti;

    public function __construct(string $jti)
    {
        parent::__construct('Webhook was already accepted (replayed jti)');
        $this->jti = $jti;
    }

    public function getJti(): string
    {
        return $this->jti;
    }
}
