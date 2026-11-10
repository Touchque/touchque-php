<?php

namespace TouchQue\Exceptions;

/**
 * A refused Security Event Token (Shared Signals). $error is the RFC 8935
 * error to answer with (HTTP 400 {"err": $error}): invalid_request,
 * invalid_key, invalid_issuer or invalid_audience; temporarily_unavailable
 * when the issuer's keys could not be read (answer 503: the transmitter
 * tries again).
 */
class TouchQueSecurityEventException extends TouchQueException
{
    public string $error;

    public function __construct(string $error, string $message)
    {
        parent::__construct($message);
        $this->error = $error;
    }
}
