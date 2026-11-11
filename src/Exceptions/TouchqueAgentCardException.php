<?php

namespace Touchque\Exceptions;

/**
 * An A2A agent card that did not verify. $error is unsigned, malformed,
 * untrusted_key, invalid_signature or keys_unavailable.
 */
class TouchqueAgentCardException extends TouchqueException
{
    public string $error;

    public function __construct(string $error, string $message)
    {
        parent::__construct($message);
        $this->error = $error;
    }
}
