<?php

namespace TouchQue\Exceptions;

/**
 * A refused ID-JAG or exchange (Cross App Access). $error is the OAuth error:
 * invalid_grant for a bad ID-JAG, else what the server answered.
 */
class TouchQueIdJagException extends TouchQueException
{
    public string $error;
    public ?int $status;

    public function __construct(string $error, string $message, ?int $status = null)
    {
        parent::__construct($message, $status ?? 0);
        $this->error = $error;
        $this->status = $status;
    }
}
