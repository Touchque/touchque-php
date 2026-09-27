<?php

namespace TouchQue\Exceptions;

/** A phishing-resistant policy requires this request to be approved with a
 * passkey — no push was sent. */
class TouchQuePasskeyRequiredError extends TouchQueException
{
    public string $requestId;

    public function __construct(string $requestId)
    {
        parent::__construct(
            "TouchQue: request '$requestId' must be approved with a passkey "
            . '(phishing-resistant policy); no push was sent.'
        );
        $this->requestId = $requestId;
    }
}
