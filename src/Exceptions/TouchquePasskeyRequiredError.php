<?php

namespace Touchque\Exceptions;

/**
 * This request must be approved with a passkey. `$reason` is `policy` when a
 * phishing-resistant policy requires it (no push was sent), or `step_up` when
 * the user tapped Approve on the phone during a call (Vishing Shield) and the
 * request, still open, now waits for a passkey in the browser.
 */
class TouchquePasskeyRequiredError extends TouchqueException
{
    public string $requestId;
    public string $reason;

    public function __construct(string $requestId, string $reason = 'policy')
    {
        parent::__construct($reason === 'step_up'
            ? "Touchque: request '$requestId' must now be approved with a passkey: the user approved on the phone during a call."
            : "Touchque: request '$requestId' must be approved with a passkey (phishing-resistant policy); no push was sent.");
        $this->requestId = $requestId;
        $this->reason = $reason;
    }
}
