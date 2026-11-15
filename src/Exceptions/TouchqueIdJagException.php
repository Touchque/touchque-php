<?php

namespace Touchque\Exceptions;

/**
 * A refused ID-JAG or exchange (Cross App Access). $error is the OAuth error:
 * invalid_grant for a bad ID-JAG, temporarily_unavailable when a token endpoint
 * could not be reached or its answer read (getPrevious(): the
 * TouchqueNetworkException with curl's error), else what the server answered.
 * $dpopNonce is the latest valid DPoP-Nonce (RFC 9449 section 8) the token
 * endpoint sent in that call: the retry's answer's when it has one, else the
 * first answer's; null when there is none (a missing or empty header, one
 * repeated with different values, or one that is not nonce syntax). A proof
 * for another try carries it (CrossAppAccess::idJagDpopProof's 'nonce').
 */
class TouchqueIdJagException extends TouchqueException
{
    public string $error;
    public ?int $status;
    public ?string $dpopNonce;

    public function __construct(string $error, string $message, ?int $status = null, ?string $dpopNonce = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, $status ?? 0, null, $previous);
        $this->error = $error;
        $this->status = $status;
        $this->dpopNonce = $dpopNonce;
    }
}
