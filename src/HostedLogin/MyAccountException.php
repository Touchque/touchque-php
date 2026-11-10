<?php

namespace TouchQue\HostedLogin;

use TouchQue\Exceptions\TouchQueException;

/** A My Account API call failed; isStepUp() means the sign-in is too old for it (RFC 9470). */
class MyAccountException extends TouchQueException
{
    private string $errorCode;
    private ?string $description;
    private int $status;
    private ?int $maxAge;

    public function __construct(string $errorCode, int $status, ?string $description = null, ?int $maxAge = null)
    {
        parent::__construct($description !== null ? "{$errorCode}: {$description}" : $errorCode, $status);
        $this->errorCode = $errorCode;
        $this->description = $description;
        $this->status = $status;
        $this->maxAge = $maxAge;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    /** True when the person must sign in again (authorizationUrl with maxAge 0) before this change. */
    public function isStepUp(): bool
    {
        return $this->errorCode === 'insufficient_user_authentication';
    }

    public function getMaxAge(): ?int
    {
        return $this->maxAge;
    }
}
