<?php

namespace TouchQue\HostedLogin;

use TouchQue\Exceptions\TouchQueException;

/** A sign-in or token check failed; getErrorCode() is machine-readable. */
class HostedLoginException extends TouchQueException
{
    private string $errorCode;
    private ?string $description;
    private ?int $status;

    public function __construct(string $errorCode, ?string $description = null, ?int $status = null)
    {
        parent::__construct($description !== null ? "{$errorCode}: {$description}" : $errorCode, $status ?? 0);
        $this->errorCode = $errorCode;
        $this->description = $description;
        $this->status = $status;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function getStatus(): ?int
    {
        return $this->status;
    }
}
