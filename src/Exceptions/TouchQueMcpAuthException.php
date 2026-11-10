<?php

namespace TouchQue\Exceptions;

/**
 * McpAuth refused a request: answer with $status (401, 403) and the
 * WWW-Authenticate header in $wwwAuthenticate. $error is missing_token,
 * invalid_token, invalid_dpop_proof or insufficient_scope.
 */
class TouchQueMcpAuthException extends TouchQueException
{
    public int $status;
    public string $error;
    public string $wwwAuthenticate;

    public function __construct(int $status, string $error, string $message, string $wwwAuthenticate)
    {
        parent::__construct($message, $status);
        $this->status = $status;
        $this->error = $error;
        $this->wwwAuthenticate = $wwwAuthenticate;
    }
}
