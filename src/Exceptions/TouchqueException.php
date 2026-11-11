<?php

namespace Touchque\Exceptions;

class TouchqueException extends \Exception
{
    protected ?array $data;

    public function __construct(string $message, int $code = 0, ?array $data = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->data = $data;
    }

    public function getData(): ?array
    {
        return $this->data;
    }
}
