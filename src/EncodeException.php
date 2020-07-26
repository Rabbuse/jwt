<?php
declare(strict_types=1);

namespace Rabbuse\Jwt;

class EncodeException extends \Exception
{
    public function __construct(string $message = "", $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}