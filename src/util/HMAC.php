<?php
declare(strict_types=1);

namespace Rabbuse\Jwt\util;

class HMAC
{
    private $algo = null;

    public function __construct(string $algo)
    {
        if (empty($algo) || !in_array($algo, hash_algos())) {
            throw new SignException('not support algo!');
        }
        $this->algo = $algo;
    }


    public function encrypt(string $str, string $key)
    {
        return hash_hmac($this->algo , $str , $key, true);
    }


    public function decrypt()
    {

    }
}