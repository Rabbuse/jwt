<?php
declare(strict_types=1);

namespace Rabbuse\Jwt\util;

class OPENSSL
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
        $key = openssl_get_privatekey($key);
        if (!$key) {
            throw new SignException('get privatekey error!');
        }
        openssl_sign($str, $signature, $key, $this->algo);
        openssl_free_key($key);
        return $signature;
    }


    public function decrypt(string $str, string $key, string $sign)
    {
        $key = openssl_get_publickey($key);
        if (!$key) {
            throw new SignException('get publickey error!');
        }
        return openssl_verify($str, $sign, $key, $this->algo);
    }
}