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


    public function encryptWithEs(string $str, string $key)
    {
        $key = openssl_get_privatekey($key);
        if (!$key) {
            throw new SignException('get privatekey error!');
        }
        openssl_sign($str, $signature, $key, $this->algo);
        //r串的长度
        $rlen = ord(substr($signature,3,1));
        //s串的长度
        $slen = ord(substr($signature,5+$rlen,1));

        $r = substr($signature,4,$rlen);
        if ('00' === bin2hex(substr($r, 0, 1))) {
            $r = substr($r, 1);
        }
        $s = substr($signature, 6+$rlen, $slen);
        if ('00' === bin2hex(substr($s, 0, 1))) {
            $s = substr($s, 1);
        }
        openssl_free_key($key);
        return $r.$s;
    }


    public function decrypt(string $str, string $key, string $sign)
    {
        $key = openssl_get_publickey($key);
        if (!$key) {
            throw new SignException('get publickey error!');
        }
        $verify = openssl_verify($str, $sign, $key, $this->algo);
        openssl_free_key($key);
        return $verify;
    }
}