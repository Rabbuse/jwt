<?php
declare(strict_types=1);

namespace Rabbuse\Jwt;

use Rabbuse\Jwt\util\{HMAC};

class JWT
{
    protected static $instance = null;

    //jwt过期的时间，为0时不检测，即无过期时间
    protected $exp = 0;

    //jwt生效时间，在这个时间前jwt无效，为0时不检测，即无生效时间
    protected $nbf = 0;

    //jwt的签发人
    protected $iss = 'Rabbuse';

    //jwt的发放目标
    protected $aud = null;

    //jwt的主题
    protected $sub = null;

    //jwt的id编号
    protected $jti = null;

    //jwt的加密类型
    protected $alg = 'HS256';

    private static $allow_alg = [
        'HS256' => ['function' => 'hash_hmac', 'param' => 'sha256'],
        'HS384' => ['function' => 'hash_hmac', 'param' => 'sha384'],
        'HS512' => ['function' => 'hash_hmac', 'param' => 'sha512'],
        'PS256' => ['a' => 1, 'b' => 2],
        'PS384' => ['a' => 1, 'b' => 2],
        'PS512' => ['a' => 1, 'b' => 2],
        'RS256' => ['a' => 1, 'b' => 2],
        'RS384' => ['a' => 1, 'b' => 2],
        'RS512' => ['a' => 1, 'b' => 2],
        'ES256' => ['a' => 1, 'b' => 2],
        'ES256K' => ['a' => 1, 'b' => 2],
        'ES384' => ['a' => 1, 'b' => 2],
        'ES512' => ['a' => 1, 'b' => 2],
        'EdDSA' => ['a' => 1, 'b' => 2],
    ];

    private function __construct()
    {
    }

    private function __clone()
    {
    }

    private function __waleup()
    {
    }

    /**
     * @return JWT|null
     */
    public static function getInstance()
    {
        if (!self::$instance || !self::$instance instanceof self) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * @param array $data
     * @param string $key
     * @return string
     * @throws EncodeException
     * @throws util\SignException
     */
    public function encode(array $data, string $key)
    {
        $header = $this->createHeader();
        if (!$header) {
            throw new EncodeException('header create error!');
        }
        $payload = $this->createPayload($data);
        if (!$payload) {
            throw new EncodeException('payload create error!');
        }
        $sign = $this->base64_url_encode($this->createSign(implode('.', [$header, $payload]), $key));
        return "{$header}.{$payload}.{$sign}";
    }


    public static function decode(string $jwt, string $key)
    {

    }

    /**
     * 设置jwt的签发人
     * @param $iss
     * @return self
     */
    public function setIssuer($iss)
    {
        $this->iss = $iss;
        return self::$instance;
    }

    /**
     * 设置过期时间
     * @param int $time
     * @return self
     */
    public function setExpire(int $time)
    {
        $this->exp = $time;
        return self::$instance;
    }

    /**
     * 设置有效时间(秒)
     * @param int $time
     * @return self
     */
    public function setValid(int $time)
    {
        $this->exp = time() + $time;
        return self::$instance;
    }

    /**
     * 设置生效时间
     * @param int $time
     * @return self
     */
    public function setNotBefore(int $time)
    {
        $this->nbf = $time;
        return self::$instance;
    }

    /**
     * 设置生效所需时间(秒)
     * @param int $time
     * @return self
     */
    public function setBeforeTime(int $time)
    {
        $this->nbf = time() + $time;
        return self::$instance;
    }

    /**
     * 设置jwt的发放目标
     * @param $aud
     * @return self
     */
    public function setAudience($aud)
    {
        $this->aud = $aud;
        return self::$instance;
    }

    /**
     * 设置jwt的主题
     * @param $sub
     * @return self
     */
    public function setSubject($sub)
    {
        $this->sub = $sub;
        return self::$instance;
    }

    /**
     * 设置jwt的id编号
     * @param $jti
     * @return self
     */
    public function setJwtId($jti)
    {
        $this->jti = $jti;
        return self::$instance;
    }

    /**
     * 设置jwt的加密类型
     * @param string $alg
     * @return self
     */
    public function setAlg(string $alg)
    {
        $this->alg = $alg;
        return self::$instance;
    }

    /**
     * @param string $alg
     * @return string
     * @throws EncodeException
     */
    private function createHeader()
    {
        if (!array_key_exists($this->alg, self::$allow_alg)) {
            throw new EncodeException('alg is not allow!');
        }
        $json = $this->jsonEncode(['typ' => 'JWT', 'alg' => $this->alg]);
        return $this->base64_url_encode($json);
    }

    /**
     * @param array $data
     * @return string
     * @throws EncodeException
     */
    private function createPayload(array $data)
    {
        $setting = [
            "iss" => $this->iss,
            "iat" => time(),
            "exp" => $this->exp,
            "aud" => $this->aud,
            "sub" => $this->sub,
            "nbf" => $this->nbf,
            "jti" => $this->jti,
        ];
        $json = $this->jsonEncode(array_merge($data, $setting));
        return $this->base64_url_encode($json);
    }

    /**
     * @param string $str
     * @param string $key
     * @return string
     * @throws EncodeException
     * @throws util\SignException
     */
    private function createSign(string $str, string $key)
    {
        if (!isset(self::$allow_alg[$this->alg])) {
            throw new EncodeException('alg is not allow!');
        }
        $info = (self::$allow_alg[$this->alg]);
        switch ($info['function']) {
            case 'hash_hmac':
                $hmac = new HMAC($info['param']);
                return $hmac->encrypt($str, $key);
            default:
                throw new EncodeException('encrypt type error!');
        }
    }

    /**
     * @param array $data
     * @return false|string
     * @throws EncodeException
     */
    private function jsonEncode(array $data)
    {
        $json = json_encode($data);
        if (!$json) {
            throw new EncodeException('json encode error: ' . json_last_error());
        }
        return $json;
    }

    /**
     * @param string $string
     * @return mixed
     */
    private function base64_url_encode(string $string)
    {
        $data = base64_encode($string);
        return str_replace(['+', '/', '='], ['-', '_', ''], $data);
    }

    /**
     * @param string $string
     * @return bool|string
     */
    private function base64_url_decode(string $string)
    {
        $data = str_replace(['-', '_'], ['+', '/'], $string);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }
        return base64_decode($data);
    }
}