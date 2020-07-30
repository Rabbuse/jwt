<?php
declare(strict_types=1);

namespace Rabbuse\Jwt;

use Rabbuse\Jwt\util\{HMAC, OPENSSL};

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

    //允许的加密类型
    private static $allow_alg = [
        'HS256' => ['function' => 'hash_hmac', 'param' => 'sha256'],
        'HS384' => ['function' => 'hash_hmac', 'param' => 'sha384'],
        'HS512' => ['function' => 'hash_hmac', 'param' => 'sha512'],
        // 'PS256' => ['a' => 1, 'b' => 2],
        // 'PS384' => ['a' => 1, 'b' => 2],
        // 'PS512' => ['a' => 1, 'b' => 2],
         'RS256' => ['function' => 'openssl_rs', 'param' => 'sha256'],
         'RS384' => ['function' => 'openssl_rs', 'param' => 'sha384'],
         'RS512' => ['function' => 'openssl_rs', 'param' => 'sha512'],
         'ES256' => ['function' => 'openssl_es', 'param' => 'sha256'],
        // 'ES256K' => ['function' => 'openssl_es', 'param' => 'sha256'],
         'ES384' => ['function' => 'openssl_es', 'param' => 'sha384'],
         'ES512' => ['function' => 'openssl_es', 'param' => 'sha512'],
        // 'EdDSA' => ['a' => 1, 'b' => 2],
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
     * 生成jwt
     * @param array $data
     * @param string $key
     * @return string
     * @throws EncodeException
     * @throws util\SignException
     */
    public function encode(array $data, string $key)
    {
        if (empty($key)) {
            throw new EncodeException('key cannot be empty!');
        }
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


    /**
     * 解析jwt
     * @param string $jwt
     * @param string $key
     * @return mixed
     * @throws DecodeException
     */
    public function decode(string $jwt, string $key)
    {
        $arr = explode('.', $jwt);
        if (count($arr) !== 3) {
            throw new DecodeException('jwt format error!');
        } 
        if (empty($key)) {
            throw new DecodeException('key cannot be empty!');
        }
        //拆解jwt
        $array = $this->decodeArray($arr);
        list($header, $payload, $sign) = $array;
        //验证jwt的合法性
        $this->verify("{$arr[0]}.{$arr[1]}", $sign, $key, $header->alg);
        if (!empty($payload->nbf) && $payload->nbf > time()) {
            throw new DecodeException('jwt not in force!');
        }
        if (!empty($payload->iat) && $payload->iat > time()) {
            throw new DecodeException('jwt create time error!');
        }
        if (!empty($payload->exp) && $payload->exp <= time()) {
            throw new DecodeException('jwt is expire!');
        }
        return $payload;
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
        $info = self::$allow_alg[$this->alg];
        switch ($info['function']) {
            case 'hash_hmac':
                $hmac = new HMAC($info['param']);
                return $hmac->encrypt($str, $key);
            case 'openssl_rs':
                $ssl = new OPENSSL($info['param']);
                return $ssl->encrypt($str, $key);
            case 'openssl_es':
                $ssl = new OPENSSL($info['param']);
                return $ssl->encryptWithEs($str, $key);
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


    /**
     * @param array $data
     * @return array
     * @throws DecodeException
     */
    private function decodeArray(array $data)
    {
        list($header, $payload, $sign) = $data;
        $header = json_decode($this->base64_url_decode($header));
        if (empty($header)) {
            throw new DecodeException('header decode error!');
        }
        if (empty($header->alg) || !isset(self::$allow_alg[$header->alg])) {
            throw new DecodeException('alg is not allow!');
        }
        $payload = json_decode($this->base64_url_decode($payload));
        if (empty($payload)) {
            throw new DecodeException('payload decode error!');
        }
        $sign = $this->base64_url_decode($sign);
        if (empty($sign)) {
            throw new DecodeException('invalid sign!');
        }
        return [$header, $payload, $sign];
    }

    /**
     * @param string $str
     * @param string $sign
     * @param string $key
     * @param string $alg
     * @return bool
     * @throws DecodeException
     * @throws util\SignException
     */
    private function verify(string $str, string $sign, string $key, string $alg)
    {
        if (!isset(self::$allow_alg[$alg])) {
            throw new DecodeException('alg is not allow!');
        }
        $info = self::$allow_alg[$alg];
        switch ($info['function']) {
            case 'hash_hmac':
                $hmac = new HMAC($info['param']);
                $res = $hmac->decrypt($str, $key, $sign);
            break;
            case 'openssl_rs':
                $ssl = new OPENSSL($info['param']);
                $res = $ssl->decrypt($str, $key, $sign);
                break;
            case 'openssl_es':
                $ssl = new OPENSSL($info['param']);
                $res = $ssl->decrypt($str, $key, $sign);
                break;
            default:
                throw new DecodeException('decrypt type error!');
        }
        if (!$res) {
            throw new DecodeException('sign verification failed!');
        }
        return true;
    }
}