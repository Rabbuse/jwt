使用方法
use Rabbuse\Jwt\JWT;
获取实例：
$jwt = JWT::getInstance();
生成一个jwt串
$token = $jwt->encode(['1d'], 'key');
可以通过内置方法设置一些jwt属性
设置jwt的加密类型,默认是HS256
$jwt->setAlg('HS256');
设置签发人
$jwt->setIssuer('rabbuse');
设置过期时间，需要传入一个到期的时间戳
$jwt->setExpire(1595603554);
或者使用setValid方法设置有效时间，需要传入jwt有效的秒数
$jwt->setExpire(3600);
设置生效时间，传入一个时间戳，在到达这个时间之前jwt不会生效
$jwt->setNotBefore(1595603554);
或者使用setBeforeTime方法设置生效剩余时间，需要传入一个距离生效时间剩余的秒数
$jwt->setBeforeTime(600);
还可以使用链式调用批量设置属性，例如设置jwt的发放目标、主题和id编号
$jwt->setAudience('aud')->setSubject('jwt')->setJwtId('123');
最后调用encode方法，提供一些需要保存的信息和一个加密秘钥，以生成一个jwt字符串