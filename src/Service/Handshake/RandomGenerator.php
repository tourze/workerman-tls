<?php

namespace Tourze\Workerman\TLS\Service\Handshake;

/**
 * TLS随机数生成器
 * 根据RFC 5246 Section 7.4.1.2要求生成32字节随机数
 */
class RandomGenerator
{
    public function generate(): string
    {
        $random = random_bytes(28);
        $gmtUnixTime = pack('N', time());
        return $gmtUnixTime . $random;
    }
}
