<?php

namespace Tourze\Workerman\TLS\Crypto;

use Tourze\Workerman\TLS\Enum\CipherSuite;

/**
 * 密码套件策略接口
 */
interface CipherSuiteStrategy
{
    /**
     * 从客户端支持的密码套件中选择一个
     */
    public function negotiate(array $clientSuites): ?CipherSuite;

    /**
     * 创建对应的加密器
     */
    public function createCipher(): CipherInterface;
}
