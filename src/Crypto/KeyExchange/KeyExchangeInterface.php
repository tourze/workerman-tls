<?php

namespace Tourze\Workerman\TLS\Crypto\KeyExchange;

use Tourze\Workerman\TLS\Message\ClientKeyExchange;

/**
 * 密钥交换接口
 */
interface KeyExchangeInterface
{
    /**
     * 获取公钥
     */
    public function getPublicKey(): string;

    /**
     * 生成客户端密钥交换参数
     */
    public function generateClientKeyExchange(): string;

    /**
     * 处理客户端密钥交换消息
     */
    public function processClientKeyExchange(ClientKeyExchange $message): void;

    /**
     * 获取预主密钥
     */
    public function getPremasterSecret(): string;
}
