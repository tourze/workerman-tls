<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS密码套件枚举
 */
enum CipherSuite: int
{
    // TLS 1.3 密码套件
    case TLS_AES_128_GCM_SHA256 = 0x1301;
    case TLS_AES_256_GCM_SHA384 = 0x1302;
    case TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

    // ECDHE-RSA 密码套件 (TLS 1.2)
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F;
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030;

    // RSA 密码套件 (TLS 1.2)
    case TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C;
    case TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D;

    /**
     * 检查是否需要服务器密钥交换
     */
    public function requiresServerKeyExchange(): bool
    {
        return match($this) {
            // TLS 1.3 always uses key exchange
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_AES_256_GCM_SHA384,
            self::TLS_CHACHA20_POLY1305_SHA256,
            // TLS 1.2 ECDHE ciphers
            self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => true,
            default => false
        };
    }

    /**
     * 获取密钥交换算法
     */
    public function getKeyExchangeAlgorithm(): KeyExchangeAlgorithm
    {
        return match($this) {
            // TLS 1.3 always uses ECDHE
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_AES_256_GCM_SHA384,
            self::TLS_CHACHA20_POLY1305_SHA256 => KeyExchangeAlgorithm::ECDHE_RSA,
            // TLS 1.2 algorithms
            self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => KeyExchangeAlgorithm::ECDHE_RSA,
            self::TLS_RSA_WITH_AES_128_GCM_SHA256,
            self::TLS_RSA_WITH_AES_256_GCM_SHA384 => KeyExchangeAlgorithm::RSA,
            default => throw new \InvalidArgumentException('Unknown key exchange algorithm')
        };
    }

    /**
     * 检查是否为TLS 1.3密码套件
     */
    public function isTls13(): bool
    {
        return match($this) {
            self::TLS_AES_128_GCM_SHA256,
            self::TLS_AES_256_GCM_SHA384,
            self::TLS_CHACHA20_POLY1305_SHA256 => true,
            default => false
        };
    }
}
