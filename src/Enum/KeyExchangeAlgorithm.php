<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS密钥交换算法枚举
 */
enum KeyExchangeAlgorithm: int
{
    case RSA = 1;
    case DH_DSS = 2;
    case DH_RSA = 3;
    case DHE_DSS = 4;
    case DHE_RSA = 5;
    case DH_ANON = 6;
    case ECDH_ECDSA = 7;
    case ECDH_RSA = 8;
    case ECDHE_ECDSA = 9;
    case ECDHE_RSA = 10;
    case ECDH_ANON = 11;
    case PSK = 12;
    case DHE_PSK = 13;
    case RSA_PSK = 14;
    case ECDHE_PSK = 15;

    public function requiresServerKeyExchange(): bool
    {
        return match($this) {
            self::DH_DSS, self::DH_RSA, self::DHE_DSS, self::DHE_RSA, self::ECDH_ECDSA, self::ECDH_RSA, self::ECDHE_ECDSA, self::ECDHE_RSA => true,
            default => false
        };
    }
}
