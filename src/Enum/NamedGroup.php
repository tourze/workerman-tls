<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS命名曲线组枚举
 * @see RFC 8446 Section 4.2.7
 */
enum NamedGroup: int
{
    // NIST curves (TLS 1.2 & 1.3)
    case SECP256R1 = 0x0017;
    case SECP384R1 = 0x0018;
    case SECP521R1 = 0x0019;

    // X25519/X448 (TLS 1.3)
    case X25519 = 0x001D;
    case X448 = 0x001E;

    // FFDHE groups (TLS 1.3)
    case FFDHE2048 = 0x0100;
    case FFDHE3072 = 0x0101;
    case FFDHE4096 = 0x0102;
    case FFDHE6144 = 0x0103;
    case FFDHE8192 = 0x0104;

    public function getNistName(): string
    {
        return match($this) {
            self::SECP256R1 => 'prime256v1',
            self::SECP384R1 => 'secp384r1',
            self::SECP521R1 => 'secp521r1',
            self::X25519 => 'x25519',
            self::X448 => 'x448',
            self::FFDHE2048 => 'ffdhe2048',
            self::FFDHE3072 => 'ffdhe3072',
            self::FFDHE4096 => 'ffdhe4096',
            self::FFDHE6144 => 'ffdhe6144',
            self::FFDHE8192 => 'ffdhe8192'
        };
    }

    public function getKeySize(): int
    {
        return match($this) {
            self::SECP256R1 => 256,
            self::SECP384R1 => 384,
            self::SECP521R1 => 521,
            self::X25519 => 256,
            self::X448 => 448,
            self::FFDHE2048 => 2048,
            self::FFDHE3072 => 3072,
            self::FFDHE4096 => 4096,
            self::FFDHE6144 => 6144,
            self::FFDHE8192 => 8192
        };
    }

    /**
     * 检查是否为TLS 1.3特有组
     */
    public function isTls13Only(): bool
    {
        return match($this) {
            self::X25519,
            self::X448,
            self::FFDHE2048,
            self::FFDHE3072,
            self::FFDHE4096,
            self::FFDHE6144,
            self::FFDHE8192 => true,
            default => false
        };
    }
}
