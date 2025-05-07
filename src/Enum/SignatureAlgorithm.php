<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS签名算法枚举
 * @see RFC 8446 Section 4.2.3
 */
enum SignatureAlgorithm: int
{
    // TLS 1.2 算法
    /** @var int RSA PKCS#1 v1.5 签名算法，使用 SHA-256 哈希 */
    case RSA_PKCS1_SHA256 = 0x0401;
    /** @var int RSA PKCS#1 v1.5 签名算法，使用 SHA-384 哈希 */
    case RSA_PKCS1_SHA384 = 0x0501;
    /** @var int RSA PKCS#1 v1.5 签名算法，使用 SHA-512 哈希 */
    case RSA_PKCS1_SHA512 = 0x0601;
    /** @var int ECDSA 签名算法，使用 NIST P-256 曲线和 SHA-256 哈希 */
    case ECDSA_SECP256R1_SHA256 = 0x0403;
    /** @var int ECDSA 签名算法，使用 NIST P-384 曲线和 SHA-384 哈希 */
    case ECDSA_SECP384R1_SHA384 = 0x0503;
    /** @var int ECDSA 签名算法，使用 NIST P-521 曲线和 SHA-512 哈希 */
    case ECDSA_SECP521R1_SHA512 = 0x0603;

    // TLS 1.3 算法
    /** @var int RSA PSS RSAE 签名算法，使用 SHA-256 哈希 */
    case RSA_PSS_RSAE_SHA256 = 0x0804;
    /** @var int RSA PSS RSAE 签名算法，使用 SHA-384 哈希 */
    case RSA_PSS_RSAE_SHA384 = 0x0805;
    /** @var int RSA PSS RSAE 签名算法，使用 SHA-512 哈希 */
    case RSA_PSS_RSAE_SHA512 = 0x0806;
    /** @var int RSA PSS PSS 签名算法，使用 SHA-256 哈希 */
    case RSA_PSS_PSS_SHA256 = 0x0809;
    /** @var int RSA PSS PSS 签名算法，使用 SHA-384 哈希 */
    case RSA_PSS_PSS_SHA384 = 0x080A;
    /** @var int RSA PSS PSS 签名算法，使用 SHA-512 哈希 */
    case RSA_PSS_PSS_SHA512 = 0x080B;
    /** @var int EdDSA 签名算法，使用 Ed25519 曲线 */
    case ED25519 = 0x0807;
    /** @var int EdDSA 签名算法，使用 Ed448 曲线 */
    case ED448 = 0x0808;

    public function getHash(): string 
    {
        return match($this) {
            // TLS 1.2 算法
            self::RSA_PKCS1_SHA256, self::ECDSA_SECP256R1_SHA256 => 'sha256',
            self::RSA_PKCS1_SHA384, self::ECDSA_SECP384R1_SHA384 => 'sha384',
            self::RSA_PKCS1_SHA512, self::ECDSA_SECP521R1_SHA512 => 'sha512',
            // TLS 1.3 算法
            self::RSA_PSS_RSAE_SHA256, self::RSA_PSS_PSS_SHA256 => 'sha256',
            self::RSA_PSS_RSAE_SHA384, self::RSA_PSS_PSS_SHA384 => 'sha384',
            self::RSA_PSS_RSAE_SHA512, self::RSA_PSS_PSS_SHA512 => 'sha512',
            self::ED25519 => 'sha512',
            self::ED448 => 'shake256'
        };
    }

    /**
     * 检查是否为TLS 1.3特有算法
     */
    public function isTls13Only(): bool
    {
        return match($this) {
            self::RSA_PSS_RSAE_SHA256,
            self::RSA_PSS_RSAE_SHA384,
            self::RSA_PSS_RSAE_SHA512,
            self::RSA_PSS_PSS_SHA256,
            self::RSA_PSS_PSS_SHA384,
            self::RSA_PSS_PSS_SHA512,
            self::ED25519,
            self::ED448 => true,
            default => false
        };
    }

    /**
     * 检查是否为TLS 1.2特有算法
     */
    public function isTls12Only(): bool
    {
        return match($this) {
            self::RSA_PKCS1_SHA256,
            self::RSA_PKCS1_SHA384,
            self::RSA_PKCS1_SHA512,
            self::ECDSA_SECP256R1_SHA256,
            self::ECDSA_SECP384R1_SHA384,
            self::ECDSA_SECP521R1_SHA512 => true,
            default => false
        };
    }

    /**
     * 获取算法的中文标签
     */
    public function getLabel(): string
    {
        return match($this) {
            // TLS 1.2 算法
            self::RSA_PKCS1_SHA256 => 'RSA-PKCS1-SHA256',
            self::RSA_PKCS1_SHA384 => 'RSA-PKCS1-SHA384',
            self::RSA_PKCS1_SHA512 => 'RSA-PKCS1-SHA512',
            self::ECDSA_SECP256R1_SHA256 => 'ECDSA-P256-SHA256',
            self::ECDSA_SECP384R1_SHA384 => 'ECDSA-P384-SHA384',
            self::ECDSA_SECP521R1_SHA512 => 'ECDSA-P521-SHA512',
            // TLS 1.3 算法
            self::RSA_PSS_RSAE_SHA256 => 'RSA-PSS-RSAE-SHA256',
            self::RSA_PSS_RSAE_SHA384 => 'RSA-PSS-RSAE-SHA384',
            self::RSA_PSS_RSAE_SHA512 => 'RSA-PSS-RSAE-SHA512',
            self::RSA_PSS_PSS_SHA256 => 'RSA-PSS-PSS-SHA256',
            self::RSA_PSS_PSS_SHA384 => 'RSA-PSS-PSS-SHA384',
            self::RSA_PSS_PSS_SHA512 => 'RSA-PSS-PSS-SHA512',
            self::ED25519 => 'Ed25519',
            self::ED448 => 'Ed448'
        };
    }

    /**
     * 检查是否为 RSA 算法
     */
    public function isRsa(): bool
    {
        return match($this) {
            self::RSA_PKCS1_SHA256,
            self::RSA_PKCS1_SHA384,
            self::RSA_PKCS1_SHA512,
            self::RSA_PSS_RSAE_SHA256,
            self::RSA_PSS_RSAE_SHA384,
            self::RSA_PSS_RSAE_SHA512,
            self::RSA_PSS_PSS_SHA256,
            self::RSA_PSS_PSS_SHA384,
            self::RSA_PSS_PSS_SHA512 => true,
            default => false
        };
    }

    /**
     * 检查是否为 ECDSA 算法
     */
    public function isEcdsa(): bool
    {
        return match($this) {
            self::ECDSA_SECP256R1_SHA256,
            self::ECDSA_SECP384R1_SHA384,
            self::ECDSA_SECP521R1_SHA512 => true,
            default => false
        };
    }

    /**
     * 检查是否为 EdDSA 算法
     */
    public function isEdDsa(): bool
    {
        return match($this) {
            self::ED25519,
            self::ED448 => true,
            default => false
        };
    }
}
