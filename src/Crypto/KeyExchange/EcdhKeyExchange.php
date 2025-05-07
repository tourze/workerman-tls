<?php

namespace Tourze\Workerman\TLS\Crypto\KeyExchange;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Message\ClientKeyExchange;

/**
 * ECDH 密钥交换实现
 */
class EcdhKeyExchange implements KeyExchangeInterface
{
    private string $privateKey;
    private string $publicKey;
    private ?string $premasterSecret = null;

    public function __construct()
    {
        // 生成 ECDH 密钥对
        $curve = 'secp256k1';
        $this->privateKey = random_bytes(32);
        $this->publicKey = openssl_pkey_derive(
            openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" .
                base64_encode($this->privateKey) . "\n-----END PUBLIC KEY-----\n"),
            $curve
        );
        LogUtil::info("Generated ECDH key pair");
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function generateClientKeyExchange(): string
    {
        // 生成客户端 ECDH 公钥
        $clientPrivateKey = random_bytes(32);
        $clientPublicKey = openssl_pkey_derive(
            openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" .
                base64_encode($clientPrivateKey) . "\n-----END PUBLIC KEY-----\n"),
            'secp256k1'
        );

        // 计算预主密钥
        $this->premasterSecret = openssl_pkey_derive(
            openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" .
                base64_encode($this->publicKey) . "\n-----END PUBLIC KEY-----\n"),
            'secp256k1',
            $clientPrivateKey
        );

        LogUtil::info("Generated client ECDH key exchange");
        return $clientPublicKey;
    }

    public function processClientKeyExchange(ClientKeyExchange $message): void
    {
        // 从消息中获取客户端公钥
        $clientPublicKey = $message->getClientPublicKey();

        // 计算预主密钥
        $this->premasterSecret = openssl_pkey_derive(
            openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" .
                base64_encode($clientPublicKey) . "\n-----END PUBLIC KEY-----\n"),
            'secp256k1',
            $this->privateKey
        );

        LogUtil::info("Processed client ECDH key exchange");
    }

    public function getPremasterSecret(): string
    {
        if ($this->premasterSecret === null) {
            throw new \RuntimeException('Premaster secret not available');
        }
        return $this->premasterSecret;
    }
}
