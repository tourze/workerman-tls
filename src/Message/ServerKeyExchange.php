<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 服务器密钥交换消息
 */
class ServerKeyExchange extends HandshakeMessage
{
    public function __construct(
        private readonly string $publicKey,
        private readonly int $curveType,
        private readonly int $curveValue,
        private readonly int $signatureAlgorithm,
        private readonly string $signature
    ) {
        parent::__construct(HandshakeType::SERVER_KEY_EXCHANGE);
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getCurveType(): int
    {
        return $this->curveType;
    }

    public function getCurveValue(): int
    {
        return $this->curveValue;
    }

    public function getSignatureAlgorithm(): int
    {
        return $this->signatureAlgorithm;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function encode(): string
    {
        return pack('C', $this->curveType) .
            pack('n', $this->curveValue) .
            pack('C', strlen($this->publicKey)) .
            $this->publicKey .
            pack('n', $this->signatureAlgorithm) .
            pack('n', strlen($this->signature)) .
            $this->signature;
    }

    public static function decode(string $data): self
    {
        $offset = 0;

        // 解析曲线类型
        $curveType = ord($data[$offset]);
        $offset++;

        // 解析曲线值
        $curveValue = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // 解析公钥
        $publicKeyLength = ord($data[$offset]);
        $offset++;
        $publicKey = substr($data, $offset, $publicKeyLength);
        $offset += $publicKeyLength;

        // 解析签名算法
        $signatureAlgorithm = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // 解析签名
        $signatureLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $signature = substr($data, $offset, $signatureLength);

        return new self(
            $publicKey,
            $curveType,
            $curveValue,
            $signatureAlgorithm,
            $signature
        );
    }
}
