<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 客户端密钥交换消息
 */
class ClientKeyExchange extends HandshakeMessage
{
    public function __construct(
        private readonly string $clientPublicKey
    ) {
        parent::__construct(HandshakeType::CLIENT_KEY_EXCHANGE);
    }

    public function encode(): string
    {
        // 编码公钥长度和公钥
        return pack('n', strlen($this->clientPublicKey)) . $this->clientPublicKey;
    }

    public static function decode(string $data): self
    {
        // 解码公钥长度和公钥
        $length = unpack('n', substr($data, 0, 2))[1];
        $publicKey = substr($data, 2, $length);
        return new self($publicKey);
    }

    public function getClientPublicKey(): string
    {
        return $this->clientPublicKey;
    }
}
