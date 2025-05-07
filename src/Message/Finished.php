<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * Finished 消息
 * 用于验证握手过程的完整性
 */
class Finished extends HandshakeMessage
{
    public function __construct(
        private readonly string $verifyData
    ) {
        parent::__construct(HandshakeType::FINISHED);
    }

    public function encode(): string
    {
        return $this->verifyData;
    }

    public static function decode(string $data): self
    {
        return new self($data);
    }

    public function getVerifyData(): string
    {
        return $this->verifyData;
    }
}
