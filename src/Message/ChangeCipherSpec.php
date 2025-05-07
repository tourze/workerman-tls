<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\ContentType;

/**
 * ChangeCipherSpec 消息
 * 用于通知对端切换到新的加密参数
 */
class ChangeCipherSpec
{
    private readonly ContentType $type;

    public function __construct()
    {
        $this->type = ContentType::CHANGE_CIPHER_SPEC;
    }

    public function getType(): ContentType
    {
        return $this->type;
    }

    public function encode(): string
    {
        return "\x01"; // ChangeCipherSpec 消息固定为 0x01
    }

    public static function decode(string $data): self
    {
        if ($data !== "\x01") {
            throw new \InvalidArgumentException('Invalid ChangeCipherSpec message');
        }
        return new self();
    }
}
