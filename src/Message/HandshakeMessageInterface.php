<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 握手消息接口
 */
interface HandshakeMessageInterface
{
    public function getType(): HandshakeType;
    public function encode(): string;
    public function serialize(): string;
    public static function deserialize(string $data): self;
}
