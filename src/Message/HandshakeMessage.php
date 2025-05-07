<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 握手消息基类
 */
abstract class HandshakeMessage implements HandshakeMessageInterface
{
    public function __construct(
        private readonly HandshakeType $type
    ) {}

    public function getType(): HandshakeType
    {
        return $this->type;
    }

    /**
     * 序列化消息
     */
    public function serialize(): string
    {
        $body = $this->encode();
        $length = strlen($body);

        // 消息头: 1字节类型 + 3字节长度
        $header = pack('C', $this->type->value) .
            chr(($length >> 16) & 0xFF) .
            chr(($length >> 8) & 0xFF) .
            chr($length & 0xFF);

        return $header . $body;
    }

    /**
     * 反序列化消息
     */
    public static function deserialize(string $data): HandshakeMessageInterface
    {
        // 解析消息头
        $type = ord($data[0]);
        $length = (ord($data[1]) << 16) | (ord($data[2]) << 8) | ord($data[3]);
        $body = substr($data, 4, $length);

        // 根据类型解码消息体
        return static::decode($body);
    }

    /**
     * 编码消息体
     */
    abstract public function encode(): string;

    /**
     * 解码消息体
     */
    abstract public static function decode(string $data): self;
}
