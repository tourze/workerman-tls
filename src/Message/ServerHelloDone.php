<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 服务器Hello完成消息
 */
class ServerHelloDone extends HandshakeMessage
{
    public function __construct()
    {
        parent::__construct(HandshakeType::SERVER_HELLO_DONE);
    }

    public function encode(): string
    {
        return ''; // ServerHelloDone消息没有内容
    }

    public static function decode(string $data): self
    {
        return new self();
    }
}
