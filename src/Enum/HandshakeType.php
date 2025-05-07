<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * SSL/TLS握手协议消息类型
 * @see RFC 5246 Section 7.4 (TLS 1.2)
 * @see RFC 8446 Section 4 (TLS 1.3)
 */
enum HandshakeType: int
{
    case HELLO_REQUEST = 0;        // 服务端→客户端 (TLS 1.2)
    case CLIENT_HELLO = 1;        // 客户端→服务端
    case SERVER_HELLO = 2;        // 服务端→客户端
    case NEW_SESSION_TICKET = 4;  // 服务端→客户端 (TLS 1.3)
    case END_OF_EARLY_DATA = 5;   // 客户端→服务端 (TLS 1.3)
    case ENCRYPTED_EXTENSIONS = 8; // 服务端→客户端 (TLS 1.3)
    case CERTIFICATE = 11;        // 双向
    case SERVER_KEY_EXCHANGE = 12; // 服务端→客户端 (TLS 1.2)
    case CERTIFICATE_REQUEST = 13; // 服务端→客户端
    case SERVER_HELLO_DONE = 14;  // 服务端→客户端 (TLS 1.2)
    case CERTIFICATE_VERIFY = 15; // 客户端→服务端
    case CLIENT_KEY_EXCHANGE = 16; // 客户端→服务端 (TLS 1.2)
    case FINISHED = 20;           // 双向
    case KEY_UPDATE = 24;         // 双向 (TLS 1.3)
    case MESSAGE_HASH = 254;      // 内部使用 (TLS 1.3)

    /**
     * 获取消息方向
     */
    public function getDirection(): MessageDirection
    {
        return match($this) {
            self::CLIENT_HELLO,
            self::END_OF_EARLY_DATA,
            self::CERTIFICATE_VERIFY,
            self::CLIENT_KEY_EXCHANGE => MessageDirection::CLIENT_TO_SERVER,

            self::HELLO_REQUEST,
            self::SERVER_HELLO,
            self::NEW_SESSION_TICKET,
            self::ENCRYPTED_EXTENSIONS,
            self::SERVER_KEY_EXCHANGE,
            self::CERTIFICATE_REQUEST,
            self::SERVER_HELLO_DONE => MessageDirection::SERVER_TO_CLIENT,

            self::CERTIFICATE,
            self::FINISHED,
            self::KEY_UPDATE,
            self::MESSAGE_HASH => MessageDirection::BOTH
        };
    }

    /**
     * 检查是否为TLS 1.3特有消息类型
     */
    public function isTls13Only(): bool
    {
        return match($this) {
            self::NEW_SESSION_TICKET,
            self::END_OF_EARLY_DATA,
            self::ENCRYPTED_EXTENSIONS,
            self::KEY_UPDATE,
            self::MESSAGE_HASH => true,
            default => false
        };
    }

    /**
     * 检查是否为TLS 1.2特有消息类型
     */
    public function isTls12Only(): bool
    {
        return match($this) {
            self::HELLO_REQUEST,
            self::SERVER_KEY_EXCHANGE,
            self::SERVER_HELLO_DONE,
            self::CLIENT_KEY_EXCHANGE => true,
            default => false
        };
    }

    public function validateDirection(bool $isServer): bool
    {
        return $this->getDirection()->isValidFor($isServer);
    }
}
