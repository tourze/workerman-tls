<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS记录层内容类型
 * @see RFC 5246 Section 6.2.1
 */
enum ContentType: int
{
    case CHANGE_CIPHER_SPEC = 20;  // 密码规格变更协议
    case ALERT = 21;              // 警告协议
    case HANDSHAKE = 22;          // 握手协议
    case APPLICATION_DATA = 23;    // 应用数据协议

    public function toString(): string
    {
        return match($this) {
            self::CHANGE_CIPHER_SPEC => 'ChangeCipherSpec',
            self::ALERT => 'Alert',
            self::HANDSHAKE => 'Handshake',
            self::APPLICATION_DATA => 'ApplicationData'
        };
    }
}
