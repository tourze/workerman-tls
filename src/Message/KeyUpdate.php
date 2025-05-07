<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * TLS 1.3 密钥更新消息
 * @see RFC 8446 Section 4.6.3
 */
class KeyUpdate extends HandshakeMessage
{
    public const REQUEST_UPDATE = 1;
    public const NOT_REQUESTED = 0;

    public function __construct(
        private readonly int $requestUpdate
    ) {
        parent::__construct(HandshakeType::KEY_UPDATE);
    }

    public function getRequestUpdate(): int
    {
        return $this->requestUpdate;
    }

    public function encode(): string
    {
        return pack('C', $this->requestUpdate);
    }

    public static function decode(string $data): self
    {
        $requestUpdate = unpack('C', $data)[1];
        if (!in_array($requestUpdate, [self::REQUEST_UPDATE, self::NOT_REQUESTED])) {
            throw new \InvalidArgumentException('Invalid request_update value');
        }
        return new self($requestUpdate);
    }
}
