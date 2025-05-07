<?php

namespace Tourze\Workerman\TLS\State;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Enum\HandshakeType;
use Tourze\Workerman\TLS\Message\HandshakeMessageInterface;

/**
 * 管理TLS握手状态机
 */
class HandshakeStateManager
{
    private ?HandshakeType $nextMessageType = null;
    private bool $handshakeCompleted = false;

    public function __construct(
        private readonly bool $isServer
    ) {}

    public function isHandshakeCompleted(): bool
    {
        return $this->handshakeCompleted;
    }

    public function getNextMessageType(): ?HandshakeType
    {
        return $this->nextMessageType;
    }

    public function validateMessageType(HandshakeType $type): bool
    {
        if ($this->nextMessageType === null) {
            // 初始状态只接受ClientHello
            return $type === HandshakeType::CLIENT_HELLO;
        }

        return $type === $this->nextMessageType;
    }

    public function updateState(HandshakeMessageInterface $message): void
    {
        $currentType = $message->getType();
        LogUtil::info("Updating state from message type: " . $currentType->name);

        $this->nextMessageType = match($currentType) {
            HandshakeType::CLIENT_HELLO => HandshakeType::CLIENT_KEY_EXCHANGE,
            HandshakeType::CLIENT_KEY_EXCHANGE => HandshakeType::CERTIFICATE_VERIFY,
            HandshakeType::CERTIFICATE_VERIFY => HandshakeType::FINISHED,
            HandshakeType::FINISHED => null,
            default => throw new \InvalidArgumentException("Unexpected message type: {$currentType->name}")
        };

        if ($this->nextMessageType === null) {
            $this->handshakeCompleted = true;
            LogUtil::info('Handshake completed');
        } else {
            LogUtil::debug("Next expected message type: {$this->nextMessageType->name}");
        }
    }

    public function reset(): void
    {
        $this->nextMessageType = null;
        $this->handshakeCompleted = false;
        LogUtil::info('State machine reset');
    }
}
