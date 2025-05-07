<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\PsrLogger\LogUtil;

/**
 * 收集和管理握手消息
 */
class HandshakeMessageCollector
{
    /** @var HandshakeMessage[] */
    private array $messages = [];

    public function addMessage(HandshakeMessage $message): void
    {
        $this->messages[] = $message;
        LogUtil::debug("Added message: " . $message->getType()->name);
    }

    /**
     * @return HandshakeMessage[]
     */
    public function getMessages(): array
    {
        return $this->messages;
    }

    public function clear(): void
    {
        $this->messages = [];
        LogUtil::info("Message collector cleared");
    }
}
