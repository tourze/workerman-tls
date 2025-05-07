<?php

namespace Tourze\Workerman\TLS\Service\Handshake;

use Tourze\Workerman\TLS\Enum\HandshakeState;

class StateMachine
{
    private HandshakeState $currentState = HandshakeState::START;

    public function transition(string $event): void
    {
        $this->currentState = match ($this->currentState) {
            HandshakeState::START => match ($event) {
                'client_hello_received' => HandshakeState::CLIENT_HELLO_SENT,
                default => throw new \InvalidArgumentException('Invalid transition')
            },
            HandshakeState::CLIENT_HELLO_SENT => match ($event) {
                'server_hello_sent' => HandshakeState::SERVER_HELLO_SENT,
                default => throw new \InvalidArgumentException('Invalid transition')
            },
            // 补充完整的状态转换逻辑
            default => throw new \RuntimeException('Unhandled state transition')
        };
    }

    public function getCurrentState(): HandshakeState
    {
        return $this->currentState;
    }
}
