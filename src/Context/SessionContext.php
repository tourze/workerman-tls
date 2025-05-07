<?php

namespace Tourze\Workerman\TLS\Context;

use Tourze\Workerman\PsrLogger\LogUtil;

/**
 * 管理TLS会话状态
 */
class SessionContext
{
    private bool $isHandshakeCompleted = false;
    private ?string $sessionTicket = null;
    private ?string $sessionId = null;
    private array $sessionData = [];

    public function __construct(
        private readonly bool $isServer,
        private readonly bool $enableSessionResumption = true
    )
    {
    }

    public function isHandshakeCompleted(): bool
    {
        return $this->isHandshakeCompleted;
    }

    public function markHandshakeCompleted(): void
    {
        $this->isHandshakeCompleted = true;
        LogUtil::info('Handshake marked as completed');
    }

    public function getSessionTicket(): ?string
    {
        return $this->sessionTicket;
    }

    public function setSessionTicket(string $ticket): void
    {
        $this->sessionTicket = $ticket;
        LogUtil::info('Session ticket set');
    }

    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function setSessionId(string $id): void
    {
        assert(strlen($id) <= 32, 'Session ID cannot exceed 32 bytes');
        $this->sessionId = $id;
        LogUtil::info('Session ID set');
    }

    public function isSessionResumptionEnabled(): bool
    {
        return $this->enableSessionResumption;
    }

    public function saveSessionData(array $data): void
    {
        $this->sessionData = $data;
        LogUtil::info('Session data saved');
    }

    public function getSessionData(): array
    {
        return $this->sessionData;
    }

    public function clearSession(): void
    {
        $this->sessionTicket = null;
        $this->sessionId = null;
        $this->sessionData = [];
        LogUtil::info('Session cleared');
    }
}
