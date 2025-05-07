<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * TLS 1.3 新会话票据消息
 * @see RFC 8446 Section 4.6.1
 */
class NewSessionTicket extends HandshakeMessage
{
    public function __construct(
        private readonly int $ticketLifetime,
        private readonly int $ticketAgeAdd,
        private readonly string $ticketNonce,
        private readonly string $ticket,
        private readonly array $extensions = []
    ) {
        parent::__construct(HandshakeType::NEW_SESSION_TICKET);
    }

    public function getTicketLifetime(): int
    {
        return $this->ticketLifetime;
    }

    public function getTicketAgeAdd(): int
    {
        return $this->ticketAgeAdd;
    }

    public function getTicketNonce(): string
    {
        return $this->ticketNonce;
    }

    public function getTicket(): string
    {
        return $this->ticket;
    }

    public function getExtensions(): array
    {
        return $this->extensions;
    }

    public function encode(): string
    {
        $data = pack('N', $this->ticketLifetime) .
            pack('N', $this->ticketAgeAdd) .
            pack('C', strlen($this->ticketNonce)) .
            $this->ticketNonce .
            pack('n', strlen($this->ticket)) .
            $this->ticket;

        // 添加扩展
        $extensionsData = '';
        foreach ($this->extensions as $type => $content) {
            $extensionsData .= pack('n', $type) .
                pack('n', strlen($content)) .
                $content;
        }
        $data .= pack('n', strlen($extensionsData)) . $extensionsData;

        return $data;
    }

    public static function decode(string $data): self
    {
        $offset = 0;

        // 读取票据生命周期
        $ticketLifetime = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;

        // 读取票据年龄增量
        $ticketAgeAdd = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;

        // 读取票据随机数
        $nonceLength = unpack('C', substr($data, $offset, 1))[1];
        $offset += 1;
        $ticketNonce = substr($data, $offset, $nonceLength);
        $offset += $nonceLength;

        // 读取票据
        $ticketLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $ticket = substr($data, $offset, $ticketLength);
        $offset += $ticketLength;

        // 读取扩展
        $extensions = [];
        $extensionsLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $extensionsEnd = $offset + $extensionsLength;

        while ($offset < $extensionsEnd) {
            $type = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            $length = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            $content = substr($data, $offset, $length);
            $offset += $length;
            $extensions[$type] = $content;
        }

        return new self(
            $ticketLifetime,
            $ticketAgeAdd,
            $ticketNonce,
            $ticket,
            $extensions
        );
    }
}
