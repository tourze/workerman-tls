<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * TLS 1.3 加密扩展消息
 * @see RFC 8446 Section 4.3.1
 */
class EncryptedExtensions extends HandshakeMessage
{
    public function __construct(
        private readonly array $extensions = []
    ) {
        parent::__construct(HandshakeType::ENCRYPTED_EXTENSIONS);
    }

    public function getExtensions(): array
    {
        return $this->extensions;
    }

    public function encode(): string
    {
        $extensionsData = '';
        foreach ($this->extensions as $type => $content) {
            $extensionsData .= pack('n', $type) .
                pack('n', strlen($content)) .
                $content;
        }
        return pack('n', strlen($extensionsData)) . $extensionsData;
    }

    public static function decode(string $data): self
    {
        $offset = 0;
        $extensions = [];

        // 读取扩展总长度
        $extensionsLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // 读取所有扩展
        while ($offset < strlen($data)) {
            // 读取扩展类型
            $type = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;

            // 读取扩展长度
            $length = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;

            // 读取扩展内容
            $content = substr($data, $offset, $length);
            $offset += $length;

            $extensions[$type] = $content;
        }

        return new self($extensions);
    }
}
