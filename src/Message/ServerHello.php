<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\{CipherSuite, HandshakeType, TlsVersion};

/**
 * 服务器Hello消息
 */
class ServerHello extends HandshakeMessage
{
    public function __construct(
        private readonly string $random,
        private readonly CipherSuite $cipherSuite,
        private readonly TlsVersion $version,
        private readonly string $sessionId,
        private readonly int $compressionMethod,
        private readonly array $extensions = []
    ) {
        parent::__construct(HandshakeType::SERVER_HELLO);
    }

    public function getRandom(): string
    {
        return $this->random;
    }

    public function getCipherSuite(): CipherSuite
    {
        return $this->cipherSuite;
    }

    public function getVersion(): TlsVersion
    {
        return $this->version;
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    public function getCompressionMethod(): int
    {
        return $this->compressionMethod;
    }

    public function getExtensions(): array
    {
        return $this->extensions;
    }

    public function encode(): string
    {
        $data = pack('n', $this->version->value) .
            $this->random .
            pack('C', strlen($this->sessionId)) .
            $this->sessionId .
            pack('n', $this->cipherSuite->value) .
            pack('C', $this->compressionMethod);

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

        // 解析版本
        $version = TlsVersion::from(unpack('n', substr($data, $offset, 2))[1]);
        $offset += 2;

        // 解析随机数
        $random = substr($data, $offset, 32);
        $offset += 32;

        // 解析会话ID
        $sessionIdLength = ord($data[$offset]);
        $offset++;
        $sessionId = substr($data, $offset, $sessionIdLength);
        $offset += $sessionIdLength;

        // 解析密码套件
        $cipherSuite = CipherSuite::from(unpack('n', substr($data, $offset, 2))[1]);
        $offset += 2;

        // 解析压缩方法
        $compressionMethod = ord($data[$offset]);
        $offset++;

        // 解析扩展
        $extensions = [];
        if ($offset < strlen($data)) {
            $extensionsLength = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            $endOffset = $offset + $extensionsLength;
            while ($offset < $endOffset) {
                $type = unpack('n', substr($data, $offset, 2))[1];
                $offset += 2;
                $length = unpack('n', substr($data, $offset, 2))[1];
                $offset += 2;
                $extensions[$type] = substr($data, $offset, $length);
                $offset += $length;
            }
        }

        return new self(
            $random,
            $cipherSuite,
            $version,
            $sessionId,
            $compressionMethod,
            $extensions
        );
    }
}
