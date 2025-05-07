<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\{HandshakeType, TlsVersion};

/**
 * 客户端Hello消息
 */
class ClientHello extends HandshakeMessage
{
    public function __construct(
        private readonly TlsVersion $version,
        private readonly string $random,
        private readonly string $sessionId,
        private readonly array $cipherSuites,
        private readonly array $compressionMethods,
        private readonly array $extensions = []
    ) {
        parent::__construct(HandshakeType::CLIENT_HELLO);
    }

    public function getVersion(): TlsVersion
    {
        return $this->version;
    }

    public function getRandom(): string
    {
        return $this->random;
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    public function getCipherSuites(): array
    {
        return $this->cipherSuites;
    }

    public function getCompressionMethods(): array
    {
        return $this->compressionMethods;
    }

    public function getExtensions(): array
    {
        return $this->extensions;
    }

    public function getSupportedGroups(): array
    {
        // 扩展类型 10 是 supported_groups
        if (!isset($this->extensions[10])) {
            return [];
        }

        $data = $this->extensions[10];
        if (strlen($data) < 2) {
            return [];
        }

        // 解析长度
        $length = unpack('n', substr($data, 0, 2))[1];
        $groups = [];

        // 解析每个组
        for ($i = 2; $i < strlen($data); $i += 2) {
            $groups[] = unpack('n', substr($data, $i, 2))[1];
        }

        return $groups;
    }

    public function encode(): string
    {
        $data = pack('n', $this->version->value) .
            $this->random .
            pack('C', strlen($this->sessionId)) .
            $this->sessionId;

        // 密码套件
        $cipherSuitesData = '';
        foreach ($this->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $data .= pack('n', strlen($cipherSuitesData)) . $cipherSuitesData;

        // 压缩方法
        $data .= pack('C', count($this->compressionMethods));
        foreach ($this->compressionMethods as $method) {
            $data .= pack('C', $method);
        }

        // 扩展
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
        $cipherSuitesLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $cipherSuites = [];
        for ($i = 0; $i < $cipherSuitesLength; $i += 2) {
            $cipherSuites[] = unpack('n', substr($data, $offset + $i, 2))[1];
        }
        $offset += $cipherSuitesLength;

        // 解析压缩方法
        $compressionMethodsLength = ord($data[$offset]);
        $offset++;
        $compressionMethods = [];
        for ($i = 0; $i < $compressionMethodsLength; $i++) {
            $compressionMethods[] = ord($data[$offset + $i]);
        }
        $offset += $compressionMethodsLength;

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
            $version,
            $random,
            $sessionId,
            $cipherSuites,
            $compressionMethods,
            $extensions
        );
    }
}
