<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 证书验证消息
 */
class CertificateVerify extends HandshakeMessage
{
    public function __construct(
        private readonly string $signature,
        private readonly int $signatureAlgorithm
    ) {
        parent::__construct(HandshakeType::CERTIFICATE_VERIFY);
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getSignatureAlgorithm(): int
    {
        return $this->signatureAlgorithm;
    }

    public function encode(): string
    {
        return pack('n', $this->signatureAlgorithm) .
            pack('n', strlen($this->signature)) .
            $this->signature;
    }

    public static function decode(string $data): self
    {
        $algorithm = unpack('n', substr($data, 0, 2))[1];
        $length = unpack('n', substr($data, 2, 2))[1];
        $signature = substr($data, 4, $length);
        return new self($signature, $algorithm);
    }
}
