<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 证书消息
 */
class Certificate extends HandshakeMessage
{
    public function __construct(
        private readonly array $certificates
    ) {
        parent::__construct(HandshakeType::CERTIFICATE);
    }

    public function getCertificates(): array
    {
        return $this->certificates;
    }

    public function encode(): string
    {
        $certificatesData = '';
        foreach ($this->certificates as $cert) {
            $length = strlen($cert);
            $certificatesData .= pack('N', $length) . $cert;
        }

        return pack('N', strlen($certificatesData)) . $certificatesData;
    }

    public static function decode(string $data): self
    {
        $totalLength = unpack('N', substr($data, 0, 4))[1];
        $offset = 4;
        $certificates = [];

        while ($offset < $totalLength + 4) {
            $length = unpack('N', substr($data, $offset, 4))[1];
            $offset += 4;
            $certificates[] = substr($data, $offset, $length);
            $offset += $length;
        }

        return new self($certificates);
    }
}
