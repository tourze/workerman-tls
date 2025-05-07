<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 证书请求消息
 */
class CertificateRequest extends HandshakeMessage
{
    public function __construct(
        private readonly array $certificateTypes,
        private readonly array $signatureAlgorithms,
        private readonly array $distinguishedNames
    ) {
        parent::__construct(HandshakeType::CERTIFICATE_REQUEST);
    }

    public function getCertificateTypes(): array
    {
        return $this->certificateTypes;
    }

    public function getSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithms;
    }

    public function getDistinguishedNames(): array
    {
        return $this->distinguishedNames;
    }

    public function encode(): string
    {
        // 证书类型列表
        $data = pack('C', count($this->certificateTypes));
        foreach ($this->certificateTypes as $type) {
            $data .= pack('C', $type);
        }

        // 签名算法列表
        $sigAlgData = '';
        foreach ($this->signatureAlgorithms as $algorithm) {
            $sigAlgData .= pack('n', $algorithm);
        }
        $data .= pack('n', strlen($sigAlgData)) . $sigAlgData;

        // DN列表
        $dnData = '';
        foreach ($this->distinguishedNames as $dn) {
            $dnData .= pack('n', strlen($dn)) . $dn;
        }
        $data .= pack('n', strlen($dnData)) . $dnData;

        return $data;
    }

    public static function decode(string $data): self
    {
        $offset = 0;

        // 解析证书类型列表
        $certTypesCount = ord($data[$offset]);
        $offset++;
        $certTypes = [];
        for ($i = 0; $i < $certTypesCount; $i++) {
            $certTypes[] = ord($data[$offset + $i]);
        }
        $offset += $certTypesCount;

        // 解析签名算法列表
        $sigAlgLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $sigAlgs = [];
        for ($i = 0; $i < $sigAlgLength; $i += 2) {
            $sigAlgs[] = unpack('n', substr($data, $offset + $i, 2))[1];
        }
        $offset += $sigAlgLength;

        // 解析DN列表
        $dnLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $dns = [];
        $endOffset = $offset + $dnLength;
        while ($offset < $endOffset) {
            $len = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            $dns[] = substr($data, $offset, $len);
            $offset += $len;
        }

        return new self($certTypes, $sigAlgs, $dns);
    }
}
