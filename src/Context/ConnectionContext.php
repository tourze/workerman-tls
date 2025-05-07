<?php

namespace Tourze\Workerman\TLS\Context;

use Tourze\Workerman\TLS\Enum\CipherSuite;
use Tourze\Workerman\TLS\Enum\TlsVersion;
use Tourze\Workerman\TLS\Message\HandshakeMessage;

/**
 * TLS连接上下文
 */
class ConnectionContext
{
    private SecurityContext $securityContext;
    private CryptoContext $cryptoContext;
    private SessionContext $sessionContext;
    private HandshakeContext $handshakeContext;

    public function __construct(
        private readonly bool $isServer,
        array $supportedVersions = [TlsVersion::TLS_1_2],
        array $supportedCipherSuites = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ],
        array $certificates = [],
        array $privateKeys = []
    ) {
        $this->securityContext = new SecurityContext($supportedVersions, $supportedCipherSuites);
        $this->cryptoContext = new CryptoContext($isServer);
        $this->sessionContext = new SessionContext($isServer);
        $this->handshakeContext = new HandshakeContext(
            $isServer,
            $this->securityContext,
            $this->cryptoContext,
            $this->sessionContext,
            $certificates,
            $privateKeys
        );
    }

    public function isHandshakeCompleted(): bool
    {
        return $this->sessionContext->isHandshakeCompleted();
    }

    public function isEncryptionActive(): bool
    {
        return $this->cryptoContext->isEncryptionActive();
    }

    public function isCompressionActive(): bool
    {
        return $this->cryptoContext->isCompressionActive();
    }

    public function getMACSize(): int
    {
        return $this->cryptoContext->getMACSize();
    }

    public function decrypt(string $data, int $seqNum): string
    {
        return $this->cryptoContext->decrypt($data, $seqNum);
    }

    public function encrypt(string $data, int $seqNum): string
    {
        return $this->cryptoContext->encrypt($data, $seqNum);
    }

    public function decompress(string $data): string
    {
        return $this->cryptoContext->decompress($data);
    }

    public function compress(string $data): string
    {
        return $this->cryptoContext->compress($data);
    }

    public function verifyMAC(string $data, string $mac, int $seqNum, int $contentType): bool
    {
        return $this->cryptoContext->verifyMAC($data, $mac, $seqNum, $contentType);
    }

    public function calculateMAC(string $data, int $seqNum, int $contentType): string
    {
        return $this->cryptoContext->calculateMAC($data, $seqNum, $contentType);
    }

    public function activateEncryption(): void
    {
        $this->cryptoContext->activateEncryption();
    }

    public function getNegotiatedVersion(): ?TlsVersion
    {
        return $this->securityContext->getNegotiatedVersion();
    }

    public function getSelectedCipherSuite(): ?CipherSuite
    {
        return $this->securityContext->getSelectedCipherSuite();
    }

    /**
     * 处理握手消息
     * @return \Generator<HandshakeMessage>
     */
    public function handleHandshakeMessage(HandshakeMessage $message): \Generator
    {
        return $this->handshakeContext->handleHandshakeMessage($message);
    }

    public function activateClientToServerEncryption(): void
    {
        $this->cryptoContext->activateClientToServerEncryption();
    }

    public function activateServerToClientEncryption(): void
    {
        $this->cryptoContext->activateServerToClientEncryption();
    }
}
