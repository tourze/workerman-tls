<?php

namespace Tourze\Workerman\TLS\Context;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Certificate\CertificateStore;
use Tourze\Workerman\TLS\Crypto\KeyExchange\EcdhKeyExchange;
use Tourze\Workerman\TLS\Crypto\KeyExchange\KeyExchangeInterface;
use Tourze\Workerman\TLS\Enum\CipherSuite;
use Tourze\Workerman\TLS\Enum\SignatureAlgorithm;
use Tourze\Workerman\TLS\Enum\TlsVersion;
use Tourze\Workerman\TLS\Message\CertificateVerify;
use Tourze\Workerman\TLS\Message\Finished;
use Tourze\Workerman\TLS\Message\HandshakeMessage;
use Tourze\Workerman\TLS\Message\ServerKeyExchange;

/**
 * 管理TLS安全参数
 */
class SecurityContext
{
    private ?TlsVersion $negotiatedVersion = null;
    private ?CipherSuite $selectedCipherSuite = null;
    private ?string $clientRandom = null;
    private ?string $serverRandom = null;
    private ?string $masterSecret = null;
    private bool $clientCertificateRequested = false;
    private ?KeyExchangeInterface $keyExchange = null;
    private string $handshakeMessages = '';
    private bool $earlyDataAllowed = false;
    private ?string $resumptionMasterSecret = null;

    public function __construct(
        private readonly array $supportedVersions,
        private readonly array $supportedCipherSuites
    )
    {
        $this->keyExchange = new EcdhKeyExchange();
    }

    public function selectVersion(TlsVersion $clientVersion): ?TlsVersion
    {
        // 选择双方都支持的最高版本
        $version = null;
        foreach ($this->supportedVersions as $supportedVersion) {
            if ($supportedVersion <= $clientVersion &&
                ($version === null || $supportedVersion > $version)) {
                $version = $supportedVersion;
            }
        }

        if ($version !== null) {
            $this->negotiatedVersion = $version;
            LogUtil::info("Selected TLS version: " . $version->name);
        }

        return $version;
    }

    public function selectCipherSuite(array $clientCipherSuites): ?CipherSuite
    {
        // 根据协商的TLS版本过滤密码套件
        $supportedSuites = array_filter(
            $this->supportedCipherSuites,
            fn($suite) => match($this->negotiatedVersion) {
                TlsVersion::TLS_1_3 => $suite->isTls13(),
                default => !$suite->isTls13()
            }
        );

        // 选择双方都支持的第一个密码套件
        foreach ($clientCipherSuites as $clientCipherSuite) {
            if (in_array($clientCipherSuite, $supportedSuites)) {
                $this->selectedCipherSuite = $clientCipherSuite;
                LogUtil::info("Selected cipher suite: " . $clientCipherSuite->name);
                return $clientCipherSuite;
            }
        }

        return null;
    }

    public function isVersionSupported(TlsVersion $version): bool
    {
        return in_array($version, $this->supportedVersions);
    }

    public function isCipherSuiteSupported(CipherSuite $cipherSuite): bool
    {
        return in_array($cipherSuite, $this->supportedCipherSuites);
    }

    public function setClientRandom(string $random): void
    {
        assert(strlen($random) === 32, 'Client random must be 32 bytes');
        $this->clientRandom = $random;
    }

    public function setServerRandom(string $random): void
    {
        assert(strlen($random) === 32, 'Server random must be 32 bytes');
        $this->serverRandom = $random;
    }

    public function getClientRandom(): string
    {
        assert($this->clientRandom !== null, 'Client random not set');
        return $this->clientRandom;
    }

    public function getServerRandom(): string
    {
        assert($this->serverRandom !== null, 'Server random not set');
        return $this->serverRandom;
    }

    public function getNegotiatedVersion(): ?TlsVersion
    {
        return $this->negotiatedVersion;
    }

    public function getSelectedCipherSuite(): ?CipherSuite
    {
        return $this->selectedCipherSuite;
    }

    public function requiresClientAuth(): bool
    {
        // 目前总是要求客户端证书
        return true;
    }

    public function getSupportedSignatureAlgorithms(): array
    {
        // 根据TLS版本返回支持的签名算法
        return match($this->negotiatedVersion) {
            TlsVersion::TLS_1_3 => [
                SignatureAlgorithm::ED25519,
                SignatureAlgorithm::ED448,
                SignatureAlgorithm::RSA_PSS_PSS_SHA256,
                SignatureAlgorithm::RSA_PSS_PSS_SHA384,
                SignatureAlgorithm::RSA_PSS_PSS_SHA512,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA512
            ],
            default => [
                SignatureAlgorithm::RSA_PKCS1_SHA256,
                SignatureAlgorithm::RSA_PKCS1_SHA384,
                SignatureAlgorithm::RSA_PKCS1_SHA512,
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
                SignatureAlgorithm::ECDSA_SECP521R1_SHA512
            ]
        };
    }

    public function getAcceptableCAs(): array
    {
        // 返回可接受的CA证书列表
        $caDir = __DIR__ . '/../Resources/certs/ca';
        $cas = [];

        foreach (glob($caDir . '/*.crt') as $caFile) {
            $cas[] = openssl_x509_read(file_get_contents($caFile));
        }

        return $cas;
    }

    public function getServerEphemeralKey(): string
    {
        return $this->keyExchange->getPublicKey();
    }

    public function verifyServerKeyExchange(ServerKeyExchange $message, string $serverCertificate): bool
    {
        // 验证服务器密钥交换参数
        $publicKey = $message->getPublicKey();
        $signature = $message->getSignature();
        $signedData = $this->clientRandom . $this->serverRandom . $publicKey;

        // 使用服务器证书的公钥验证签名
        return openssl_verify(
                $signedData,
                $signature,
                $serverCertificate,
                OPENSSL_ALGO_SHA256
            ) === 1;
    }

    public function generateClientKeyExchange(): string
    {
        return $this->keyExchange->generateClientKeyExchange();
    }

    public function processClientKeyExchange(HandshakeMessage $message): void
    {
        $this->keyExchange->processClientKeyExchange($message);
        $this->deriveMasterSecret();
    }

    public function generateCertificateVerify(string $privateKey): string
    {
        // 生成证书验证消息
        $signedData = $this->handshakeMessages;
        $signature = '';
        openssl_sign($signedData, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        return $signature;
    }

    public function verifyCertificateVerify(HandshakeMessage $message, string $clientCertificate): bool
    {
        assert($message instanceof CertificateVerify);

        // 验证客户端证书签名
        $signature = $message->getSignature();
        $signedData = $this->handshakeMessages;

        return openssl_verify(
                $signedData,
                $signature,
                $clientCertificate,
                OPENSSL_ALGO_SHA256
            ) === 1;
    }

    public function verifyCertificateChain(array $certificates): bool
    {
        if (empty($certificates)) {
            return false;
        }

        // 构建证书链
        $store = new CertificateStore();
        foreach ($this->getAcceptableCAs() as $ca) {
            $store->addCertificate($ca);
        }

        // 验证每个证书
        $chain = array_reverse($certificates);
        foreach ($chain as $i => $cert) {
            if ($i === 0) {
                // 根证书自验证
                if (!$cert->verify($cert)) {
                    return false;
                }
            } else {
                // 验证证书链
                if (!$cert->verify($chain[$i - 1])) {
                    return false;
                }
            }
        }

        return true;
    }

    public function setClientCertificateRequested(bool $requested): void
    {
        $this->clientCertificateRequested = $requested;
    }

    public function isClientCertificateRequested(): bool
    {
        return $this->clientCertificateRequested;
    }

    public function generateVerifyData(string $label): string
    {
        assert($this->masterSecret !== null, 'Master secret not derived');

        // 根据 RFC 5246 Section 7.4.9
        $seed = hash('sha256', $label, true) .
            hash('sha256', $this->handshakeMessages, true);

        return $this->prf($this->masterSecret, $label, $seed, 12);
    }

    public function verifyClientFinished(HandshakeMessage $message): bool
    {
        assert($message instanceof Finished);

        $expectedVerifyData = $this->generateVerifyData('client finished');
        return hash_equals($expectedVerifyData, $message->getVerifyData());
    }

    public function verifyServerFinished(HandshakeMessage $message): bool
    {
        assert($message instanceof Finished);

        $expectedVerifyData = $this->generateVerifyData('server finished');
        return hash_equals($expectedVerifyData, $message->getVerifyData());
    }

    private function deriveMasterSecret(): void
    {
        assert($this->clientRandom !== null && $this->serverRandom !== null,
            'Random values not set');

        // 根据 RFC 5246 Section 8.1
        $premaster = $this->keyExchange->getPremasterSecret();
        $seed = $this->clientRandom . $this->serverRandom;

        $this->masterSecret = $this->prf($premaster, "master secret", $seed, 48);
        LogUtil::info("Master secret derived successfully");
    }

    private function prf(string $secret, string $label, string $seed, int $length): string
    {
        // TLS 1.2 使用 SHA-256 作为 PRF
        $hmac = function (string $key, string $data) {
            return hash_hmac('sha256', $data, $key, true);
        };

        $result = '';
        $a = $hmac($secret, $label . $seed);

        while (strlen($result) < $length) {
            $result .= $hmac($secret, $a . $label . $seed);
            $a = $hmac($secret, $a);
        }

        return substr($result, 0, $length);
    }

    public function updateHandshakeMessages(HandshakeMessage $message): void
    {
        $this->handshakeMessages .= $message->serialize();
    }

    public function setEarlyDataAllowed(bool $allowed): void
    {
        $this->earlyDataAllowed = $allowed;
    }

    public function isEarlyDataAllowed(): bool
    {
        return $this->earlyDataAllowed;
    }

    public function setResumptionMasterSecret(string $secret): void
    {
        $this->resumptionMasterSecret = $secret;
    }

    public function getResumptionMasterSecret(): ?string
    {
        return $this->resumptionMasterSecret;
    }

    public function isTls13(): bool
    {
        return $this->negotiatedVersion === TlsVersion::TLS_1_3;
    }
}
