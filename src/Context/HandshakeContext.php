<?php

namespace Tourze\Workerman\TLS\Context;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Enum\HandshakeType;
use Tourze\Workerman\TLS\Message\Certificate;
use Tourze\Workerman\TLS\Message\CertificateRequest;
use Tourze\Workerman\TLS\Message\CertificateVerify;
use Tourze\Workerman\TLS\Message\ChangeCipherSpec;
use Tourze\Workerman\TLS\Message\ClientHello;
use Tourze\Workerman\TLS\Message\ClientKeyExchange;
use Tourze\Workerman\TLS\Message\Finished;
use Tourze\Workerman\TLS\Message\HandshakeMessage;
use Tourze\Workerman\TLS\Message\ServerHello;
use Tourze\Workerman\TLS\Message\ServerHelloDone;
use Tourze\Workerman\TLS\Message\ServerKeyExchange;

/**
 * 管理TLS握手过程
 */
class HandshakeContext
{
    private ?string $serverCertificate = null;
    private ?string $clientCertificate = null;
    private array $certificates;
    private array $privateKeys;

    public function __construct(
        private readonly bool $isServer,
        private readonly SecurityContext $securityContext,
        private readonly CryptoContext $cryptoContext,
        private readonly SessionContext $sessionContext,
        array $certificates = [],
        array $privateKeys = []
    ) {
        $this->certificates = $certificates;
        $this->privateKeys = $privateKeys;
    }

    /**
     * 处理握手消息
     * @return \Generator<HandshakeMessage>
     */
    public function handleHandshakeMessage(HandshakeMessage $message): \Generator
    {
        LogUtil::info("Handling handshake message: " . $message->getType()->name);

        // 根据消息类型和当前状态处理
        yield from match ($message->getType()) {
            HandshakeType::CLIENT_HELLO => $this->handleClientHello($message),
            HandshakeType::SERVER_HELLO => $this->handleServerHello($message),
            HandshakeType::CERTIFICATE => $this->handleCertificate($message),
            HandshakeType::SERVER_KEY_EXCHANGE => $this->handleServerKeyExchange($message),
            HandshakeType::CERTIFICATE_REQUEST => $this->handleCertificateRequest($message),
            HandshakeType::SERVER_HELLO_DONE => $this->handleServerHelloDone($message),
            HandshakeType::CLIENT_KEY_EXCHANGE => $this->handleClientKeyExchange($message),
            HandshakeType::CERTIFICATE_VERIFY => $this->handleCertificateVerify($message),
            HandshakeType::FINISHED => $this->handleFinished($message),
            default => throw new \InvalidArgumentException(
                "Unexpected handshake message type: " . $message->getType()->name
            )
        };
    }

    /**
     * 处理 ClientHello 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleClientHello(HandshakeMessage $message): \Generator
    {
        assert($message instanceof ClientHello);
        assert($this->isServer, 'Only server can handle ClientHello');

        // 1. 选择TLS版本
        $clientVersion = $message->getVersion();
        $serverVersion = $this->securityContext->selectVersion($clientVersion);
        if ($serverVersion === null) {
            throw new \RuntimeException("No compatible TLS version found");
        }

        // 2. 选择密码套件
        $clientCipherSuites = $message->getCipherSuites();
        $selectedCipherSuite = $this->securityContext->selectCipherSuite($clientCipherSuites);
        if ($selectedCipherSuite === null) {
            throw new \RuntimeException("No compatible cipher suite found");
        }

        // 3. 生成服务器随机数
        $serverRandom = random_bytes(32);
        $this->securityContext->setServerRandom($serverRandom);
        $this->securityContext->setClientRandom($message->getRandom());

        // 4. 发送 ServerHello
        yield new ServerHello(
            $serverRandom,
            $selectedCipherSuite,
            $serverVersion,
            $message->getSessionId(),
            0, // No compression
            [] // No extensions
        );

        // 5. 发送证书
        yield new Certificate($this->certificates);

        // 6. 发送 ServerKeyExchange (如果需要)
        if ($selectedCipherSuite->requiresServerKeyExchange()) {
            $ephemeralKey = $this->securityContext->getServerEphemeralKey();
            $signedData = $message->getRandom() . $serverRandom . $ephemeralKey;
            $signature = '';
            openssl_sign($signedData, $signature, $this->privateKeys[0], OPENSSL_ALGO_SHA256);

            yield new ServerKeyExchange(
                $ephemeralKey,
                1, // named_curve
                23, // secp256r1
                0x0401, // rsa_pkcs1_sha256
                $signature
            );
        }

        // 7. 请求客户端证书 (可选)
        if ($this->securityContext->requiresClientAuth()) {
            yield new CertificateRequest(
                [1], // RSA signing
                $this->securityContext->getSupportedSignatureAlgorithms(),
                $this->securityContext->getAcceptableCAs()
            );
        }

        // 8. 发送 ServerHelloDone
        yield new ServerHelloDone();
    }

    /**
     * 处理 ServerHello 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleServerHello(HandshakeMessage $message): \Generator
    {
        assert($message instanceof ServerHello);
        assert(!$this->isServer, 'Only client can handle ServerHello');

        // 1. 验证并保存服务器选择的版本和密码套件
        $serverVersion = $message->getVersion();
        if (!$this->securityContext->isVersionSupported($serverVersion)) {
            throw new \RuntimeException("Server selected unsupported TLS version");
        }

        $selectedCipherSuite = $message->getCipherSuite();
        if (!$this->securityContext->isCipherSuiteSupported($selectedCipherSuite)) {
            throw new \RuntimeException("Server selected unsupported cipher suite");
        }

        // 2. 保存服务器随机数
        $this->securityContext->setServerRandom($message->getRandom());

        yield from [];
    }

    /**
     * 处理 Certificate 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleCertificate(HandshakeMessage $message): \Generator
    {
        assert($message instanceof Certificate);

        // 验证证书链
        if (!$this->securityContext->verifyCertificateChain($message->getCertificates())) {
            throw new \RuntimeException("Invalid certificate chain");
        }

        $certificates = $message->getCertificates();
        if (!empty($certificates)) {
            if ($this->isServer) {
                // 存储客户端证书
                $this->clientCertificate = openssl_pkey_get_public($certificates[0]);
                if ($this->clientCertificate === false) {
                    throw new \RuntimeException("Failed to get client public key");
                }
            } else {
                // 存储服务器证书
                $this->serverCertificate = openssl_pkey_get_public($certificates[0]);
                if ($this->serverCertificate === false) {
                    throw new \RuntimeException("Failed to get server public key");
                }
            }
        }

        yield from [];
    }

    /**
     * 处理 ServerKeyExchange 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleServerKeyExchange(HandshakeMessage $message): \Generator
    {
        assert($message instanceof ServerKeyExchange);
        assert(!$this->isServer, 'Only client can handle ServerKeyExchange');
        assert($this->serverCertificate !== null, 'Server certificate not received');

        // 验证服务器密钥交换参数
        if (!$this->securityContext->verifyServerKeyExchange($message, $this->serverCertificate)) {
            throw new \RuntimeException("Invalid server key exchange parameters");
        }

        yield from [];
    }

    /**
     * 处理 CertificateRequest 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleCertificateRequest(HandshakeMessage $message): \Generator
    {
        assert($message instanceof CertificateRequest);
        assert(!$this->isServer, 'Only client can handle CertificateRequest');

        // 标记需要发送客户端证书
        $this->securityContext->setClientCertificateRequested(true);

        yield from [];
    }

    /**
     * 处理 ServerHelloDone 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleServerHelloDone(HandshakeMessage $message): \Generator
    {
        assert($message instanceof ServerHelloDone);
        assert(!$this->isServer, 'Only client can handle ServerHelloDone');

        // 1. 发送客户端证书 (如果服务器请求)
        if ($this->securityContext->isClientCertificateRequested()) {
            yield new Certificate($this->certificates);
        }

        // 2. 发送客户端密钥交换
        yield new ClientKeyExchange(
            $this->securityContext->generateClientKeyExchange()
        );

        // 3. 发送证书验证 (如果发送了客户端证书)
        if ($this->securityContext->isClientCertificateRequested() && !empty($this->certificates)) {
            $signature = $this->securityContext->generateCertificateVerify($this->privateKeys[0]);
            yield new CertificateVerify(
                $signature,
                0x0401 // rsa_pkcs1_sha256
            );
        }

        // 4. 发送 ChangeCipherSpec
        yield new ChangeCipherSpec();

        // 5. 激活加密
        $this->cryptoContext->activateClientToServerEncryption();

        // 6. 发送 Finished
        yield new Finished(
            $this->securityContext->generateVerifyData('client finished')
        );
    }

    /**
     * 处理 ClientKeyExchange 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleClientKeyExchange(HandshakeMessage $message): \Generator
    {
        assert($message instanceof ClientKeyExchange);
        assert($this->isServer, 'Only server can handle ClientKeyExchange');

        // 处理客户端密钥交换参数
        $this->securityContext->processClientKeyExchange($message);

        yield from [];
    }

    /**
     * 处理 CertificateVerify 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleCertificateVerify(HandshakeMessage $message): \Generator
    {
        assert($message instanceof CertificateVerify);
        assert($this->clientCertificate !== null, 'Client certificate not received');

        // 验证客户端证书签名
        if (!$this->securityContext->verifyCertificateVerify($message, $this->clientCertificate)) {
            throw new \RuntimeException("Invalid certificate verify signature");
        }

        yield from [];
    }

    /**
     * 处理 Finished 消息
     * @return \Generator<HandshakeMessage>
     */
    private function handleFinished(HandshakeMessage $message): \Generator
    {
        assert($message instanceof Finished);

        if ($this->isServer) {
            // 服务器处理客户端的 Finished
            if (!$this->verifyClientFinished($message)) {
                throw new \RuntimeException("Invalid client finished message");
            }

            // 发送服务器的 ChangeCipherSpec 和 Finished
            yield new ChangeCipherSpec();
            $this->cryptoContext->activateServerToClientEncryption();
            yield new Finished(
                $this->securityContext->generateVerifyData('server finished')
            );

            // 标记握手完成
            $this->sessionContext->markHandshakeCompleted();
        } else {
            // 客户端处理服务器的 Finished
            if (!$this->securityContext->verifyServerFinished($message)) {
                throw new \RuntimeException("Invalid server finished message");
            }

            // 标记握手完成
            $this->sessionContext->markHandshakeCompleted();
        }
    }

    public function verifyClientFinished(HandshakeMessage $message): bool
    {
        assert($message instanceof Finished);
        return $this->securityContext->verifyClientFinished($message);
    }

    public function generateServerFinished(): HandshakeMessage
    {
        return new Finished(
            $this->securityContext->generateVerifyData('server finished')
        );
    }
}
