<?php

namespace Tourze\Workerman\TLS\Processor;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Context\CryptoContext;
use Tourze\Workerman\TLS\Context\SecurityContext;
use Tourze\Workerman\TLS\Context\SessionContext;
use Tourze\Workerman\TLS\Enum\CipherSuite;
use Tourze\Workerman\TLS\Enum\NamedGroup;
use Tourze\Workerman\TLS\Enum\TlsVersion;
use Tourze\Workerman\TLS\Message\Certificate;
use Tourze\Workerman\TLS\Message\CertificateVerify;
use Tourze\Workerman\TLS\Message\ClientHello;
use Tourze\Workerman\TLS\Message\ClientKeyExchange;
use Tourze\Workerman\TLS\Message\Finished;
use Tourze\Workerman\TLS\Message\HandshakeMessage;
use Tourze\Workerman\TLS\Message\HandshakeMessageCollector;
use Tourze\Workerman\TLS\Message\ServerHello;
use Tourze\Workerman\TLS\Message\ServerHelloDone;
use Tourze\Workerman\TLS\Message\ServerKeyExchange;
use Tourze\Workerman\TLS\Parameter\HandshakeParameterManager;
use Tourze\Workerman\TLS\State\HandshakeStateManager;

/**
 * 处理TLS握手消息
 */
class HandshakeMessageProcessor
{
    private HandshakeMessageCollector $messageCollector;
    private HandshakeStateManager $stateManager;
    private HandshakeParameterManager $parameterManager;
    private SecurityContext $securityContext;
    private CryptoContext $cryptoContext;
    private SessionContext $sessionContext;

    public function __construct(
        private readonly bool $isServer,
        array $certificates = [],
        array $privateKeys = [],
        array $supportedVersions = [TlsVersion::TLS_1_2],
        array $supportedCipherSuites = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ]
    )
    {
        $this->messageCollector = new HandshakeMessageCollector();
        $this->stateManager = new HandshakeStateManager($isServer);
        $this->parameterManager = new HandshakeParameterManager($certificates, $privateKeys);
        $this->securityContext = new SecurityContext($supportedVersions, $supportedCipherSuites);
        $this->cryptoContext = new CryptoContext($isServer);
        $this->sessionContext = new SessionContext($isServer);
    }

    /**
     * 处理握手消息
     * @param \Tourze\Workerman\TLS\Message\HandshakeMessage $message
     * @return \Generator<\Tourze\Workerman\TLS\Message\HandshakeMessage>
     */
    public function processMessage(HandshakeMessage $message): \Generator
    {
        LogUtil::info("Processing handshake message: " . $message->getType()->name);

        // 验证消息类型
        if (!$this->stateManager->validateMessageType($message->getType())) {
            throw new \InvalidArgumentException("Unexpected message type: {$message->getType()->name}");
        }

        // 记录消息
        $this->messageCollector->addMessage($message);

        // 根据消息类型处理
        $responses = match (true) {
            $message instanceof ClientHello => $this->handleClientHello($message),
            $message instanceof ClientKeyExchange => $this->handleClientKeyExchange($message),
            $message instanceof CertificateVerify => $this->handleCertificateVerify($message),
            $message instanceof Finished => $this->handleClientFinished($message),
            default => throw new \InvalidArgumentException("Unsupported message type: {$message->getType()->name}")
        };

        // 记录响应消息并更新状态
        foreach ($responses as $response) {
            $this->messageCollector->addMessage($response);
            yield $response;
        }

        // 更新状态机
        $this->stateManager->updateState($message);
    }

    /**
     * @param ClientHello $message
     * @return array<\Tourze\Workerman\TLS\Message\HandshakeMessage>
     */
    private function handleClientHello(ClientHello $message): array
    {
        // 处理客户端随机数
        $this->securityContext->setClientRandom($message->getRandom());

        // 生成服务器随机数
        $serverRandom = random_bytes(32);
        $this->securityContext->setServerRandom($serverRandom);

        // 选择协议版本
        $version = $this->securityContext->selectVersion($message->getVersion());

        // 选择密码套件
        $cipherSuite = $this->securityContext->selectCipherSuite($message->getCipherSuites());

        // 选择椭圆曲线
        $curve = $this->parameterManager->selectCurve($message->getSupportedGroups());

        // 生成会话ID
        $sessionId = random_bytes(32);
        $this->sessionContext->setSessionId($sessionId);

        // 准备扩展
        $extensions = $this->prepareExtensions($message, $curve);

        // 生成密钥对
        $curveParams = $this->parameterManager->getCurveParameters($curve);
        $keyPair = $this->generateKeyPair($curveParams['curve_id']);

        // 生成签名
        $signature = $this->generateKeyExchangeSignature(
            $message->getRandom(),
            $serverRandom,
            $curveParams,
            $keyPair['public_key']
        );

        return [
            new ServerHello($serverRandom, $cipherSuite, $version, $sessionId, 0, $extensions),
            new Certificate($this->parameterManager->getCertificates()),
            new ServerKeyExchange(
                $keyPair['public_key'],
                $curveParams['curve_type'],
                $curveParams['curve_value'],
                0x0401, // rsa_pkcs1_sha256
                $signature
            ),
            new ServerHelloDone()
        ];
    }

    /**
     * @param ClientKeyExchange $message
     * @return array<\Tourze\Workerman\TLS\Message\HandshakeMessage>
     */
    private function handleClientKeyExchange(ClientKeyExchange $message): array
    {
        LogUtil::info("Processing client key exchange");

        // 获取客户端的公钥
        $clientPublicKey = $message->getClientPublicKey();

        // 使用ECDH计算预主密钥
        $preMasterSecret = $this->computePreMasterSecret(
            $clientPublicKey,
            $this->parameterManager->getPrivateKeys()[0]
        );

        // 计算主密钥
        $masterSecret = $this->computeMasterSecret(
            $preMasterSecret,
            $this->securityContext->getClientRandom(),
            $this->securityContext->getServerRandom()
        );

        // 更新主密钥
        $this->securityContext->updateHandshakeMessages($message);

        // 派生会话密钥
        $this->cryptoContext->deriveKeys(
            $masterSecret,
            $this->securityContext->getServerRandom(),
            $this->securityContext->getClientRandom()
        );

        // 激活加密
        $this->cryptoContext->activateEncryption();

        return [];
    }

    /**
     * @param CertificateVerify $message
     * @return array<\Tourze\Workerman\TLS\Message\HandshakeMessage>
     */
    private function handleCertificateVerify(CertificateVerify $message): array
    {
        LogUtil::info("Processing certificate verify");

        // 验证客户端证书签名
        $signature = $message->getSignature();
        $signatureAlgorithm = $message->getSignatureAlgorithm();

        // 获取所有之前的握手消息
        $handshakeMessages = $this->messageCollector->getMessages();
        $verifyData = '';
        foreach ($handshakeMessages as $msg) {
            $verifyData .= $msg->encode();
        }

        // 验证签名
        if (!$this->verifySignature($verifyData, $signature, $signatureAlgorithm)) {
            throw new \RuntimeException('Certificate verification failed');
        }

        LogUtil::info("Certificate verification successful");
        return [];
    }

    /**
     * @param Finished $message
     * @return array<\Tourze\Workerman\TLS\Message\HandshakeMessage>
     */
    private function handleClientFinished(Finished $message): array
    {
        LogUtil::info("Processing client finished");

        // 验证客户端的Finished消息
        $verifyData = $this->computeVerifyData(
            $this->messageCollector->getMessages(),
            $this->securityContext->generateVerifyData("client finished"),
            "client finished"
        );

        if (!hash_equals($verifyData, $message->getVerifyData())) {
            throw new \RuntimeException('Client finished verification failed');
        }

        // 生成服务器的Finished消息
        $serverVerifyData = $this->computeVerifyData(
            $this->messageCollector->getMessages(),
            $this->securityContext->generateVerifyData("server finished"),
            "server finished"
        );

        // 标记握手完成
        $this->sessionContext->markHandshakeCompleted();

        return [new Finished($serverVerifyData)];
    }

    private function computeVerifyData(array $messages, string $masterSecret, string $label): string
    {
        // 计算所有握手消息的哈希
        $handshakeData = '';
        foreach ($messages as $msg) {
            $handshakeData .= $msg->encode();
        }
        $messageHash = hash('sha256', $handshakeData, true);

        // 使用PRF计算verify_data
        $seed = $label . $messageHash;
        $length = 12; // verify_data length in TLS 1.2

        $hmac = function (string $key, string $data) {
            return hash_hmac('sha256', $data, $key, true);
        };

        $result = '';
        $a = $hmac($masterSecret, $seed);

        while (strlen($result) < $length) {
            $result .= $hmac($masterSecret, $a . $seed);
            $a = $hmac($masterSecret, $a);
        }

        return substr($result, 0, $length);
    }

    private function prepareExtensions(ClientHello $message, NamedGroup $selectedCurve): array
    {
        $extensions = [];

        // 1. 安全重协商扩展 (必需)
        $extensions[0xff01] = "\x00";

        // 2. EC Point Formats (如果客户端支持)
        if (isset($message->getExtensions()[0x000b])) {
            $extensions[0x000b] = "\x01\x00"; // 只支持非压缩格式
        }

        // 3. 支持的组 (如果客户端支持)
        if (isset($message->getExtensions()[0x000a])) {
            $extensions[0x000a] = pack('n', $selectedCurve->value);
        }

        return $extensions;
    }

    private function generateKeyPair(string $curveId): array
    {
        $key = openssl_pkey_new([
            'curve_name' => $curveId,
            'private_key_type' => OPENSSL_KEYTYPE_EC
        ]);

        if ($key === false) {
            throw new \RuntimeException('Failed to generate EC key pair: ' . openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new \RuntimeException('Failed to get key details: ' . openssl_error_string());
        }

        return [
            'public_key' => $details['key'],
            'private_key' => $key
        ];
    }

    private function generateKeyExchangeSignature(
        string $clientRandom,
        string $serverRandom,
        array  $curveParams,
        string $publicKey
    ): string
    {
        $signatureData = $clientRandom .
            $serverRandom .
            pack('C', $curveParams['curve_type']) .
            pack('n', $curveParams['curve_value']) .
            pack('C', strlen($publicKey)) .
            $publicKey;

        $signature = '';
        if (!openssl_sign(
            $signatureData,
            $signature,
            $this->parameterManager->getPrivateKeys()[0],
            OPENSSL_ALGO_SHA256
        )) {
            throw new \RuntimeException('Failed to sign key exchange data: ' . openssl_error_string());
        }

        return $signature;
    }

    private function computePreMasterSecret(string $clientPublicKey, string $serverPrivateKey): string
    {
        $sharedSecret = openssl_pkey_derive(
            openssl_pkey_get_public($clientPublicKey),
            $serverPrivateKey
        );

        if ($sharedSecret === false) {
            throw new \RuntimeException('Failed to compute shared secret: ' . openssl_error_string());
        }

        return $sharedSecret;
    }

    private function computeMasterSecret(string $preMasterSecret, string $clientRandom, string $serverRandom): string
    {
        // TLS 1.2 PRF with SHA-256
        $seed = "master secret" . $clientRandom . $serverRandom;
        $length = 48; // Master secret is always 48 bytes

        $hmac = function (string $key, string $data) {
            return hash_hmac('sha256', $data, $key, true);
        };

        $result = '';
        $a = $hmac($preMasterSecret, $seed);

        while (strlen($result) < $length) {
            $result .= $hmac($preMasterSecret, $a . $seed);
            $a = $hmac($preMasterSecret, $a);
        }

        return substr($result, 0, $length);
    }

    private function verifySignature(string $data, string $signature, int $algorithm): bool
    {
        // 目前只支持 RSA-PKCS1-SHA256
        if ($algorithm !== 0x0401) {
            throw new \RuntimeException('Unsupported signature algorithm');
        }

        return openssl_verify(
                $data,
                $signature,
                $this->parameterManager->getCertificates()[0],
                OPENSSL_ALGO_SHA256
            ) === 1;
    }
}
