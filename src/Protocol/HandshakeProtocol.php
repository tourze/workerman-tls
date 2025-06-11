<?php

namespace Tourze\Workerman\TLS\Protocol;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Context\ConnectionContext;
use Tourze\Workerman\TLS\Enum\CipherSuite;
use Tourze\Workerman\TLS\Enum\HandshakeType;
use Tourze\Workerman\TLS\Enum\TlsVersion;
use Tourze\Workerman\TLS\Message\Certificate;
use Tourze\Workerman\TLS\Message\CertificateRequest;
use Tourze\Workerman\TLS\Message\CertificateVerify;
use Tourze\Workerman\TLS\Message\ClientHello;
use Tourze\Workerman\TLS\Message\ClientKeyExchange;
use Tourze\Workerman\TLS\Message\Finished;
use Tourze\Workerman\TLS\Message\HandshakeMessage;
use Tourze\Workerman\TLS\Message\ServerHello;
use Tourze\Workerman\TLS\Message\ServerHelloDone;
use Tourze\Workerman\TLS\Message\ServerKeyExchange;
use Workerman\Connection\ConnectionInterface;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\ProtocolInterface;

class HandshakeProtocol implements ProtocolInterface
{
    // 支持的TLS版本
    private const SUPPORTED_VERSIONS = [
        TlsVersion::TLS_1_3,
        TlsVersion::TLS_1_2
    ];

    // 支持的密码套件
    private const SUPPORTED_CIPHER_SUITES = [
        // TLS 1.3 cipher suites
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        // TLS 1.2 cipher suites
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ];

    // 连接上下文映射
    private static ?\WeakMap $connectionContexts = null;

    public static function init(): void
    {
        self::$connectionContexts = new \WeakMap();
        LogUtil::info('HandshakeProtocol initialized');
    }

    /**
     * 输入处理
     * 仅检查消息长度,返回需要的数据长度
     */
    public static function input(string $buffer, ConnectionInterface $connection): int
    {
        assert(!empty($buffer), 'Buffer cannot be empty');
        assert($connection instanceof TcpConnection, 'Connection must be TcpConnection');

        $context = self::getConnectionContext($connection);

        // 如果握手已完成,交给其他层处理
        if ($context->isHandshakeCompleted()) {
            LogUtil::debug('Handshake already completed, skipping input');
            return 0;
        }

        try {
            LogUtil::info('Processing input buffer, length: ' . strlen($buffer));
            LogUtil::debug('Input buffer hex dump', $buffer);

            // 检查是否有足够的数据来解析记录层头部
            if (strlen($buffer) < 5) {
                LogUtil::debug('Need more data for record header, current length: ' . strlen($buffer));
                return 5 - strlen($buffer);
            }

            // 解析记录层头部
            $recordHeader = unpack('Ctype/nversion/nlength', substr($buffer, 0, 5));
            assert(is_array($recordHeader), 'Record header unpack failed');
            assert(isset($recordHeader['type'], $recordHeader['version'], $recordHeader['length']), 
                'Invalid record header format');

            LogUtil::info(sprintf(
                'Record header - type: %d (0x%02X), version: 0x%04X, length: %d',
                $recordHeader['type'],
                $recordHeader['type'],
                $recordHeader['version'],
                $recordHeader['length']
            ));

            if ($recordHeader['type'] !== 22) { // 22 = handshake
                LogUtil::debug('Not a handshake message, type: ' . $recordHeader['type']);
                return 0;
            }

            // 检查TLS版本
            if (!in_array($recordHeader['version'], [0x0301, 0x0302, 0x0303])) {
                LogUtil::error('Unsupported TLS version: 0x' . dechex($recordHeader['version']));
                throw new \Exception('Unsupported TLS version');
            }

            // 检查是否有足够的数据来解析完整的记录
            $totalLength = 5 + $recordHeader['length'];
            if (strlen($buffer) < $totalLength) {
                LogUtil::debug('Need more data for complete record, have ' . strlen($buffer) . ' need ' . $totalLength);
                return $totalLength - strlen($buffer);
            }

            return $totalLength;
        } catch (\Throwable $e) {
            // 握手失败,关闭连接
            LogUtil::error("Handshake failed", $e);
            $connection->close();
            return 0;
        }
    }

    /**
     * 解码握手消息和应用层数据
     */
    public static function decode(string $buffer, ConnectionInterface $connection): string
    {
        // 暂时只支持TCP
        assert($connection instanceof TcpConnection);

        $context = self::getConnectionContext($connection);

        // 如果握手已完成,交给其他层处理
        if ($context->isHandshakeCompleted()) {
            LogUtil::debug('Handshake completed, skipping decode');
            return '';
        }

        try {
            LogUtil::debug('Decoding handshake message', $buffer);

            // 解析记录层头部
            $recordHeader = unpack('Ctype/nversion/nlength', substr($buffer, 0, 5));
            assert(is_array($recordHeader), 'Record header unpack failed');
            assert(isset($recordHeader['type'], $recordHeader['version'], $recordHeader['length']), 
                'Invalid record header format');

            LogUtil::debug(sprintf(
                'Record header - type: %d (0x%02X), version: 0x%04X, length: %d',
                $recordHeader['type'],
                $recordHeader['type'],
                $recordHeader['version'],
                $recordHeader['length']
            ));

            if ($recordHeader['type'] !== 22) { // 22 = handshake
                LogUtil::debug('Not a handshake message, type: ' . $recordHeader['type']);
                return '';
            }

            // 获取握手消息内容
            $handshakeData = substr($buffer, 5);
            LogUtil::debug('Handshake data', $handshakeData);
            assert(strlen($handshakeData) === $recordHeader['length'],
                'Handshake data length mismatch');

            // 解析握手消息头部
            $messageType = ord($handshakeData[0]);
            LogUtil::debug(sprintf('Message type: %d (0x%02X)', $messageType, $messageType));

            $length = 0;
            $length |= ord($handshakeData[1]) << 16;
            $length |= ord($handshakeData[2]) << 8;
            $length |= ord($handshakeData[3]);
            LogUtil::debug(sprintf(
                'Message length bytes: 0x%02X%02X%02X = %d',
                ord($handshakeData[1]),
                ord($handshakeData[2]),
                ord($handshakeData[3]),
                $length
            ));

            // 获取消息体
            $data = substr($handshakeData, 4, $length);
            LogUtil::debug('Message body', $data);
            assert(strlen($data) === $length, 'Message body length mismatch');

            // 根据消息类型反序列化
            try {
                $type = HandshakeType::from($messageType);
                LogUtil::debug('Message type enum: ' . $type->name);
            } catch (\ValueError $e) {
                LogUtil::error(sprintf('Invalid message type: 0x%02X', $messageType));
                throw $e;
            }

            LogUtil::debug('Deserializing message...');
            $message = match ($type) {
                HandshakeType::CLIENT_HELLO => ClientHello::decode($data),
                HandshakeType::SERVER_HELLO => ServerHello::decode($data),
                HandshakeType::CERTIFICATE => Certificate::decode($data),
                HandshakeType::SERVER_KEY_EXCHANGE => ServerKeyExchange::decode($data),
                HandshakeType::CERTIFICATE_REQUEST => CertificateRequest::decode($data),
                HandshakeType::SERVER_HELLO_DONE => ServerHelloDone::decode($data),
                HandshakeType::CERTIFICATE_VERIFY => CertificateVerify::decode($data),
                HandshakeType::CLIENT_KEY_EXCHANGE => ClientKeyExchange::decode($data),
                HandshakeType::FINISHED => Finished::decode($data),
                default => throw new \InvalidArgumentException(
                    sprintf("Unknown handshake message type: 0x%02X", $type->value)
                )
            };
            LogUtil::debug('Message deserialized successfully');

            LogUtil::info("Processing handshake message type: {$message->getType()->name}");
            LogUtil::debug("Serialized message hex dump", $message->serialize());

            // 处理握手消息并获取响应消息序列
            LogUtil::debug('Starting to handle handshake message...');
            $responses = iterator_to_array($context->handleHandshakeMessage($message));
            LogUtil::info('Got ' . count($responses) . ' response messages');

            foreach ($responses as $i => $response) {
                assert($response instanceof HandshakeMessage, 'Response must be a HandshakeMessage');
                LogUtil::info("Sending response message {$i}: {$response->getType()->name}");
                LogUtil::debug("Response message hex dump", $response->serialize());

                // 发送握手消息
                LogUtil::debug('Encoding response message...');
                $encodedResponse = self::encodeHandshakeMessage($response);
                LogUtil::info('Response length: ' . strlen($encodedResponse));
                LogUtil::debug('Encoded response hex dump', $encodedResponse);

                LogUtil::debug('Sending response...');
                $connection->send($encodedResponse, true);
                LogUtil::info("Response {$i} sent successfully");
            }

            return '';
        } catch (\Throwable $e) {
            // 握手失败,关闭连接
            LogUtil::error("Handshake failed", $e);
            $connection->close();
            return '';
        }
    }

    /**
     * 编码握手消息和应用层数据
     */
    public static function encode(mixed $data, ConnectionInterface $connection): string
    {
        // 暂时只支持TCP
        assert($connection instanceof TcpConnection);

        $context = self::getConnectionContext($connection);

        // 如果是握手消息,直接发送
        if ($data instanceof HandshakeMessage) {
            LogUtil::debug("Encoding handshake message type: {$data->getType()->name}");
            return self::encodeHandshakeMessage($data);
        }

        // 如果握手未完成,返回空
        if (!$context->isHandshakeCompleted()) {
            LogUtil::debug('Handshake not completed, skipping encode');
            return '';
        }

        return $data;
    }

    /**
     * 获取连接上下文
     */
    private static function getConnectionContext(ConnectionInterface $connection): ConnectionContext
    {
        if (!isset(self::$connectionContexts)) {
            self::init();
        }

        if (!isset(self::$connectionContexts[$connection])) {
            LogUtil::info('Creating new connection context');
            // 从证书管理器获取证书和私钥
            [$cert, $key] = CertificateManager::getInstance()->getCertificateAndKey($connection);

            if ($cert === null || $key === null) {
                throw new \RuntimeException('No certificate or private key bound to connection');
            }

            $context = new ConnectionContext(
                true, // 服务器端
                self::SUPPORTED_VERSIONS,
                self::SUPPORTED_CIPHER_SUITES,
                [$cert], // 证书
                [$key]  // 私钥
            );
            self::$connectionContexts[$connection] = $context;
        }

        return self::$connectionContexts[$connection];
    }

    /**
     * 编码握手消息
     */
    private static function encodeHandshakeMessage(HandshakeMessage $message): string
    {
        // 获取消息体
        $body = $message->serialize();
        $bodyLength = strlen($body);

        LogUtil::debug("Encoding message type: {$message->getType()->name}, body length: {$bodyLength}", $body);

        // 构造握手消息头部 (4字节)
        // 1字节消息类型 + 3字节长度
        $handshakeHeader = pack('C', $message->getType()->value) . 
            chr(($bodyLength >> 16) & 0xFF) .
            chr(($bodyLength >> 8) & 0xFF) .
            chr($bodyLength & 0xFF);

        // 组合握手消息
        $handshakeMessage = $handshakeHeader . $body;
        $handshakeLength = strlen($handshakeMessage);

        // 如果消息超过最大记录大小，需要分割
        $maxRecordSize = 16384 - 5; // 减去记录层头部的5字节
        if ($handshakeLength > $maxRecordSize) {
            LogUtil::info("Message size {$handshakeLength} exceeds max record size, splitting");
            $result = '';
            $offset = 0;
            while ($offset < $handshakeLength) {
                $recordSize = min($maxRecordSize, $handshakeLength - $offset);
                LogUtil::info("Sending TLS record of size: {$recordSize}");

                // 构造记录层头部 (5字节)
                $recordHeader = pack('Cnn', 22, 0x0303, $recordSize);

                // 添加记录
                $result .= $recordHeader . substr($handshakeMessage, $offset, $recordSize);
                $offset += $recordSize;
            }
            return $result;
        }

        // 构造记录层头部 (5字节)
        // 1字节类型(22=handshake) + 2字节版本(0x0303=TLS1.2) + 2字节长度
        $recordHeader = pack('Cnn', 22, 0x0303, $handshakeLength);

        // 返回完整的TLS记录
        return $recordHeader . $handshakeMessage;
    }
}
