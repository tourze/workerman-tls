<?php

namespace Tourze\Workerman\TLS\Protocol;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Context\ConnectionContext;
use Tourze\Workerman\TLS\Message\ChangeCipherSpec;
use Tourze\Workerman\TLS\Message\ClientHello;
use Tourze\Workerman\TLS\Message\ClientKeyExchange;
use Tourze\Workerman\TLS\Message\Finished;
use Tourze\Workerman\TLS\Message\HandshakeMessage;
use Workerman\Connection\ConnectionInterface;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\ProtocolInterface;

class TlsProtocol implements ProtocolInterface
{
    // TLS状态机状态
    private const STATE_INITIAL = 0;
    private const STATE_CLIENT_HELLO = 1;
    private const STATE_SERVER_HELLO = 2;
    private const STATE_SERVER_CERTIFICATE = 3;
    private const STATE_SERVER_KEY_EXCHANGE = 4;
    private const STATE_SERVER_HELLO_DONE = 5;
    private const STATE_CLIENT_KEY_EXCHANGE = 6;
    private const STATE_CLIENT_CHANGE_CIPHER_SPEC = 7;
    private const STATE_CLIENT_FINISHED = 8;
    private const STATE_SERVER_CHANGE_CIPHER_SPEC = 9;
    private const STATE_SERVER_FINISHED = 10;
    private const STATE_APPLICATION_DATA = 11;

    // 连接上下文映射
    private static ?\WeakMap $connectionContexts = null;

    // 连接状态映射
    private static ?\WeakMap $connectionStates = null;

    public static function init(): void
    {
        self::$connectionContexts = new \WeakMap();
        self::$connectionStates = new \WeakMap();
        LogUtil::info('TlsProtocol initialized');
    }

    /**
     * 输入处理
     */
    public static function input(string $buffer, ConnectionInterface $connection): int
    {
        assert($connection instanceof TcpConnection);

        try {
            // 获取或初始化连接状态
            $state = self::getConnectionState($connection);
            LogUtil::debug("Current state: $state");

            // 在握手阶段,使用握手协议处理
            if ($state < self::STATE_APPLICATION_DATA) {
                return HandshakeProtocol::input($buffer, $connection);
            }

            // 在应用数据阶段,使用记录层协议处理
            return RecordLayerProtocol::input($buffer, $connection);

        } catch (\Throwable $e) {
            LogUtil::error("TLS protocol error", $e);
            $connection->close();
            return 0;
        }
    }

    /**
     * 解码处理
     */
    public static function decode(string $buffer, ConnectionInterface $connection): string
    {
        assert($connection instanceof TcpConnection);

        try {
            $state = self::getConnectionState($connection);
            LogUtil::debug("Current state: $state");

            // 在握手阶段
            if ($state < self::STATE_APPLICATION_DATA) {
                $message = HandshakeProtocol::decode($buffer, $connection);

                // 处理握手消息
                if ($message instanceof HandshakeMessage) {
                    self::handleHandshakeMessage($message, $connection);
                }

                return '';
            }

            // 在应用数据阶段
            return RecordLayerProtocol::decode($buffer, $connection);

        } catch (\Throwable $e) {
            LogUtil::error("TLS decode error", $e);
            $connection->close();
            return '';
        }
    }

    /**
     * 编码处理
     */
    public static function encode(mixed $data, ConnectionInterface $connection): string
    {
        assert($connection instanceof TcpConnection);

        try {
            $state = self::getConnectionState($connection);
            LogUtil::debug("Current state: $state");

            // 在握手阶段
            if ($state < self::STATE_APPLICATION_DATA) {
                return HandshakeProtocol::encode($data, $connection);
            }

            // 在应用数据阶段
            return RecordLayerProtocol::encode($data, $connection);

        } catch (\Throwable $e) {
            LogUtil::error("TLS encode error", $e);
            $connection->close();
            return '';
        }
    }

    /**
     * 处理握手消息
     */
    private static function handleHandshakeMessage(HandshakeMessage $message, ConnectionInterface $connection): void
    {
        $context = self::getConnectionContext($connection);
        $state = self::getConnectionState($connection);

        LogUtil::info("Handling handshake message in state $state: " . $message->getType()->name);

        try {
            // 根据当前状态和消息类型更新状态机
            switch ($state) {
                case self::STATE_INITIAL:
                    if ($message instanceof ClientHello) {
                        self::setConnectionState($connection, self::STATE_CLIENT_HELLO);
                        // 处理ClientHello并发送ServerHello等消息
                        foreach ($context->handleHandshakeMessage($message) as $response) {
                            $connection->send($response);
                        }
                        self::setConnectionState($connection, self::STATE_SERVER_HELLO_DONE);
                    }
                    break;

                case self::STATE_SERVER_HELLO_DONE:
                    if ($message instanceof ClientKeyExchange) {
                        self::setConnectionState($connection, self::STATE_CLIENT_KEY_EXCHANGE);
                    }
                    break;

                case self::STATE_CLIENT_KEY_EXCHANGE:
                    if ($message instanceof ChangeCipherSpec) {
                        self::setConnectionState($connection, self::STATE_CLIENT_CHANGE_CIPHER_SPEC);
                        // 激活客户端到服务端的加密
                        $context->activateClientToServerEncryption();
                    }
                    break;

                case self::STATE_CLIENT_CHANGE_CIPHER_SPEC:
                    if ($message instanceof Finished) {
                        self::setConnectionState($connection, self::STATE_CLIENT_FINISHED);
                        // 处理客户端Finished消息
                        foreach ($context->handleHandshakeMessage($message) as $response) {
                            $connection->send($response);
                        }
                        self::setConnectionState($connection, self::STATE_APPLICATION_DATA);
                    }
                    break;
            }

        } catch (\Throwable $e) {
            LogUtil::error("Error handling handshake message", $e);
            $connection->close();
        }
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
            throw new \RuntimeException('No connection context found');
        }

        return self::$connectionContexts[$connection];
    }

    /**
     * 获取连接状态
     */
    private static function getConnectionState(ConnectionInterface $connection): int
    {
        if (!isset(self::$connectionStates)) {
            self::init();
        }

        if (!isset(self::$connectionStates[$connection])) {
            self::$connectionStates[$connection] = self::STATE_INITIAL;
        }

        return self::$connectionStates[$connection];
    }

    /**
     * 设置连接状态
     */
    private static function setConnectionState(ConnectionInterface $connection, int $state): void
    {
        if (!isset(self::$connectionStates)) {
            self::init();
        }

        self::$connectionStates[$connection] = $state;
        LogUtil::info("Connection state changed to: $state");
    }
}
