<?php

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Protocol\HandshakeProtocol;
use Workerman\Worker;

require_once __DIR__ . '/vendor/autoload.php';

// 初始化Worker
$worker = new Worker('tcp://0.0.0.0:8443');
$worker->name = 'TLS测试服务器';
$worker->count = 1;

// 设置协议
$worker->protocol = HandshakeProtocol::class;

// 当客户端连接时
$worker->onConnect = function($connection) use ($io) {
    $io->text(sprintf('新连接: %s', $connection->getRemoteAddress()));
    LogUtil::info('New connection: ' . $connection->getRemoteAddress());

    // 读取证书和私钥
    $cert = file_get_contents($this->testDir . '/server.crt');
    $key = file_get_contents($this->testDir . '/server.key');

    if ($cert === false || $key === false) {
        throw new \RuntimeException('Failed to load certificate or private key');
    }

    // 验证证书和私钥
    $certManager = CertificateManager::getInstance();
    if (!$certManager->validateCertificateAndKey($cert, $key)) {
        throw new \RuntimeException('Invalid certificate or private key');
    }

    // 为连接绑定证书
    $certManager->bindCertificate($connection, $cert, $key);
};

// 当收到数据时
$worker->onMessage = function($connection, $data) {
    LogUtil::info('Received data:', $data);
};

// 当连接关闭时
$worker->onClose = function($connection) use ($io) {
    $io->text(sprintf('连接关闭: %s', $connection->getRemoteAddress()));
    LogUtil::info('Connection closed: ' . $connection->getRemoteAddress());
    CertificateManager::getInstance()->cleanup($connection);
};

Worker::runAll();
