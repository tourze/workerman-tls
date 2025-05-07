<?php

// 生成CA私钥和证书
$io->section('生成CA证书');
shell_exec(sprintf(
    'openssl req -x509 -new -nodes -days 365 -keyout %s/ca.key -out %s/ca.crt -subj "/CN=Test CA"',
    $this->testDir, $this->testDir
));

// 生成服务器私钥
$io->section('生成服务器证书');
shell_exec(sprintf('openssl genrsa -out %s/server.key 2048', $this->testDir));

// 生成服务器CSR
shell_exec(sprintf(
    'openssl req -new -key %s/server.key -out %s/server.csr -subj "/CN=localhost"',
    $this->testDir, $this->testDir
));

// 使用CA签名服务器证书
shell_exec(sprintf(
    'openssl x509 -req -days 365 -in %s/server.csr -CA %s/ca.crt -CAkey %s/ca.key -CAcreateserial -out %s/server.crt',
    $this->testDir, $this->testDir, $this->testDir, $this->testDir
));

// 生成客户端私钥
$io->section('生成客户端证书');
shell_exec(sprintf('openssl genrsa -out %s/client.key 2048', $this->testDir));

// 生成客户端CSR
shell_exec(sprintf(
    'openssl req -new -key %s/client.key -out %s/client.csr -subj "/CN=Test Client"',
    $this->testDir, $this->testDir
));

// 使用CA签名客户端证书
shell_exec(sprintf(
    'openssl x509 -req -days 365 -in %s/client.csr -CA %s/ca.crt -CAkey %s/ca.key -CAcreateserial -out %s/client.crt',
    $this->testDir, $this->testDir, $this->testDir, $this->testDir
));

// 清理临时文件
unlink($this->testDir . '/server.csr');
unlink($this->testDir . '/client.csr');
unlink($this->testDir . '/ca.srl');

$io->success('证书生成完成');
$io->text('证书文件位置:');
$io->listing([
    'CA证书: test/ca.crt',
    'CA私钥: test/ca.key',
    '服务器证书: test/server.crt',
    '服务器私钥: test/server.key',
    '客户端证书: test/client.crt',
    '客户端私钥: test/client.key'
]);
