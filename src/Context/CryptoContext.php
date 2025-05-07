<?php

namespace Tourze\Workerman\TLS\Context;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Crypto\AesGcmCipher;
use Tourze\Workerman\TLS\Crypto\CipherInterface;

/**
 * 管理TLS连接的加密状态
 */
class CryptoContext
{
    private bool $encryptionActive = false;
    private bool $compressionActive = false;
    private ?string $clientMACKey = null;
    private ?string $serverMACKey = null;
    private ?string $clientEncryptKey = null;
    private ?string $serverEncryptKey = null;
    private int $macSize = 32; // SHA256 = 32 bytes
    private ?CipherInterface $cipher = null;

    public function __construct(
        private readonly bool $isServer
    )
    {
    }

    public function isEncryptionActive(): bool
    {
        return $this->encryptionActive;
    }

    public function activateEncryption(): void
    {
        $this->encryptionActive = true;
        $this->cipher = new AesGcmCipher();
        LogUtil::info('Encryption activated');
    }

    public function activateClientToServerEncryption(): void
    {
        $this->encryptionActive = true;
        $this->cipher = new AesGcmCipher();
        LogUtil::info('Client to server encryption activated');
    }

    public function activateServerToClientEncryption(): void
    {
        $this->encryptionActive = true;
        $this->cipher = new AesGcmCipher();
        LogUtil::info('Server to client encryption activated');
    }

    public function isCompressionActive(): bool
    {
        return $this->compressionActive;
    }

    public function getMACSize(): int
    {
        return $this->macSize;
    }

    public function decrypt(string $data, int $seqNum): string
    {
        if (!$this->encryptionActive || !$this->cipher) {
            return $data;
        }

        // Use negotiated cipher suite for decryption
        $key = $this->isServer ? $this->clientEncryptKey : $this->serverEncryptKey;
        return $this->cipher->decrypt($data, $key);
    }

    public function encrypt(string $data, int $seqNum): string
    {
        if (!$this->encryptionActive || !$this->cipher) {
            return $data;
        }

        // Use negotiated cipher suite for encryption
        $key = $this->isServer ? $this->serverEncryptKey : $this->clientEncryptKey;
        return $this->cipher->encrypt($data, $key);
    }

    public function calculateMAC(string $data, int $seqNum, int $contentType): string
    {
        if (!$this->encryptionActive) {
            return '';
        }

        // Construct MAC input:
        // sequence_number(8) + content_type(1) + length(2) + data
        $macInput = pack('J', $seqNum) . // 8-byte sequence number
            chr($contentType) . // 1-byte content type
            pack('n', strlen($data)) . // 2-byte length
            $data; // actual data

        $key = $this->isServer ? $this->serverMACKey : $this->clientMACKey;
        return hash_hmac('sha256', $macInput, $key, true);
    }

    public function verifyMAC(string $data, string $mac, int $seqNum, int $contentType): bool
    {
        if (!$this->encryptionActive) {
            return true;
        }

        // Construct MAC input same as calculateMAC
        $macInput = pack('J', $seqNum) .
            chr($contentType) .
            pack('n', strlen($data)) .
            $data;

        $key = $this->isServer ? $this->clientMACKey : $this->serverMACKey;

        return hash_equals(
            hash_hmac('sha256', $macInput, $key, true),
            $mac
        );
    }

    public function decompress(string $data): string
    {
        if (!$this->compressionActive) {
            return $data;
        }
        return gzuncompress($data);
    }

    public function compress(string $data): string
    {
        if (!$this->compressionActive) {
            return $data;
        }
        return gzcompress($data);
    }

    /**
     * 从主密钥派生会话密钥
     */
    public function deriveKeys(string $masterSecret, string $serverRandom, string $clientRandom): void
    {
        LogUtil::info('Deriving session keys from master secret');

        // 根据RFC5246 Section 6.3, key_block的计算:
        // key_block = PRF(SecurityParameters.master_secret,
        //                 "key expansion",
        //                 SecurityParameters.server_random + SecurityParameters.client_random)

        $seed = $serverRandom . $clientRandom;
        $keyBlock = $this->prf($masterSecret, "key expansion", $seed);

        // 根据选择的密码套件确定密钥长度
        $macKeyLength = 32; // SHA256 = 32 bytes
        $encKeyLength = 32; // AES-256 = 32 bytes
        $ivLength = 16;     // AES block size = 16 bytes

        // 从key_block中提取各个密钥
        $offset = 0;

        // MAC密钥
        $this->clientMACKey = substr($keyBlock, $offset, $macKeyLength);
        $offset += $macKeyLength;
        $this->serverMACKey = substr($keyBlock, $offset, $macKeyLength);
        $offset += $macKeyLength;

        // 加密密钥
        $this->clientEncryptKey = substr($keyBlock, $offset, $encKeyLength);
        $offset += $encKeyLength;
        $this->serverEncryptKey = substr($keyBlock, $offset, $encKeyLength);
        $offset += $encKeyLength;

        LogUtil::info('Session keys derived successfully');
        LogUtil::debug('Key lengths - MAC: ' . $macKeyLength .
            ', Encryption: ' . $encKeyLength);
    }

    /**
     * TLS PRF (伪随机函数)实现
     */
    private function prf(string $secret, string $label, string $seed): string
    {
        // TLS 1.2 使用 SHA-256 作为PRF
        $hmac = function (string $key, string $data) {
            return hash_hmac('sha256', $data, $key, true);
        };

        // P_hash 实现
        $result = '';
        $a = $hmac($secret, $label . $seed);

        // 生成足够长度的密钥材料
        while (strlen($result) < 136) { // 需要的总长度: (32+32+16)*2 = 136 bytes
            $result .= $hmac($secret, $a . $label . $seed);
            $a = $hmac($secret, $a);
        }

        return $result;
    }
}
