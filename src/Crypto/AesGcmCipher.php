<?php

namespace Tourze\Workerman\TLS\Crypto;

use Tourze\Workerman\PsrLogger\LogUtil;

class AesGcmCipher implements CipherInterface
{
    private const IV_LENGTH = 12; // GCM recommended IV length
    private const TAG_LENGTH = 16; // GCM tag length
    private const CIPHER_ALGO = 'aes-256-gcm';

    public function encrypt(string $data, string $key): string
    {
        try {
            // Generate random IV
            $iv = random_bytes(self::IV_LENGTH);

            // Encrypt data
            $tag = '';
            $ciphertext = openssl_encrypt(
                $data,
                self::CIPHER_ALGO,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                '', // Additional authenticated data (AAD)
                self::TAG_LENGTH
            );

            if ($ciphertext === false) {
                throw new \RuntimeException('Encryption failed: ' . openssl_error_string());
            }

            // Combine IV + ciphertext + tag
            return $iv . $ciphertext . $tag;

        } catch  (\Throwable $e) {
            LogUtil::error('Encryption error', $e);
            throw $e;
        }
    }

    public function decrypt(string $data, string $key): string
    {
        try {
            // Extract IV, ciphertext and tag
            $iv = substr($data, 0, self::IV_LENGTH);
            $tag = substr($data, -self::TAG_LENGTH);
            $ciphertext = substr($data, self::IV_LENGTH, -self::TAG_LENGTH);

            // Decrypt data
            $plaintext = openssl_decrypt(
                $ciphertext,
                self::CIPHER_ALGO,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );

            if ($plaintext === false) {
                throw new \RuntimeException('Decryption failed: ' . openssl_error_string());
            }

            return $plaintext;

        } catch  (\Throwable $e) {
            LogUtil::error('Decryption error', $e);
            throw $e;
        }
    }
}
