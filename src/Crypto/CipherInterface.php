<?php

namespace Tourze\Workerman\TLS\Crypto;

interface CipherInterface
{
    /**
     * Encrypt data using the given key
     */
    public function encrypt(string $data, string $key): string;

    /**
     * Decrypt data using the given key
     */
    public function decrypt(string $data, string $key): string;
}
