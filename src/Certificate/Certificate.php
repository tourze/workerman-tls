<?php

namespace Tourze\Workerman\TLS\Certificate;

/**
 * X.509 证书封装
 */
class Certificate
{
    private $cert;
    private $publicKey;

    public function __construct(string $certData)
    {
        $this->cert = openssl_x509_read($certData);
        if ($this->cert === false) {
            throw new \RuntimeException('Invalid certificate data');
        }
        $this->publicKey = openssl_pkey_get_public($this->cert);
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function verify(Certificate $issuer): bool
    {
        return openssl_x509_verify($this->cert, $issuer->cert) === 1;
    }

    public function __destruct()
    {
        if ($this->cert) {
            openssl_x509_free($this->cert);
        }
        if ($this->publicKey) {
            openssl_pkey_free($this->publicKey);
        }
    }
}
