<?php

namespace Tourze\Workerman\TLS\Certificate;

/**
 * 证书存储管理
 */
class CertificateStore
{
    private array $certificates = [];
    private array $trustedCAs = [];

    public function addCertificate(Certificate $cert): void
    {
        $this->certificates[] = $cert;
    }

    public function addTrustedCA(Certificate $ca): void
    {
        $this->trustedCAs[] = $ca;
    }

    public function verify(Certificate $cert): bool
    {
        // 尝试使用所有可信CA验证证书
        foreach ($this->trustedCAs as $ca) {
            if ($cert->verify($ca)) {
                return true;
            }
        }
        return false;
    }

    public function verifyChain(array $chain): bool
    {
        if (empty($chain)) {
            return false;
        }

        // 验证证书链
        $current = array_shift($chain);
        if (!$this->verify($current)) {
            return false;
        }

        // 验证剩余证书链
        foreach ($chain as $cert) {
            if (!$cert->verify($current)) {
                return false;
            }
            $current = $cert;
        }

        return true;
    }
}
