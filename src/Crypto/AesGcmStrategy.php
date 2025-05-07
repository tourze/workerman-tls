<?php

namespace Tourze\Workerman\TLS\Crypto;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Enum\CipherSuite;

/**
 * AES-GCM密码套件策略
 */
class AesGcmStrategy implements CipherSuiteStrategy
{
    private array $supportedSuites = [
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ];

    public function negotiate(array $clientSuites): ?CipherSuite
    {
        LogUtil::info("Negotiating AES-GCM cipher suite");
        LogUtil::debug("Client suites: " . implode(', ', array_map(fn($s) => '0x' . dechex($s), $clientSuites)));

        foreach ($clientSuites as $suite) {
            try {
                $cipherSuite = CipherSuite::from($suite);
                if (in_array($cipherSuite, $this->supportedSuites)) {
                    LogUtil::info("Selected cipher suite: " . $cipherSuite->name);
                    return $cipherSuite;
                }
            } catch (\ValueError $e) {
                LogUtil::warning("Unsupported cipher suite: 0x" . dechex($suite));
                continue;
            }
        }

        LogUtil::info("No suitable AES-GCM cipher suite found");
        return null;
    }

    public function createCipher(): CipherInterface
    {
        return new AesGcmCipher();
    }
}
