<?php

namespace Tourze\Workerman\TLS\Crypto;

use Tourze\Workerman\TLS\Enum\CipherSuite;

/**
 * 密码套件工厂
 */
class CipherSuiteFactory
{
    private array $strategies;

    public function __construct()
    {
        $this->strategies = [
            new AesGcmStrategy()
        ];
    }

    public function negotiate(array $clientSuites): ?CipherSuite
    {
        foreach ($this->strategies as $strategy) {
            $suite = $strategy->negotiate($clientSuites);
            if ($suite !== null) {
                return $suite;
            }
        }
        return null;
    }

    public function createCipher(CipherSuite $suite): CipherInterface
    {
        foreach ($this->strategies as $strategy) {
            if ($strategy->negotiate([$suite->value]) === $suite) {
                return $strategy->createCipher();
            }
        }
        throw new \RuntimeException("No strategy found for cipher suite: {$suite->name}");
    }
}
