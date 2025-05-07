<?php

namespace Tourze\Workerman\TLS\Parameter;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Enum\NamedGroup;
use Tourze\Workerman\TLS\Enum\SignatureAlgorithm;
use Tourze\Workerman\TLS\Enum\TlsVersion;

/**
 * 管理TLS握手参数
 */
class HandshakeParameterManager
{
    private array $supportedGroups = [
        // TLS 1.3 groups
        NamedGroup::X25519,
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::X448,
        NamedGroup::SECP521R1,
        NamedGroup::FFDHE2048,
        NamedGroup::FFDHE3072
    ];

    private array $supportedSignatureAlgorithms = [
        // TLS 1.3 algorithms
        SignatureAlgorithm::ED25519,
        SignatureAlgorithm::ED448,
        SignatureAlgorithm::RSA_PSS_PSS_SHA256,
        SignatureAlgorithm::RSA_PSS_PSS_SHA384,
        SignatureAlgorithm::RSA_PSS_PSS_SHA512,
        SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        // TLS 1.2 algorithms
        SignatureAlgorithm::RSA_PKCS1_SHA256,
        SignatureAlgorithm::RSA_PKCS1_SHA384,
        SignatureAlgorithm::RSA_PKCS1_SHA512,
        SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SignatureAlgorithm::ECDSA_SECP521R1_SHA512
    ];

    private ?NamedGroup $selectedCurve = null;
    private ?SignatureAlgorithm $selectedSignatureAlgorithm = null;
    private array $certificates;
    private array $privateKeys;

    public function __construct(
        array $certificates = [],
        array $privateKeys = []
    ) {
        $this->certificates = $certificates;
        $this->privateKeys = $privateKeys;
    }

    public function selectCurve(array $clientGroups): NamedGroup
    {
        // 选择双方都支持的最优先的组
        foreach ($this->supportedGroups as $group) {
            if (in_array($group, $clientGroups)) {
                $this->selectedCurve = $group;
                LogUtil::info("Selected group: " . $group->name);
                return $group;
            }
        }
        throw new \RuntimeException('No common groups found');
    }

    public function selectSignatureAlgorithm(array $clientAlgorithms, TlsVersion $version): SignatureAlgorithm
    {
        // 根据TLS版本过滤算法
        $supportedAlgorithms = array_filter(
            $this->supportedSignatureAlgorithms,
            fn($alg) => match($version) {
                TlsVersion::TLS_1_3 => !$alg->isTls12Only(),
                TlsVersion::TLS_1_2 => !$alg->isTls13Only(),
                default => true
            }
        );

        // 选择双方都支持的最优先的算法
        foreach ($supportedAlgorithms as $algorithm) {
            if (in_array($algorithm, $clientAlgorithms)) {
                $this->selectedSignatureAlgorithm = $algorithm;
                LogUtil::info("Selected signature algorithm: " . $algorithm->name);
                return $algorithm;
            }
        }
        throw new \RuntimeException('No common signature algorithms found');
    }

    public function getSelectedCurve(): ?NamedGroup
    {
        return $this->selectedCurve;
    }

    public function getSelectedSignatureAlgorithm(): ?SignatureAlgorithm
    {
        return $this->selectedSignatureAlgorithm;
    }

    public function getCertificates(): array
    {
        return $this->certificates;
    }

    public function getPrivateKeys(): array
    {
        return $this->privateKeys;
    }

    public function getCurveParameters(NamedGroup $curve): array
    {
        $curveId = match($curve) {
            NamedGroup::SECP256R1 => 'prime256v1',
            NamedGroup::SECP384R1 => 'secp384r1',
            NamedGroup::SECP521R1 => 'secp521r1',
            default => throw new \InvalidArgumentException('Unsupported curve: ' . $curve->name)
        };

        return [
            'curve_id' => $curveId,
            'curve_type' => 3, // named_curve
            'curve_value' => $curve->value
        ];
    }
}
