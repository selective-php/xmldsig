<?php

namespace Selective\XmlDSig;

use EllipticCurve\Ecdsa;
use EllipticCurve\PrivateKey;
use Selective\XmlDSig\Exception\CertificateException;
use Selective\XmlDSig\Exception\XmlSignerException;
use UnexpectedValueException;

final class CryptoSigner implements CryptoSignerInterface
{
    private PrivateKeyStore $privateKeyStore;

    private Algorithm $algorithm;

    /**
     * The constructor.
     *
     * @param PrivateKeyStore $privateKeyStore The private key store
     * @param Algorithm $algorithm The algorithm
     */
    public function __construct(PrivateKeyStore $privateKeyStore, Algorithm $algorithm)
    {
        $this->privateKeyStore = $privateKeyStore;
        $this->algorithm = $algorithm;
    }

    public function computeSignature(string $data): string
    {
        $privateKey = $this->privateKeyStore->getPrivateKey();

        // Calculate and encode digest value
        if (!$privateKey) {
            throw new CertificateException('Undefined private key');
        }

        // Algorithm::METHOD_ECDSA_SHA256
        if ($this->algorithm->getSignatureAlgorithmName() === Algorithm::METHOD_ECDSA_SHA256) {
            // Generate privateKey from PEM string
            $privateKey = PrivateKey::fromPem(
                '-----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
    oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
    RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
    -----END EC PRIVATE KEY-----'
            );
            $signature = Ecdsa::sign($data, $privateKey);
            $signatureValue = $signature->_toString();
            $signatureValue2 = $signature->toBase64();
            $signatureValue2 = base64_decode($signatureValue2);

            return $signatureValue2;
        }

        $status = openssl_sign($data, $signatureValue, $privateKey, $this->algorithm->getSignatureSslAlgorithm());

        if (!$status) {
            throw new XmlSignerException('Computing of the signature failed');
        }

        return $signatureValue;
    }

    public function computeDigest(string $data): string
    {
        // Calculate and encode digest value
        $digestValue = openssl_digest($data, $this->algorithm->getDigestAlgorithmName(), true);

        if ($digestValue === false) {
            throw new UnexpectedValueException('Invalid digest value');
        }

        return $digestValue;
    }

    public function getPrivateKeyStore(): PrivateKeyStore
    {
        return $this->privateKeyStore;
    }

    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
    }
}
