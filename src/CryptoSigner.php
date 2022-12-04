<?php

namespace Selective\XmlDSig;

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

        $status = openssl_sign($data, $signatureValue, $privateKey, $this->algorithm->getSslAlgorithm());

        if (!$status) {
            throw new XmlSignerException('Computing of the signature failed');
        }

        return $signatureValue;
    }

    public function computeDigest(string $data): string
    {
        // Calculate and encode digest value
        $digestValue = openssl_digest($data, $this->algorithm->getDigestMethodName(), true);

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
