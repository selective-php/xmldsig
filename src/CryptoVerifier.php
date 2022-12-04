<?php

namespace Selective\XmlDSig;

use Selective\XmlDSig\Exception\CertificateException;
use Selective\XmlDSig\Exception\XmlSignatureValidatorException;

final class CryptoVerifier implements CryptoVerifierInterface
{
    private PublicKeyStore $publicKeyStore;

    /**
     * The constructor.
     *
     * @param PublicKeyStore $publicKeyStore The public key store
     */
    public function __construct(PublicKeyStore $publicKeyStore)
    {
        $this->publicKeyStore = $publicKeyStore;
    }

    public function verify(string $data, string $signature, string $algorithm): bool
    {
        $publicKeys = $this->publicKeyStore->getPublicKeys();
        if (!$publicKeys) {
            throw new CertificateException('No public key provided');
        }

        $algo = $this->mapUrlToOpenSslAlgoCode($algorithm);

        foreach ($publicKeys as $publicKeyId) {
            $status = openssl_verify($data, $signature, $publicKeyId, $algo);

            if ($status === 1) {
                return true;
            }
        }

        // The XML signature is not valid
        return false;
    }

    private function mapUrlToOpenSslAlgoCode(string $algorithm): int
    {
        switch ($algorithm) {
            case Algorithm::SIGNATURE_SHA1_URL:
                return OPENSSL_ALGO_SHA1;
            case Algorithm::SIGNATURE_SHA224_URL:
                return OPENSSL_ALGO_SHA224;
            case Algorithm::SIGNATURE_SHA256_URL:
                return OPENSSL_ALGO_SHA256;
            case Algorithm::SIGNATURE_SHA384_URL:
                return OPENSSL_ALGO_SHA384;
            case Algorithm::SIGNATURE_SHA512_URL:
                return OPENSSL_ALGO_SHA512;
            default:
                throw new XmlSignatureValidatorException("Cannot verify: Unsupported Algorithm <$algorithm>");
        }
    }

    /**
     * Map algo to OpenSSL method name.
     *
     * @param string $algorithm The url
     *
     * @return string The name of the OpenSSL algorithm
     */
    private function mapUrlToOpenSslDigestAlgo(string $algorithm): string
    {
        switch ($algorithm) {
            case Algorithm::SIGNATURE_SHA1_URL:
                return Algorithm::DIGEST_SHA1;
            case Algorithm::SIGNATURE_SHA224_URL:
                return Algorithm::DIGEST_SHA224;
            case Algorithm::SIGNATURE_SHA256_URL:
                return Algorithm::DIGEST_SHA256;
            case Algorithm::SIGNATURE_SHA384_URL:
                return Algorithm::DIGEST_SHA384;
            case Algorithm::SIGNATURE_SHA512_URL:
                return Algorithm::DIGEST_SHA512;
            default:
                throw new XmlSignatureValidatorException("Cannot verify: Unsupported Algorithm <$algorithm>");
        }
    }

    public function computeDigest(string $data, string $algorithm): string
    {
        $digestAlgo = $this->mapUrlToOpenSslDigestAlgo($algorithm);
        $digest = openssl_digest($data, $digestAlgo, true);

        if ($digest === false) {
            throw new XmlSignatureValidatorException('Invalid digest value');
        }

        return $digest;
    }
}
