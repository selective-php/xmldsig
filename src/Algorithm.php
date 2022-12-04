<?php

namespace Selective\XmlDSig;

use Selective\XmlDSig\Exception\XmlSignerException;

final class Algorithm
{
    //
    // Signature Algorithm Identifiers, RSA (PKCS#1 v1.5)
    // https://www.w3.org/TR/xmldsig-core/#sec-PKCS1
    //
    public const SIGNATURE_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    public const SIGNATURE_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    public const SIGNATURE_SHA256_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    public const SIGNATURE_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    public const SIGNATURE_SHA512_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    //
    // OpenSSL digest methods
    // https://www.php.net/manual/en/function.openssl-get-md-methods.php
    //
    public const DIGEST_SHA1 = 'sha1';
    public const DIGEST_SHA224 = 'sha224';
    public const DIGEST_SHA256 = 'sha256';
    public const DIGEST_SHA384 = 'sha384';
    public const DIGEST_SHA512 = 'sha512';

    //
    // Digest Algorithm Identifiers
    // https://www.w3.org/TR/xmldsig-core/#sec-AlgID
    //
    public const DIGEST_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#sha1';
    public const DIGEST_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha224';
    public const DIGEST_SHA256_URL = 'http://www.w3.org/2001/04/xmlenc#sha256';
    public const DIGEST_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    public const DIGEST_SHA512_URL = 'http://www.w3.org/2001/04/xmlenc#sha512';

    private int $sslAlgorithm = 0;

    private string $digestMethodName = '';

    private string $signatureAlgorithmUrl = '';

    private string $digestAlgorithmUrl = '';

    /**
     * The constructor.
     *
     * @param string $digestMethod Values: sha1, sha224, sha256, sha384, sha512
     */
    public function __construct(string $digestMethod)
    {
        $this->setAlgorithm($digestMethod);
    }

    /**
     * Set signature and digest algorithm.
     *
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     */
    private function setAlgorithm(string $algorithm): void
    {
        switch ($algorithm) {
            case self::DIGEST_SHA1:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA1_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA1_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA1;
                break;
            case self::DIGEST_SHA224:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA224_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA224_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA224;
                break;
            case self::DIGEST_SHA256:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA256_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA256_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA256;
                break;
            case self::DIGEST_SHA384:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA384_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA384_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA384;
                break;
            case self::DIGEST_SHA512:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA512_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA512_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA512;
                break;
            default:
                throw new XmlSignerException("Cannot validate digest: Unsupported algorithm <$algorithm>");
        }

        $this->digestMethodName = $algorithm;
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->signatureAlgorithmUrl;
    }

    public function getDigestAlgorithm(): string
    {
        return $this->digestAlgorithmUrl;
    }

    public function getSslAlgorithm(): int
    {
        return $this->sslAlgorithm;
    }

    public function getDigestMethodName(): string
    {
        return $this->digestMethodName;
    }
}
