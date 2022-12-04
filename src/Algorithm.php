<?php

namespace Selective\XmlDSig;

use Selective\XmlDSig\Exception\XmlSignerException;
use UnexpectedValueException;

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
    public const SIGNATURE_ECDSA_SHA256_URL = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';

    //
    // OpenSSL digest methods
    // https://www.php.net/manual/en/function.openssl-get-md-methods.php
    //
    public const METHOD_SHA1 = 'sha1';
    public const METHOD_SHA224 = 'sha224';
    public const METHOD_SHA256 = 'sha256';
    public const METHOD_SHA384 = 'sha384';
    public const METHOD_SHA512 = 'sha512';
    public const METHOD_ECDSA_SHA256 = 'ecdsa-with-SHA256';

    //
    // Digest Algorithm Identifiers
    // https://www.w3.org/TR/xmldsig-core/#sec-AlgID
    //
    public const DIGEST_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#sha1';
    public const DIGEST_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha224';
    public const DIGEST_SHA256_URL = 'http://www.w3.org/2001/04/xmlenc#sha256';
    public const DIGEST_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    public const DIGEST_SHA512_URL = 'http://www.w3.org/2001/04/xmlenc#sha512';
    public const DIGEST_ECDSA_SHA256_URL = 'http://www.w3.org/2001/04/xmlenc#ecdsa-sha256';

    private int $signatureSslAlgorithm = 0;

    private string $signatureAlgorithmName = '';

    private string $signatureAlgorithmUrl = '';

    private string $digestAlgorithmName = '';

    private string $digestAlgorithmUrl = '';

    /**
     * The constructor.
     *
     * @param string $signatureMethodAlgorithm
     * @param string|null $digestMethodAlgorithm
     */
    public function __construct(string $signatureMethodAlgorithm, string $digestMethodAlgorithm = null)
    {
        $this->setSignatureMethodAlgorithm($signatureMethodAlgorithm);
        $this->setDigestMethodAlgorithm($digestMethodAlgorithm ?? $signatureMethodAlgorithm);
    }

    /**
     * Set signature and digest algorithm.
     *
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     */
    private function setSignatureMethodAlgorithm(string $algorithm): void
    {
        switch ($algorithm) {
            case self::METHOD_SHA1:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA1_URL;
                $this->signatureSslAlgorithm = OPENSSL_ALGO_SHA1;
                break;
            case self::METHOD_SHA224:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA224_URL;
                $this->signatureSslAlgorithm = OPENSSL_ALGO_SHA224;
                break;
            case self::METHOD_SHA256:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA256_URL;
                $this->signatureSslAlgorithm = OPENSSL_ALGO_SHA256;
                break;
            case self::METHOD_SHA384:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA384_URL;
                $this->signatureSslAlgorithm = OPENSSL_ALGO_SHA384;
                break;
            case self::METHOD_SHA512:
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA512_URL;
                $this->signatureSslAlgorithm = OPENSSL_ALGO_SHA512;
                break;
            case self::METHOD_ECDSA_SHA256:
                $this->signatureAlgorithmUrl = self::SIGNATURE_ECDSA_SHA256_URL;
                $this->signatureSslAlgorithm = 0;
                break;
            default:
                throw new UnexpectedValueException(sprintf('Unsupported algorithm: %s>', $algorithm));
        }

        $this->signatureAlgorithmName = $algorithm;
    }

    /**
     * Set signature and digest algorithm.
     *
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     */
    private function setDigestMethodAlgorithm(string $algorithm): void
    {
        switch ($algorithm) {
            case self::METHOD_SHA1:
                $this->digestAlgorithmUrl = self::DIGEST_SHA1_URL;
                break;
            case self::METHOD_SHA224:
                $this->digestAlgorithmUrl = self::DIGEST_SHA224_URL;
                break;
            case self::METHOD_SHA256:
                $this->digestAlgorithmUrl = self::DIGEST_SHA256_URL;
                break;
            case self::METHOD_SHA384:
                $this->digestAlgorithmUrl = self::DIGEST_SHA384_URL;
                break;
            case self::METHOD_SHA512:
                $this->digestAlgorithmUrl = self::DIGEST_SHA512_URL;
                break;
            case self::METHOD_ECDSA_SHA256:
                $this->digestAlgorithmUrl = self::DIGEST_ECDSA_SHA256_URL;
                break;
            default:
                throw new XmlSignerException("Cannot validate digest: Unsupported algorithm <$algorithm>");
        }

        $this->digestAlgorithmName = $algorithm;
    }

    public function getSignatureAlgorithmUrl(): string
    {
        return $this->signatureAlgorithmUrl;
    }

    public function getDigestAlgorithmUrl(): string
    {
        return $this->digestAlgorithmUrl;
    }

    public function getSignatureSslAlgorithm(): int
    {
        return $this->signatureSslAlgorithm;
    }

    public function getSignatureAlgorithmName(): string
    {
        return $this->signatureAlgorithmName;
    }

    public function getDigestAlgorithmName(): string
    {
        return $this->digestAlgorithmName;
    }
}
