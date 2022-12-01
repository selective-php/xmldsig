<?php

namespace Selective\XmlDSig;

use OpenSSLAsymmetricKey;
use Selective\XmlDSig\Exception\XmlSignatureValidatorException;

final class OpenSslCryptoDecoder implements CryptoDecoderInterface
{
    //
    // RSA (PKCS#1 v1.5) Identifier
    // https://www.w3.org/TR/xmldsig-core/#sec-PKCS1
    //
    private const SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private const SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    private const SHA256_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    private const SHA512_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    /**
     * @var OpenSSLAsymmetricKey|resource|null
     */
    private $publicKeyId = null;

    /**
     * Read and load the pfx file.
     *
     * @param string $pkcs12 The certificate store data
     * @param string $password The encryption password for unlocking the PKCS12 file
     *
     * @throws XmlSignatureValidatorException
     *
     * @return void
     */
    public function loadPfx(string $pkcs12, string $password): void
    {
        $status = openssl_pkcs12_read($pkcs12, $certificates, $password);

        if (!$status) {
            throw new XmlSignatureValidatorException('Invalid PFX password');
        }

        $publicKeyId = openssl_get_publickey($certificates['cert']);

        if ($publicKeyId === false) {
            throw new XmlSignatureValidatorException('Invalid public key');
        }

        $this->publicKeyId = $publicKeyId;
    }

    /**
     * Load the public key content.
     *
     * @param string $publicKey The public key data
     *
     * @throws XmlSignatureValidatorException
     *
     * @return void
     */
    public function loadPublicKey(string $publicKey): void
    {
        $publicKeyId = openssl_get_publickey($publicKey);

        if (!$publicKeyId) {
            throw new XmlSignatureValidatorException('Invalid public key');
        }

        $this->publicKeyId = $publicKeyId;
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        // Free the key from memory
        // PHP 8 deprecates openssl_free_key and automatically destroys the key instance when it goes out of scope.
        if ($this->publicKeyId && version_compare(PHP_VERSION, '8.0.0', '<')) {
            openssl_free_key($this->publicKeyId);
        }
    }

    public function verify(string $data, string $signature, string $algorithm): bool
    {
        if (!$this->publicKeyId) {
            throw new XmlSignatureValidatorException('No public key provided');
        }

        $algo = $this->mapUrlToOpenSslAlgoCode($algorithm);

        $status = openssl_verify($data, $signature, $this->publicKeyId, $algo);

        if ($status !== 1) {
            // The XML signature is not valid
            return false;
        }

        return true;
    }

    private function mapUrlToOpenSslAlgoCode(string $algorithm): int
    {
        switch ($algorithm) {
            case self::SHA1_URL:
                return OPENSSL_ALGO_SHA1;
            case self::SHA224_URL:
                return OPENSSL_ALGO_SHA224;
            case self::SHA256_URL:
                return OPENSSL_ALGO_SHA256;
            case self::SHA384_URL:
                return OPENSSL_ALGO_SHA384;
            case self::SHA512_URL:
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
            case self::SHA1_URL:
                return 'sha1';
            case self::SHA224_URL:
                return 'sha224';
            case self::SHA256_URL:
                return 'sha256';
            case self::SHA384_URL:
                return 'sha384';
            case self::SHA512_URL:
                return 'sha512';
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
