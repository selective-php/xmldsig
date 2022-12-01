<?php

namespace Selective\XmlDSig;

use OpenSSLAsymmetricKey;
use Selective\XmlDSig\Exception\XmlSignerException;
use UnexpectedValueException;

final class OpenSslCryptoEncoder implements CryptoEncoderInterface
{
    //
    // Signature Algorithm Identifiers, RSA (PKCS#1 v1.5)
    // https://www.w3.org/TR/xmldsig-core/#sec-PKCS1
    //
    private const SIGNATURE_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private const SIGNATURE_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    private const SIGNATURE_SHA256_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const SIGNATURE_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    private const SIGNATURE_SHA512_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    //
    // Digest Algorithm Identifiers
    // https://www.w3.org/TR/xmldsig-core/#sec-AlgID
    //
    private const DIGEST_SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#sha1';
    private const DIGEST_SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha224';
    private const DIGEST_SHA256_URL = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const DIGEST_SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    private const DIGEST_SHA512_URL = 'http://www.w3.org/2001/04/xmlenc#sha512';

    private int $sslAlgorithm = 0;

    private string $algorithmName = '';

    private string $signatureAlgorithmUrl = '';

    private string $digestAlgorithmUrl = '';

    /**
     * @var OpenSSLAsymmetricKey|resource|null
     */
    private $privateKeyId = null;

    private string $modulus = '';

    private string $publicExponent = '';

    /**
     * The constructor.
     *
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     */
    public function __construct(string $algorithm)
    {
        $this->setAlgorithm($algorithm);
    }

    public function computeSignature(string $data): string
    {
        // Calculate and encode digest value
        if (!$this->privateKeyId) {
            throw new UnexpectedValueException('Undefined private key');
        }

        $status = openssl_sign($data, $signatureValue, $this->privateKeyId, $this->sslAlgorithm);

        if (!$status) {
            throw new XmlSignerException('Computing of the signature failed');
        }

        return $signatureValue;
    }

    /**
     * Load the PFX content.
     *
     * @param string $pfx PFX content
     * @param string $password PFX password
     *
     * @throws XmlSignerException
     *
     * @return void
     */
    public function loadPfx(string $pfx, string $password): void
    {
        $status = openssl_pkcs12_read($pfx, $certInfo, $password);

        if (!$status) {
            throw new XmlSignerException('Invalid PFX password');
        }

        // Read the private key
        $privateKeyId = openssl_pkey_get_private((string)$certInfo['pkey']);

        if (!$privateKeyId) {
            throw new XmlSignerException('Invalid private key');
        }

        $this->privateKeyId = $privateKeyId;

        $this->loadPrivateKeyDetails();
    }

    /**
     * Load private key details.
     *
     * @throws UnexpectedValueException
     *
     * @return void
     */
    private function loadPrivateKeyDetails(): void
    {
        if (!$this->privateKeyId) {
            throw new UnexpectedValueException('Private key is not defined');
        }

        $details = openssl_pkey_get_details($this->privateKeyId);

        if ($details === false) {
            throw new UnexpectedValueException('Invalid private key');
        }

        $key = $this->getPrivateKeyDetailKey($details['type']);
        $this->modulus = base64_encode($details[$key]['n']);
        $this->publicExponent = base64_encode($details[$key]['e']);
    }

    /**
     * Get private key details key type.
     *
     * @param int $type The type
     *
     * @return string The array key
     */
    private function getPrivateKeyDetailKey(int $type): string
    {
        $key = '';
        $key = $type === OPENSSL_KEYTYPE_RSA ? 'rsa' : $key;
        $key = $type === OPENSSL_KEYTYPE_DSA ? 'dsa' : $key;
        $key = $type === OPENSSL_KEYTYPE_DH ? 'dh' : $key;
        $key = $type === OPENSSL_KEYTYPE_EC ? 'ec' : $key;

        return $key;
    }

    /**
     * Read and load a private key.
     *
     * @param string $privateKey The private key
     * @param string $password The PEM password
     *
     * @throws XmlSignerException
     *
     * @return void
     */
    public function loadPrivateKey(string $privateKey, string $password): void
    {
        // Read the private key
        $privateKeyId = openssl_pkey_get_private($privateKey, $password);

        if (!$privateKeyId) {
            throw new XmlSignerException('Invalid password or private key');
        }

        $this->privateKeyId = $privateKeyId;

        $this->loadPrivateKeyDetails();
    }

    /**
     * Set signature and digest algorithm.
     *
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     */
    private function setAlgorithm(string $algorithm): void
    {
        switch ($algorithm) {
            case 'sha1':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA1_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA1_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA1;
                break;
            case 'sha224':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA224_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA224_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA224;
                break;
            case 'sha256':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA256_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA256_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA256;
                break;
            case 'sha384':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA384_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA384_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA384;
                break;
            case 'sha512':
                $this->signatureAlgorithmUrl = self::SIGNATURE_SHA512_URL;
                $this->digestAlgorithmUrl = self::DIGEST_SHA512_URL;
                $this->sslAlgorithm = OPENSSL_ALGO_SHA512;
                break;
            default:
                throw new XmlSignerException("Cannot validate digest: Unsupported algorithm <$algorithm>");
        }

        $this->algorithmName = $algorithm;
    }

    public function computeDigest(string $data): string
    {
        // Calculate and encode digest value
        $digestValue = openssl_digest($data, $this->algorithmName, true);

        if ($digestValue === false) {
            throw new UnexpectedValueException('Invalid digest value');
        }

        return $digestValue;
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->signatureAlgorithmUrl;
    }

    public function getDigestAlgorithm(): string
    {
        return $this->digestAlgorithmUrl;
    }

    public function getModulus(): string
    {
        return $this->modulus;
    }

    public function getPublicExponent(): string
    {
        return $this->publicExponent;
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        // Free the key from memory
        // PHP 8 deprecates openssl_free_key and automatically destroys the key instance when it goes out of scope.
        if ($this->privateKeyId && version_compare(PHP_VERSION, '8.0.0', '<')) {
            openssl_free_key($this->privateKeyId);
        }
    }
}
