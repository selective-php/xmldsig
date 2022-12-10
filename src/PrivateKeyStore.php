<?php

namespace Selective\XmlDSig;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Selective\XmlDSig\Exception\CertificateException;
use Selective\XmlDSig\Exception\XmlSignerException;
use UnexpectedValueException;

final class PrivateKeyStore
{
    /**
     * @var OpenSSLCertificate[]
     */
    private array $certificates = [];

    private ?OpenSSLAsymmetricKey $privateKey = null;

    private ?string $privateKeyPem = null;

    private ?string $modulus = null;

    private ?string $publicExponent = null;

    /**
     * Add X509 certificate.
     *
     * @param OpenSSLCertificate $certificate
     *
     * @return void
     */
    public function addCertificate(OpenSSLCertificate $certificate): void
    {
        $this->certificates[] = $certificate;
    }

    /**
     * Get X509 certificates.
     *
     * @return OpenSSLCertificate[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /**
     * Load X509 certificates from PEM.
     * PEM is a base64 format for certificates.
     *
     * @param string $certificate The certificate bundle
     *
     * @return void
     */
    public function addCertificatesFromX509Pem(string $certificate): void
    {
        $x509Reader = new X509Reader();
        foreach ($x509Reader->fromPem($certificate) as $certificate) {
            $this->addCertificate($certificate);
        }
    }

    /**
     * Read and load a private key.
     *
     * @param string $pem The PEM formatted private key
     * @param string $password The PEM password
     *
     * @throws XmlSignerException
     *
     * @return void
     */
    public function loadFromPem(string $pem, string $password): void
    {
        // Read the private key
        $privateKey = openssl_pkey_get_private($pem, $password);

        if (!$privateKey) {
            throw new XmlSignerException('Invalid password or private key');
        }

        $this->privateKey = $privateKey;
        $this->privateKeyPem = $pem;

        $this->loadPrivateKeyDetails();
    }

    /**
     * Load the PKCS12 (PFX) content.
     *
     * PKCS12 is an encrypted container that contains the public key and private key combined in binary format.
     *
     * @param string $pkcs12 The content
     * @param string $password The password
     *
     * @throws CertificateException
     *
     * @return void
     */
    public function loadFromPkcs12(string $pkcs12, string $password): void
    {
        if (!$pkcs12) {
            throw new CertificateException('The PKCS12 certificate must not be empty.');
        }

        $status = openssl_pkcs12_read($pkcs12, $certInfo, $password);

        if (!$status) {
            throw new CertificateException(
                'Invalid certificate. Could not read private key from PKCS12 certificate. ' .
                openssl_error_string() .
                $pkcs12
            );
        }

        // Read the private key
        $this->privateKeyPem = (string)$certInfo['pkey'];

        if (!$this->privateKeyPem) {
            throw new CertificateException('Invalid or missing private key');
        }

        $privateKey = openssl_pkey_get_private($this->privateKeyPem);

        if (!$privateKey) {
            throw new CertificateException('Invalid private key');
        }

        $this->privateKey = $privateKey;

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
        if (!$this->privateKey) {
            throw new UnexpectedValueException('Private key is not defined');
        }

        $details = openssl_pkey_get_details($this->privateKey);

        if ($details === false) {
            throw new UnexpectedValueException('Invalid private key');
        }

        $key = $this->getPrivateKeyDetailKey($details['type']);

        if (isset($details[$key]['n'])) {
            $this->modulus = base64_encode($details[$key]['n']);
        }
        if (isset($details[$key]['e'])) {
            $this->publicExponent = base64_encode($details[$key]['e']);
        }
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

    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey;
    }

    public function getPrivateKeyAsPem(): ?string
    {
        return $this->privateKeyPem;
    }

    public function getModulus(): ?string
    {
        return $this->modulus;
    }

    public function getPublicExponent(): ?string
    {
        return $this->publicExponent;
    }
}
