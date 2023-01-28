<?php

namespace Selective\XmlDSig;

use DOMDocument;
use DOMXPath;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use Selective\XmlDSig\Exception\CertificateException;

/**
 * The public key store.
 */
final class PublicKeyStore
{
    /**
     * @var OpenSSLAsymmetricKey[]
     */
    private array $publicKeys = [];

    /**
     * Add public key.
     *
     * @param OpenSSLAsymmetricKey $publicKey The public key
     *
     * @return void
     */
    public function addPublicKey(OpenSSLAsymmetricKey $publicKey): void
    {
        $this->publicKeys[] = $publicKey;
    }

    /**
     * Return public keys.
     *
     * @return OpenSSLAsymmetricKey[] The public keys
     */
    public function getPublicKeys(): array
    {
        return $this->publicKeys;
    }

    /**
     * Load public key from a PKCS#12 certificate (PFX) certificate.
     *
     * @param string $pkcs12 The certificate data
     * @param string $password The encryption password for unlocking the PKCS12 certificate
     *
     * @throws CertificateException
     *
     * @return void
     */
    public function loadFromPkcs12(string $pkcs12, string $password): void
    {
        $status = openssl_pkcs12_read($pkcs12, $certificates, $password);

        if (!$status) {
            throw new CertificateException('Invalid certificate. Could not read public key from PKCS12 certificate.');
        }

        $publicKey = openssl_get_publickey($certificates['cert']);

        if ($publicKey === false) {
            throw new CertificateException('Invalid public key');
        }

        $this->addPublicKey($publicKey);
    }

    /**
     * Load the public key content.
     *
     * @param OpenSSLCertificate $publicKey The public key data
     *
     * @throws CertificateException
     *
     * @return void
     */
    public function loadFromCertificate(OpenSSLCertificate $publicKey): void
    {
        $publicKeyIdentifier = openssl_pkey_get_public($publicKey);

        if (!$publicKeyIdentifier) {
            throw new CertificateException('Invalid public key');
        }

        $this->addPublicKey($publicKeyIdentifier);
    }

    /**
     * Load the public key content.
     *
     * @param string $pem A PEM formatted public key
     *
     * @throws CertificateException
     *
     * @return void
     */
    public function loadFromPem(string $pem): void
    {
        $publicKey = openssl_pkey_get_public($pem);

        if (!$publicKey) {
            throw new CertificateException('Invalid public key');
        }

        $this->addPublicKey($publicKey);
    }

    /**
     * Load the public key content from XML document.
     *
     * @param DOMDocument $xml The document
     *
     * @return void
     */
    public function loadFromDocument(DOMDocument $xml): void
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        // Find the X509Certificate nodes
        $x509CertificateNodes = $xpath->query('//xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate');

        // Throw an exception if no signature was found.
        if (!$x509CertificateNodes || $x509CertificateNodes->length < 1) {
            // No X509Certificate item was found in the document
            return;
        }

        $x509Reader = new X509Reader();
        foreach ($x509CertificateNodes as $domNode) {
            $base64 = $domNode->nodeValue;
            if (!$base64) {
                continue;
            }

            $this->loadFromCertificate($x509Reader->fromRawBase64($base64));
        }
    }
}
