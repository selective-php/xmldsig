<?php

namespace Selective\XmlDSig;

use DOMDocument;
use Selective\XmlDSig\Exception\XmlSignerException;

/**
 * Sign XML Documents with Digital Signatures (XMLDSIG).
 */
final class XmlSigner
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

    /**
     * @var int
     */
    private $sslAlgorithm;

    /**
     * @var string
     */
    private $algorithmName;

    /**
     * @var string
     */
    private $signatureAlgorithmUrl;

    /**
     * @var string
     */
    private $digestAlgorithmUrl;

    /**
     * @var resource|false
     */
    private $privateKeyId;

    /**
     * @var string
     */
    private $referenceUri = '';

    /**
     * Read and load the pfx file.
     *
     * @param string $filename PFX filename
     * @param string $password PFX password
     *
     * @throws XmlSignerException
     *
     * @return bool Success
     */
    public function loadPfx(string $filename, string $password): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignerException(sprintf('File not found: %s', $filename));
        }

        $certStore = file_get_contents($filename);

        if (!$certStore) {
            throw new XmlSignerException(sprintf('File could not be read: %s', $filename));
        }

        $status = openssl_pkcs12_read($certStore, $certInfo, $password);

        if (!$status) {
            throw new XmlSignerException('Invalid PFX password');
        }

        // Read the private key
        $this->privateKeyId = openssl_pkey_get_private((string)$certInfo['pkey']);

        if (!$this->privateKeyId) {
            throw new XmlSignerException('Invalid private key');
        }

        return true;
    }

    /**
     * Sign an XML file and save the signature in a new file.
     * This method does not save the public key within the XML file.
     *
     * @param string $filename Input file
     * @param string $outputFilename Output file
     * @param string $algorithm For example: sha1, sha224, sha256, sha384, sha512
     *
     * @throws XmlSignerException
     *
     * @return bool Success
     */
    public function signXmlFile(string $filename, string $outputFilename, string $algorithm): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignerException(sprintf('File not found: %s', $filename));
        }

        if (!$this->privateKeyId) {
            throw new XmlSignerException('No private key provided');
        }

        $this->setAlgorithm($algorithm);

        // Read the xml file content
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = false;
        $xml->formatOutput = true;
        $xml->load($filename);
        $data = $xml->saveXML();

        // Compute signature with SHA-512
        $status = openssl_sign($data, $signature, $this->privateKeyId, $this->sslAlgorithm);

        if (!$status) {
            throw new XmlSignerException('Computing of the signature failed');
        }

        // Encode signature
        $signatureValue = base64_encode($signature);

        // Calculate and encode digest value
        $digestValue = base64_encode(hash($this->algorithmName, $data, true));

        $xml = $this->createSignedXml($data, $digestValue, $signatureValue);

        file_put_contents($outputFilename, $xml->saveXML());

        return true;
    }

    /**
     * Set reference URI.
     *
     * @param string $referenceUri The reference URI
     *
     * @return void
     */
    public function setReferenceUri(string $referenceUri)
    {
        $this->referenceUri = $referenceUri;
    }

    /**
     * Create the XML representation of the signature.
     *
     * @param string $data The xml content
     * @param string $digestValue The digest value
     * @param string $signatureValue The signature
     *
     * @throws XmlSignerException
     *
     * @return DOMDocument The DOM document
     */
    private function createSignedXml(string $data, string $digestValue, string $signatureValue): DOMDocument
    {
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = false;
        $xml->formatOutput = true;
        $isValid = $xml->loadXML($data);

        if (!$isValid || !$xml->documentElement) {
            throw new XmlSignerException('Invalid XML content');
        }

        $signatureElement = $xml->createElement('Signature');
        $signatureElement->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        $signedInfoElement = $xml->createElement('SignedInfo');
        $signatureElement->appendChild($signedInfoElement);

        $canonicalizationMethodElement = $xml->createElement('CanonicalizationMethod');
        $canonicalizationMethodElement->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $signedInfoElement->appendChild($canonicalizationMethodElement);

        $signatureMethodElement = $xml->createElement('SignatureMethod');
        $signatureMethodElement->setAttribute('Algorithm', $this->signatureAlgorithmUrl);
        $signedInfoElement->appendChild($signatureMethodElement);

        $referenceElement = $xml->createElement('Reference');
        $referenceElement->setAttribute('URI', $this->referenceUri);
        $signedInfoElement->appendChild($referenceElement);

        $transformsElement = $xml->createElement('Transforms');
        $referenceElement->appendChild($transformsElement);

        $transformElement = $xml->createElement('Transform');
        $transformElement->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $transformsElement->appendChild($transformElement);

        $digestMethodElement = $xml->createElement('DigestMethod');
        $digestMethodElement->setAttribute('Algorithm', $this->digestAlgorithmUrl);
        $referenceElement->appendChild($digestMethodElement);

        $digestValueElement = $xml->createElement('DigestValue', $digestValue);
        $referenceElement->appendChild($digestValueElement);

        $signatureValueElement = $xml->createElement('SignatureValue', $signatureValue);
        $signatureElement->appendChild($signatureValueElement);

        // Append the element to the XML document.
        // We insert the new element as root (child of the document)
        $xml->documentElement->appendChild($signatureElement);

        return $xml;
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

    /**
     * Destructor.
     */
    public function __destruct()
    {
        // Free the key from memory
        if ($this->privateKeyId) {
            openssl_free_key($this->privateKeyId);
        }
    }
}
