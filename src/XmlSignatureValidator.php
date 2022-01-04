<?php

namespace Selective\XmlDSig;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use OpenSSLAsymmetricKey;
use Selective\XmlDSig\Exception\XmlSignatureValidatorException;

/**
 * Verify the Digital Signatures of XML Documents.
 */
final class XmlSignatureValidator
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
     * @var XmlReader
     */
    private XmlReader $xmlReader;

    /**
     * @var bool
     */
    private bool $preserveWhiteSpace = true;

    /**
     * The constructor.
     *
     * @param bool $preserveWhiteSpace To remove redundant white spaces
     */
    public function __construct(bool $preserveWhiteSpace = true)
    {
        $this->xmlReader = new XmlReader();
        $this->preserveWhiteSpace = $preserveWhiteSpace;
    }

    /**
     * Read and load the pfx file.
     *
     * @param string $filename PFX filename
     * @param string $password PFX password
     *
     * @throws XmlSignatureValidatorException
     *
     * @return void
     */
    public function loadPfxFile(string $filename, string $password)
    {
        if (!file_exists($filename)) {
            throw new XmlSignatureValidatorException(sprintf('File not found: %s', $filename));
        }

        $pkcs12 = file_get_contents($filename);

        if (!$pkcs12) {
            throw new XmlSignatureValidatorException(sprintf('File could not be read: %s', $filename));
        }

        $this->loadPfx($pkcs12, $password);
    }

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
     * Read and load the public key file.
     *
     * @param string $filename The public key file
     *
     * @throws XmlSignatureValidatorException
     *
     * @return void
     */
    public function loadPublicKeyFile(string $filename): void
    {
        if (!file_exists($filename)) {
            throw new XmlSignatureValidatorException(sprintf('File not found: %s', $filename));
        }

        $publicKey = file_get_contents($filename);

        if (!$publicKey) {
            throw new XmlSignatureValidatorException(sprintf('File could not be read: %s', $filename));
        }

        $this->loadPublicKey($publicKey);
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
     * Sign an XML file and save the signature in a new file.
     * This method does not save the public key within the XML file.
     *
     * https://www.xml.com/pub/a/2001/08/08/xmldsig.html#verify
     *
     * @param string $filename Input file
     *
     * @throws XmlSignatureValidatorException
     *
     * @return bool Success
     */
    public function verifyXmlFile(string $filename): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignatureValidatorException(sprintf('File not found: %s', $filename));
        }

        if (!$this->publicKeyId) {
            throw new XmlSignatureValidatorException('No public key provided');
        }

        $xmlContent = file_get_contents($filename);

        if (!$xmlContent) {
            throw new XmlSignatureValidatorException(sprintf('File could not be read: %s', $filename));
        }

        return $this->verifyXml($xmlContent);
    }

    /**
     * Verify an XML string.
     *
     * https://www.xml.com/pub/a/2001/08/08/xmldsig.html#verify
     *
     * @param string $xmlContent The xml content
     *
     * @throws XmlSignatureValidatorException
     *
     * @return bool Success
     */
    public function verifyXml(string $xmlContent): bool
    {
        if (!$this->publicKeyId) {
            throw new XmlSignatureValidatorException('No public key provided');
        }

        // Read the xml file content
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = $this->preserveWhiteSpace;
        $xml->formatOutput = false;
        $isValid = $xml->loadXML($xmlContent);

        if (!$isValid || !$xml->documentElement) {
            throw new XmlSignatureValidatorException('Invalid XML content');
        }

        $digestAlgorithm = $this->getDigestAlgorithm($xml);
        $signatureValue = $this->getSignatureValue($xml);
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        /** @var DOMNodeList $nodes */
        $nodes = $xpath->evaluate('//xmlns:Signature/xmlns:SignedInfo');

        /** @var DOMElement $signedInfoNode */
        foreach ($nodes as $signedInfoNode) {
            // Remove SignatureValue value
            $signatureValueElement = $this->xmlReader->queryDomNode($xpath, '//xmlns:SignatureValue', $signedInfoNode);
            $signatureValueElement->nodeValue = '';

            $canonicalData = $signedInfoNode->C14N(true, false);

            $xml2 = new DOMDocument();
            $xml2->preserveWhiteSpace = true;
            $xml2->formatOutput = true;
            $xml2->loadXML($canonicalData);
            $canonicalData = $xml2->C14N(true, false);

            $status = openssl_verify($canonicalData, $signatureValue, $this->publicKeyId, $digestAlgorithm);

            if ($status !== 1) {
                // The XML signature is not valid
                return false;
            }
        }

        return $this->checkDigest($xml, $xpath, $digestAlgorithm);
    }

    /**
     * Check digest value.
     *
     * @param DOMDocument $xml The xml document
     * @param DOMXPath $xpath The xpath
     * @param int $digestAlgorithm The digest algorithm
     *
     * @return bool The status
     */
    private function checkDigest(DOMDocument $xml, DOMXPath $xpath, int $digestAlgorithm): bool
    {
        $digestValue = $this->getDigestValue($xml);

        // Remove signature elements
        /** @var DOMElement $signatureNode */
        foreach ($xpath->query('//xmlns:Signature') ?: [] as $signatureNode) {
            if (!$signatureNode->parentNode) {
                continue;
            }

            $signatureNode->parentNode->removeChild($signatureNode);
        }

        // Canonicalize the content, exclusive and without comments
        $canonicalData = $xml->C14N(true, false);

        $opensslDigestAlgorithm = $this->getOpenSslDigestAlgo($digestAlgorithm);
        $digestValue2 = openssl_digest($canonicalData, $opensslDigestAlgorithm, true);
        if ($digestValue2 === false) {
            throw new XmlSignatureValidatorException('Invalid digest value');
        }

        return hash_equals($digestValue, $digestValue2);
    }

    /**
     * Detect digest algorithm.
     *
     * @param DOMDocument $xml The xml document
     *
     * @throws XmlSignatureValidatorException
     *
     * @return int The algorithm code
     */
    private function getDigestAlgorithm(DOMDocument $xml): int
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');

        $signatureMethodNodes = $xpath->query('//xmlns:Signature/xmlns:SignedInfo/xmlns:SignatureMethod');

        // Throw an exception if no signature was found.
        if (!$signatureMethodNodes || $signatureMethodNodes->length < 1) {
            throw new XmlSignatureValidatorException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureMethodNodes->length > 1) {
            throw new XmlSignatureValidatorException(
                'Verification failed: More that one signature was found for the document.'
            );
        }

        /** @var DOMElement $element */
        $element = $signatureMethodNodes->item(0);
        if (!$element instanceof DOMElement) {
            throw new XmlSignatureValidatorException(
                'Verification failed: Signature algorithm was found for the document.'
            );
        }

        $algorithm = $element->getAttribute('Algorithm');

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
     * @param int $algo The algo
     *
     * @return string The name of the OpenSSL algorithm
     */
    private function getOpenSslDigestAlgo(int $algo): string
    {
        switch ($algo) {
            case OPENSSL_ALGO_SHA1:
                return 'sha1';
            case OPENSSL_ALGO_SHA224:
                return 'sha224';
            case OPENSSL_ALGO_SHA256:
                return 'sha256';
            case OPENSSL_ALGO_SHA384:
                return 'sha384';
            case OPENSSL_ALGO_SHA512:
                return 'sha512';
            default:
                throw new XmlSignatureValidatorException(
                    "Cannot verify: Unsupported Algorithm <$algo>"
                );
        }
    }

    /**
     * Get signature value.
     *
     * @param DOMDocument $xml The xml document
     *
     * @throws XmlSignatureValidatorException
     *
     * @return string The signature value
     */
    private function getSignatureValue(DOMDocument $xml): string
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        // Find the SignatureValue node
        $signatureNodes = $xpath->query('//xmlns:Signature/xmlns:SignatureValue');

        // Throw an exception if no signature was found.
        if (!$signatureNodes || $signatureNodes->length < 1) {
            throw new XmlSignatureValidatorException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureNodes->length > 1) {
            throw new XmlSignatureValidatorException(
                'Verification failed: More that one signature was found for the document.'
            );
        }

        $domNode = $signatureNodes->item(0);
        if (!$domNode) {
            throw new XmlSignatureValidatorException(
                'Verification failed: No Signature item was found in the document.'
            );
        }

        $result = base64_decode((string)$domNode->nodeValue, true);

        if ($result === false) {
            throw new XmlSignatureValidatorException('Verification failed: Invalid base64 data.');
        }

        return (string)$result;
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

    /**
     * Get the digest value.
     *
     * @param DOMDocument $xml The xml document
     *
     * @throws XmlSignatureValidatorException
     *
     * @return string The signature value
     */
    private function getDigestValue(DOMDocument $xml): string
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        // Find the DigestValue node
        $signatureNodes = $xpath->query('//xmlns:Signature/xmlns:SignedInfo/xmlns:Reference/xmlns:DigestValue');

        // Throw an exception if no signature was found.
        if (!$signatureNodes || $signatureNodes->length < 1) {
            throw new XmlSignatureValidatorException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureNodes->length > 1) {
            throw new XmlSignatureValidatorException(
                'Verification failed: More that one signature was found for the document.'
            );
        }

        $domNode = $signatureNodes->item(0);
        if (!$domNode) {
            throw new XmlSignatureValidatorException(
                'Verification failed: No Signature item was found in the document.'
            );
        }

        $result = base64_decode((string)$domNode->nodeValue, true);

        if ($result === false) {
            throw new XmlSignatureValidatorException('Verification failed: Invalid base64 data.');
        }

        return $result;
    }
}
