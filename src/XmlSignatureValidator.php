<?php

namespace Selective\XmlDSig;

use DOMDocument;
use DOMElement;
use DOMXPath;
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
     * @var resource|false
     */
    private $publicKeyId;

    /**
     * @var XmlReader
     */
    private $xmlReader;

    /**
     * The constructor.
     */
    public function __construct()
    {
        $this->xmlReader = new XmlReader();
    }

    /**
     * Read and load the pfx file.
     *
     * @param string $filename PFX filename
     * @param string $password PFX password
     *
     * @throws XmlSignatureValidatorException
     *
     * @return bool Success
     */
    public function loadPfxFile(string $filename, string $password): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignatureValidatorException(sprintf('File not found: %s', $filename));
        }

        $certStore = file_get_contents($filename);

        if (!$certStore) {
            throw new XmlSignatureValidatorException(sprintf('File could not be read: %s', $filename));
        }

        $status = openssl_pkcs12_read($certStore, $certInfo, $password);

        if (!$status) {
            throw new XmlSignatureValidatorException('Invalid PFX password');
        }

        $this->publicKeyId = openssl_get_publickey($certInfo['cert']);

        if (!$this->publicKeyId) {
            throw new XmlSignatureValidatorException('Invalid public key');
        }

        return true;
    }

    /**
     * Read and load the public key file.
     *
     * @param string $filename The public key file
     *
     * @throws XmlSignatureValidatorException
     *
     * @return bool Success
     */
    public function loadPublicKeyFile(string $filename): bool
    {
        if (!file_exists($filename)) {
            throw new XmlSignatureValidatorException(sprintf('File not found: %s', $filename));
        }

        $certStore = file_get_contents($filename);

        if (!$certStore) {
            throw new XmlSignatureValidatorException(sprintf('File could not be read: %s', $filename));
        }

        $this->publicKeyId = openssl_get_publickey($certStore);

        if (!$this->publicKeyId) {
            throw new XmlSignatureValidatorException('Invalid public key');
        }

        return true;
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

        // Read the xml file content
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = true;
        $xml->formatOutput = false;
        $isValid = $xml->loadXML($xmlContent);

        if (!$isValid || !$xml->documentElement) {
            throw new XmlSignatureValidatorException('Invalid XML content');
        }

        $digestAlgorithm = $this->getDigestAlgorithm($xml);
        $signatureValue = $this->getSignatureValue($xml);
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        /** @var DOMElement $signedInfoNode */
        foreach ($xpath->evaluate('//xmlns:Signature/xmlns:SignedInfo') as $signedInfoNode) {
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

            if ($status === 1) {
                // The XML signature is valid
                return true;
            }
            if ($status === 0) {
                // The XML signature is not valid
                return false;
            }

            throw new XmlSignatureValidatorException('Error checking signature');
        }

        // @todo check digest value
        //$digestValue = $this->getDigestValue($xml);
        //$signatureNodes = $xpath->query('//xmlns:Signature');

        // Canonicalize the content, exclusive and without comments
        //$canonicalData = $xml->documentElement->C14N(true, false);

        //foreach ($xpath->evaluate('//xmlns:Signature/xmlns:SignedInfo') as $signedInfoNode) {
        // $signedInfoNode->parentNode->removeChild($signedInfoNode);
        // }

        return false;
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

        $result = base64_decode($domNode->nodeValue, true);

        if ($result === false) {
            throw new XmlSignatureValidatorException('Verification failed: Invalid base64 data.');
        }

        return (string)$result;
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

        $result = base64_decode($domNode->nodeValue, true);

        if ($result === false) {
            throw new XmlSignatureValidatorException('Verification failed: Invalid base64 data.');
        }

        return (string)$result;
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
    protected function getDigestAlgorithm(DOMDocument $xml): int
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
     * Destructor.
     */
    public function __destruct()
    {
        // Free the key from memory
        if ($this->publicKeyId) {
            openssl_free_key($this->publicKeyId);
        }
    }
}
