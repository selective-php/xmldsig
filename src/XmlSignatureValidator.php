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
    const SHA1_URL = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    const SHA224_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    const SHA256_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SHA384_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    const SHA512_URL = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    private $publicKeyId;

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
    public function loadPfx(string $filename, string $password): bool
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
            throw new XmlSignatureValidatorException('Invalid PFX pasword');
        }

        $this->publicKeyId = openssl_get_publickey($certInfo['cert']);

        if (!$this->publicKeyId) {
            throw new XmlSignatureValidatorException('Invalid public key');
        }

        return true;
    }

    /**
     * Sign an XML file and save the signature in a new file.
     * This method does not save the public key within the XML file.
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
        $xml->preserveWhiteSpace = false;
        $xml->formatOutput = true;
        $isValid = $xml->loadXML($xmlContent);

        if (!$isValid || !$xml->documentElement) {
            throw new XmlSignatureValidatorException('Invalid XML content');
        }

        $digestAlgorithm = $this->getDigestAlgorithm($xml);
        $signatureValue = $this->getSignatureValue($xml);
        $data = $this->getXmlContent($xml);

        $status = openssl_verify($data, $signatureValue, $this->publicKeyId, $digestAlgorithm);

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

    /**
     * Detect digest algorithm.
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

        // Find the "Signature" node and create a new
        $signatureNodes = $xpath->query('//xmlns:Signature/xmlns:SignatureValue');

        // Throw an exception if no signature was found.
        if ($signatureNodes->length < 1) {
            throw new XmlSignatureValidatorException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureNodes->length > 1) {
            throw new XmlSignatureValidatorException('Verification failed: More that one signature was found for the document.');
        }

        $domNode = $signatureNodes->item(0);
        if (!$domNode) {
            throw new XmlSignatureValidatorException('Verification failed: No Signature item was found in the document.');
        }

        $result = (string)base64_decode($domNode->nodeValue);

        return $result;
    }

    /**
     * Get the real xml content (without the signature).
     *
     * @param DOMDocument $xml The xml document
     *
     * @return string The xml content
     */
    private function getXmlContent(DOMDocument $xml): string
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        if (!$xml->documentElement) {
            throw new XmlSignatureValidatorException('Invalid XML content');
        }

        $signatureNodes = $xpath->query('//xmlns:Signature');
        foreach ($signatureNodes as $signatureNode) {
            $xml->documentElement->removeChild($signatureNode);
        }

        $content = $xml->saveXML();

        if (!is_string($content)) {
            throw new XmlSignatureValidatorException('The XML content is not readable');
        }

        return $content;
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
        if ($signatureMethodNodes->length < 1) {
            throw new XmlSignatureValidatorException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureMethodNodes->length > 1) {
            throw new XmlSignatureValidatorException('Verification failed: More that one signature was found for the document.');
        }

        /** @var DOMElement $element */
        $element = $signatureMethodNodes->item(0);
        if (!$element instanceof DOMElement) {
            throw new XmlSignatureValidatorException('Verification failed: Signature algorithm was found for the document.');
        }

        $algorithm = $element->getAttribute('Algorithm');

        switch ($algorithm) {
            case self::SHA1_URL:
                return OPENSSL_ALGO_SHA1;
                break;
            case self::SHA224_URL:
                return OPENSSL_ALGO_SHA224;
                break;
            case self::SHA256_URL:
                return OPENSSL_ALGO_SHA256;
                break;
            case self::SHA384_URL:
                return OPENSSL_ALGO_SHA384;
                break;
            case self::SHA512_URL:
                return OPENSSL_ALGO_SHA512;
                break;
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
