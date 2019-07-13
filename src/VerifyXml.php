<?php

namespace Selective\XmlDSig;

use DOMDocument;
use DOMXPath;
use RuntimeException;

/**
 * Class.
 */
final class VerifyXml
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
     * @return bool Success
     */
    public function loadPfx(string $filename, string $password): bool
    {
        if (!file_exists($filename)) {
            throw new RuntimeException(sprintf('File not found: %s', $filename));
        }

        $certStore = file_get_contents($filename);
        $status = openssl_pkcs12_read($certStore, $certInfo, $password);

        if (!$status) {
            throw new RuntimeException('Invalid PFX pasword');
        }

        $this->publicKeyId = openssl_get_publickey($certInfo['cert']);

        if (!$this->publicKeyId) {
            throw new RuntimeException('Invalid public key');
        }

        return true;
    }

    /**
     * Sign an XML file and save the signature in a new file.
     * This method does not save the public key within the XML file.
     *
     * @param string $filename Input file
     *
     * @return bool Success
     */
    public function verifyXmlFile(string $filename): bool
    {
        if (!file_exists($filename)) {
            throw new RuntimeException(sprintf('File not found: %s', $filename));
        }

        if (!$this->publicKeyId) {
            throw new RuntimeException('No public key provided');
        }

        // Read the xml file content
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = false;
        $xml->formatOutput = true;
        $xml->loadXML(file_get_contents($filename));

        $digestAlgorithm = $this->getDigestAlgorithm($xml);
        $signatureValue = $this->getSignatureValue($xml);
        $data = $this->getXmlContent($xml);

        $status = openssl_verify($data, $signatureValue, $this->publicKeyId, $digestAlgorithm);

        if ($status === 1) {
            // The XML signature is valid
            return true;
        } elseif ($status === 0) {
            // The XML signature is not valid
            return false;
        } else {
            throw new RuntimeException('Error checking signature');
        }
    }

    /**
     * Detect digest algorithm.
     *
     * @param DOMDocument $xml
     *
     * @return string
     */
    protected function getSignatureValue(DOMDocument $xml): string
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        // Find the "Signature" node and create a new
        $signatureNodes = $xpath->query('//xmlns:Signature/xmlns:SignatureValue');

        // Throw an exception if no signature was found.
        if ($signatureNodes->length < 1) {
            throw new RuntimeException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureNodes->length > 1) {
            throw new RuntimeException('Verification failed: More that one signature was found for the document.');
        }

        $result = $signatureNodes->item(0)->nodeValue;
        $result = base64_decode($result);

        return $result;
    }

    /**
     * Get the real xml content (without the signature).
     *
     * @param DOMDocument $xml DOMDocument
     *
     * @return string Xml content
     */
    public function getXmlContent(DOMDocument $xml): string
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        $signatureNodes = $xpath->query('//xmlns:Signature');
        foreach ($signatureNodes as $signatureNode) {
            $xml->documentElement->removeChild($signatureNode);
        }

        $content = $xml->saveXML();

        if ($content === false) {
            throw new RuntimeException('The XML content is not readable');
        }

        return $content;
    }

    /**
     * Detect digest algorithm.
     *
     * @param DOMDocument $xml
     *
     * @return int
     */
    protected function getDigestAlgorithm(DOMDocument $xml): int
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');

        $signatureMethodNodes = $xpath->query('//xmlns:Signature/xmlns:SignedInfo/xmlns:SignatureMethod');

        // Throw an exception if no signature was found.
        if ($signatureMethodNodes->length < 1) {
            throw new RuntimeException('Verification failed: No Signature was found in the document.');
        }

        // We only support one signature for the entire XML document.
        // Throw an exception if more than one signature was found.
        if ($signatureMethodNodes->length > 1) {
            throw new RuntimeException('Verification failed: More that one signature was found for the document.');
        }

        $algorithm = $signatureMethodNodes->item(0)->getAttribute('Algorithm');

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
                throw new RuntimeException("Cannot verify: Unsupported Algorithm <$algorithm>");
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
