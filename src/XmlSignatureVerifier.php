<?php

namespace Selective\XmlDSig;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use Selective\XmlDSig\Exception\XmlSignatureValidatorException;

/**
 * Verify the Digital Signatures of XML Documents.
 */
final class XmlSignatureVerifier
{
    private CryptoVerifierInterface $cryptoVerifier;

    private XmlReader $xmlReader;

    private bool $preserveWhiteSpace;

    /**
     * The constructor.
     *
     * @param CryptoVerifierInterface $cryptoVerifier
     * @param bool $preserveWhiteSpace To remove redundant white spaces
     */
    public function __construct(CryptoVerifierInterface $cryptoVerifier, bool $preserveWhiteSpace = true)
    {
        $this->cryptoVerifier = $cryptoVerifier;
        $this->preserveWhiteSpace = $preserveWhiteSpace;
        $this->xmlReader = new XmlReader();
    }

    /**
     * Verify an XML string.
     *
     * https://www.xml.com/pub/a/2001/08/08/xmldsig.html#verify
     *
     * @param string $data The xml content
     *
     * @throws XmlSignatureValidatorException
     *
     * @return bool Success
     */
    public function verifyXml(string $data): bool
    {
        // Read the xml file content
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = $this->preserveWhiteSpace;
        $xml->formatOutput = false;
        $isValidSignature = $xml->loadXML($data);

        if (!$isValidSignature || !$xml->documentElement) {
            throw new XmlSignatureValidatorException('Invalid XML content');
        }

        return $this->verifyDocument($xml);
    }

    /**
     * Verify XML document.
     *
     * @param DOMDocument $xml The document
     *
     * @return bool The status
     */
    public function verifyDocument(DOMDocument $xml): bool
    {
        $signatureAlgorithm = $this->getDocumentAlgorithm($xml, '//xmlns:SignedInfo/xmlns:SignatureMethod');
        $digestAlgorithm = $this->getDocumentAlgorithm($xml, '//xmlns:DigestMethod');
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

            $isValidSignature = $this->cryptoVerifier->verify($canonicalData, $signatureValue, $signatureAlgorithm);

            if (!$isValidSignature) {
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
     * @param string $algorithm The digest algorithm url
     *
     * @return bool The status
     */
    private function checkDigest(DOMDocument $xml, DOMXPath $xpath, string $algorithm): bool
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

        $digestValue2 = $this->cryptoVerifier->computeDigest($canonicalData, $algorithm);

        return hash_equals($digestValue, $digestValue2);
    }

    /**
     * Detect digest algorithm.
     *
     * @param DOMDocument $xml The xml document
     * @param string $expression
     *
     * @throws XmlSignatureValidatorException
     *
     * @return string The algorithm url
     */
    private function getDocumentAlgorithm(DOMDocument $xml, string $expression): string
    {
        $xpath = new DOMXPath($xml);
        $xpath->registerNamespace('xmlns', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');

        $signatureMethodNodes = $xpath->query($expression);

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

        return $element->getAttribute('Algorithm');
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
