<?php

namespace Selective\XmlDSig;

use DOMDocument;
use DOMElement;
use DOMXPath;
use OpenSSLCertificate;
use Selective\XmlDSig\Exception\XmlSignerException;
use UnexpectedValueException;

/**
 * Sign XML Documents with Digital Signatures (XMLDSIG).
 */
final class XmlSigner
{
    private string $referenceUri = '';

    private XmlReader $xmlReader;

    private CryptoSignerInterface $cryptoSigner;

    public function __construct(CryptoSignerInterface $cryptoSigner)
    {
        $this->xmlReader = new XmlReader();
        $this->cryptoSigner = $cryptoSigner;
    }

    /**
     * Sign an XML file and save the signature in a new file.
     * This method does not save the public key within the XML file.
     *
     * @param string $data The XML content to sign
     *
     * @throws XmlSignerException
     *
     * @return string The signed XML content
     */
    public function signXml(string $data): string
    {
        // Read the xml file content
        $xml = new DOMDocument();

        // Whitespaces must be preserved
        $xml->preserveWhiteSpace = true;
        $xml->formatOutput = false;

        $xml->loadXML($data);

        // Canonicalize the content, exclusive and without comments
        if (!$xml->documentElement) {
            throw new XmlSignerException('Undefined document element');
        }

        return $this->signDocument($xml);
    }

    /**
     * Sign DOM document.
     *
     * @param DOMDocument $document The document
     * @param DOMElement|null $element The element of the document to sign
     *
     * @return string The signed XML as string
     */
    public function signDocument(DOMDocument $document, DOMElement $element = null): string
    {
        $element = $element ?? $document->documentElement;

        if ($element === null) {
            throw new XmlSignerException('Invalid XML document element');
        }

        $canonicalData = $element->C14N(true, false);

        // Calculate and encode digest value
        $digestValue = $this->cryptoSigner->computeDigest($canonicalData);

        $digestValue = base64_encode($digestValue);
        $this->appendSignature($document, $digestValue);

        $result = $document->saveXML();

        if ($result === false) {
            throw new XmlSignerException('Signing failed. Invalid XML.');
        }

        return $result;
    }

    /**
     * Create the XML representation of the signature.
     *
     * @param DOMDocument $xml The xml document
     * @param string $digestValue The digest value
     *
     * @throws UnexpectedValueException
     *
     * @return void The DOM document
     */
    private function appendSignature(DOMDocument $xml, string $digestValue): void
    {
        $signatureElement = $xml->createElement('Signature');
        $signatureElement->setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#');

        // Append the element to the XML document.
        // We insert the new element as root (child of the document)

        if (!$xml->documentElement) {
            throw new UnexpectedValueException('Undefined document element');
        }

        $xml->documentElement->appendChild($signatureElement);

        $signedInfoElement = $xml->createElement('SignedInfo');
        $signatureElement->appendChild($signedInfoElement);

        $canonicalizationMethodElement = $xml->createElement('CanonicalizationMethod');
        $canonicalizationMethodElement->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $signedInfoElement->appendChild($canonicalizationMethodElement);

        $signatureMethodElement = $xml->createElement('SignatureMethod');
        $signatureMethodElement->setAttribute(
            'Algorithm',
            $this->cryptoSigner->getAlgorithm()->getSignatureAlgorithmUrl()
        );
        $signedInfoElement->appendChild($signatureMethodElement);

        $referenceElement = $xml->createElement('Reference');
        $referenceElement->setAttribute('URI', $this->referenceUri);
        $signedInfoElement->appendChild($referenceElement);

        $transformsElement = $xml->createElement('Transforms');
        $referenceElement->appendChild($transformsElement);

        // Enveloped: the <Signature> node is inside the XML we want to sign
        $transformElement = $xml->createElement('Transform');
        $transformElement->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $transformsElement->appendChild($transformElement);

        $digestMethodElement = $xml->createElement('DigestMethod');
        $digestMethodElement->setAttribute('Algorithm', $this->cryptoSigner->getAlgorithm()->getDigestAlgorithmUrl());
        $referenceElement->appendChild($digestMethodElement);

        $digestValueElement = $xml->createElement('DigestValue', $digestValue);
        $referenceElement->appendChild($digestValueElement);

        $signatureValueElement = $xml->createElement('SignatureValue', '');
        $signatureElement->appendChild($signatureValueElement);

        $keyInfoElement = $xml->createElement('KeyInfo');
        $signatureElement->appendChild($keyInfoElement);

        $keyValueElement = $xml->createElement('KeyValue');
        $keyInfoElement->appendChild($keyValueElement);

        $rsaKeyValueElement = $xml->createElement('RSAKeyValue');
        $keyValueElement->appendChild($rsaKeyValueElement);

        $modulus = $this->cryptoSigner->getPrivateKeyStore()->getModulus();
        if ($modulus) {
            $modulusElement = $xml->createElement('Modulus', $modulus);
            $rsaKeyValueElement->appendChild($modulusElement);
        }

        $publicExponent = $this->cryptoSigner->getPrivateKeyStore()->getPublicExponent();
        if ($publicExponent) {
            $exponentElement = $xml->createElement('Exponent', $publicExponent);
            $rsaKeyValueElement->appendChild($exponentElement);
        }

        // If certificates are loaded attach them to the KeyInfo element
        $certificates = $this->cryptoSigner->getPrivateKeyStore()->getCertificates();
        if ($certificates) {
            $this->appendX509Certificates($xml, $keyInfoElement, $certificates);
        }

        // http://www.soapclient.com/XMLCanon.html
        $c14nSignedInfo = $signedInfoElement->C14N(true, false);

        $signatureValue = $this->cryptoSigner->computeSignature($c14nSignedInfo);

        $xpath = new DOMXpath($xml);
        $signatureValueElement = $this->xmlReader->queryDomNode($xpath, '//SignatureValue', $signatureElement);
        $signatureValueElement->nodeValue = base64_encode($signatureValue);
    }

    /**
     * Create and append an X509Data element containing certificates in base64 format.
     *
     * @param DOMDocument $xml
     * @param DOMElement $keyInfoElement
     * @param OpenSSLCertificate[] $certificates
     *
     * @return void
     */
    private function appendX509Certificates(DOMDocument $xml, DOMElement $keyInfoElement, array $certificates): void
    {
        $x509DataElement = $xml->createElement('X509Data');
        $keyInfoElement->appendChild($x509DataElement);

        $x509Reader = new X509Reader();
        foreach ($certificates as $certificateId) {
            $certificate = $x509Reader->toRawBase64($certificateId);

            $x509CertificateElement = $xml->createElement('X509Certificate', $certificate);
            $x509DataElement->appendChild($x509CertificateElement);
        }
    }

    /**
     * Set reference URI.
     *
     * @param string $referenceUri The reference URI
     *
     * @return void
     */
    public function setReferenceUri(string $referenceUri): void
    {
        $this->referenceUri = $referenceUri;
    }
}
