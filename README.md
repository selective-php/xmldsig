# XMLDSIG for PHP

[![Latest Version on Packagist](https://img.shields.io/github/release/selective-php/xmldsig.svg)](https://packagist.org/packages/selective/xmldsig)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)
[![Build Status](https://github.com/selective-php/xmldsig/workflows/build/badge.svg)](https://github.com/selective-php/xmldsig/actions)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/selective-php/xmldsig.svg)](https://scrutinizer-ci.com/g/selective-php/xmldsig/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/quality/g/selective-php/xmldsig.svg)](https://scrutinizer-ci.com/g/selective-php/xmldsig/?branch=master)
[![Total Downloads](https://img.shields.io/packagist/dt/selective/xmldsig.svg)](https://packagist.org/packages/selective/xmldsig/stats)

## Features

* Sign XML Documents with Digital Signatures ([XMLDSIG](https://www.w3.org/TR/xmldsig-core/))
* Verify the Digital Signatures of XML Documents
* ECDSA (SHA256) signature

## Requirements

* PHP 8.0+
* The openssl extension
* A X.509 digital certificate

## Installation

```
composer require selective/xmldsig
```

## Usage

### Signing an XML Document with a digital signature

Input file: example.xml

```xml
<?xml version="1.0"?>
<root>
    <creditcard>
        <number>19834209</number>
        <expiry>02/02/2025</expiry>
    </creditcard>
</root>
```

Load and add the private key to the `PrivateKeyStore`:

```php
use Selective\XmlDSig\PrivateKeyStore;
// ...

$privateKeyStore = new PrivateKeyStore();

// load a private key from a string
$privateKeyStore->loadFromPem('private key content', 'password');

// or load a private key from a PEM file
$privateKeyStore->loadFromPem(file_get_contents('filename.pem'), 'password');

// load pfx PKCS#12 certificate from a string
$privateKeyStore->loadFromPkcs12('pfx content', 'password');

// or load PKCS#12 certificate from a file
$privateKeyStore->loadFromPkcs12(file_get_contents('filename.p12'), 'password');
```

Define the digest method: sha1, sha224, sha256, sha384, sha512

```php
use Selective\XmlDSig\Algorithm;

$algorithm = new Algorithm(Algorithm::METHOD_SHA1);
```

Create a `CryptoSigner` instance:

```php
use Selective\XmlDSig\CryptoSigner;

$cryptoSigner = new CryptoSigner($privateKeyStore, $algorithm);
```

Signing:

```php
use Selective\XmlDSig\XmlSigner;

// Create a XmlSigner and pass the crypto signer
$xmlSigner = new XmlSigner($cryptoSigner);

// Optional: Set reference URI
$xmlSigner->setReferenceUri('');

// Create a signed XML string
$signedXml = $xmlSigner->signXml('<?xml ...');

// or sign an XML file
$signedXml = $xmlSigner->signXml(file_get_contents($filename));

// or sign an DOMDocument
$xml = new DOMDocument();
$xml->preserveWhiteSpace = true;
$xml->formatOutput = false;
$xml->loadXML($data);

$signedXml = $xmlSigner->signDocument($xml);
```

Output:

```xml
<?xml version="1.0"?>
<root>
    <creditcard>
        <number>19834209</number>
        <expiry>02/02/2025</expiry>
    </creditcard>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
            <Reference URI="">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
                <DigestValue>Base64EncodedValue==</DigestValue>
            </Reference>
        </SignedInfo>
        <SignatureValue>AnotherBase64EncodedValue===</SignatureValue>
    </Signature>
</root>
```

#### Signing only specific part of an XML document

Example:

```php
use Selective\XmlDSig\Algorithm;
use Selective\XmlDSig\CryptoSigner;
use Selective\XmlDSig\PrivateKeyStore;
use Selective\XmlDSig\XmlSigner;
use DOMDocument;
use DOMXPath;
// ...

// Load the XML content you want to sign
$xml = new DOMDocument();
$xml->preserveWhiteSpace = true;
$xml->formatOutput = false;
$xml->loadXML($data);

// Create a XPATH query to select the element you want to sign 
$xpath = new DOMXPath($xml);

// Change this query according to your requirements
$referenceUri = '#1';
$elementToSign = $xpath->query( '//*[@Id="'. $referenceUri .'"]' )->item(0);

// Add private key
$privateKeyStore = new PrivateKeyStore();
$privateKeyStore->loadPrivateKey('private key content', 'password');

$cryptoSigner = new CryptoSigner($privateKeyStore, new Algorithm(Algorithm::METHOD_SHA1));

// Sign the element
$xmlSigner = new XmlSigner($cryptoSigner);
$signedXml = $xmlSigner->signDocument($xml, $elementToSign);
```

### Signing an XML Document with ECDSA SHA256

The Elliptic Curve Digital Signature Algorithm (ECDSA) is the elliptic curve
analogue of the Digital Signature Algorithm (DSA).

It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates
to speed up the ECDSA on pure PHP.

**Requirements**

* The [GMP extension](https://www.php.net/manual/en/book.gmp.php) must be installed and enabled.

To install the package with Composer, run:

```
composer require starkbank/ecdsa
```

**Example**

Note, you can sign an XML **signature** using ECDSA.
It's not supported to use ECDSA for the **digest**.

You can find a fully working example in the [XmlEcdsaTest](tests/XmlEcdsaTest.php) test class.

### Verify the Digital Signatures of XML Documents

Load the public key(s):

```php
use Selective\XmlDSig\PublicKeyStore;
use Selective\XmlDSig\CryptoVerifier;
use Selective\XmlDSig\XmlSignatureVerifier;

$publicKeyStore = new PublicKeyStore();

// load a public key from a string
$publicKeyStore->loadFromPem('public key content');

// or load a public key file
$publicKeyStore->loadFromPem(file_get_contents('cacert.pem'));

// or load a public key from a PKCS#12 certificate string
$publicKeyStore->loadFromPkcs12('public key content', 'password');

// or load a public key from a PKCS#12 certificate file
$publicKeyStore->loadFromPkcs12(file_get_contents('filename.pfx'), 'password');

// Load public keys from DOMDocument X509Certificate nodes
$publicKeyStore->loadFromDocument($xml);

// Load public key from existing OpenSSLCertificate resource
$publicKeyStore->loadFromCertificate($certificate);
```

Create a `CryptoVerifier` instance:

```php
use Selective\XmlDSig\CryptoVerifier;

$cryptoVerifier = new CryptoVerifier($publicKeyStore);
```

Verifying:

```php
use Selective\XmlDSig\XmlSignatureVerifier;

// Create a verifier instance and pass the crypto decoder
$xmlSignatureVerifier = new XmlSignatureVerifier($cryptoVerifier);

// Verify XML from a string
$isValid = $xmlSignatureVerifier->verifyXml($signedXml);

// or verify a XML file
$isValid = $xmlSignatureVerifier->verifyXml(file_get_contents('signed.xml'));

// or verifying an DOMDocument instance
$xml = new DOMDocument();
$xml->preserveWhiteSpace = true;
$xml->formatOutput = false;
$xml->loadXML($data);

$isValid = $xmlSignatureVerifier->verifyDocument($xml);

if ($isValid === true) {
    echo 'The XML signature is valid.';
} else {
    echo 'The XML signature is not valid.';
}
```

### Online XML Digital Signature Verifier

Try these excellent online tools to verify XML signatures:

* <https://www.aleksey.com/xmlsec/xmldsig-verifier.html>
* <https://tools.chilkat.io/xmlDsigVerify.cshtml>

## Similar libraries

* <https://github.com/robrichards/xmlseclibs>

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
