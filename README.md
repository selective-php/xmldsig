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

## Requirements

* PHP 7.2+ or 8.0+
* The openssl extension
* A X.509 digital certificate

## Installation

```
composer require selective/xmldsig
```

## Usage

### Sign XML Document with Digital Signature

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

```php
use Selective\XmlDSig\DigestAlgorithmType;
use Selective\XmlDSig\XmlSigner;

$xmlSigner = new XmlSigner();

// Load a pfx file
$xmlSigner->loadPfxFile('filename.pfx', 'password');

// or load pfx from a string
$xmlSigner->loadPfx('pfx content', 'password');

// or load a PEM file
$xmlSigner->loadPrivateKeyFile('filename.pem', 'password');

// or load a PEM private key from a string
$xmlSigner->loadPrivateKey('private key content', 'password');

// Optional: Set reference URI
$xmlSigner->setReferenceUri('');

// Create a signed file
$xmlSigner->signXmlFile('example.xml', 'signed-example.xml', DigestAlgorithmType::SHA512);
```

Output file: signed-example.xml

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

### Verify the Digital Signatures of XML Documents

```php
use Selective\XmlDSig\XmlSignatureValidator;

// Create a validator instance
$signatureValidator = new XmlSignatureValidator();

// Create a validator instance that does not remove redundant white spaces
$signatureValidator = new XmlSignatureValidator(false);
```

```php
// Load a PFX file
$signatureValidator->loadPfxFile('filename.pfx', 'password');

// or load just a public key file from a string
$signatureValidator->loadPfx('public key content', 'password');

// or load a public key file (without password)
$signatureValidator->loadPublicKeyFile('cacert.pem');

// or load the public key from a string (without password)
$signatureValidator->loadPublicKey('public key content');
```

```php
// Verify a XML file
$isValid = $signatureValidator->verifyXmlFile('signed-example.xml');

// or verify XML from a string
$isValid = $signatureValidator->verifyXml('xml content');

if ($isValid === true) {
    echo 'The XML signature is valid.';
} else {
    echo 'The XML signature is not valid.';
}
```

### Online XML Digital Signature Verifier

Try these excellent online tools to verify XML signatures:

* https://www.aleksey.com/xmlsec/xmldsig-verifier.html
* https://tools.chilkat.io/xmlDsigVerify.cshtml

## Similar libraries

* https://github.com/robrichards/xmlseclibs

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
