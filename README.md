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

* PHP 8.0+
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

Create the crypto encoder and load the private key:

```php
use Selective\XmlDSig\OpenSslCryptoEncoder;

// sha1, sha224, sha256, sha384, sha512
$algo = 'sha512';
$cryptoEncoder = new OpenSslCryptoEncoder($algo);

// load a private key from a string
$cryptoEncoder->loadPrivateKey('private key content', 'password');

// or load a private key from a PEM file
$cryptoEncoder->loadPrivateKey(file_get_contents('filename.pem'), 'password');

// load pfx (PKCS#12 certificate) from a string
$cryptoEncoder->loadPfx('pfx content', 'password');

// or load pfx (PKCS#12 certificate) from a file
$cryptoEncoder->loadPfx(file_get_contents('filename.p12'), 'password');
```

Signing a XML document:

```php
use Selective\XmlDSig\XmlSigner;

// Create the XMLDSIG signer and pass the crypto encoder
$xmlSigner = new XmlSigner($cryptoEncoder);

// Optional: Set reference URI
$xmlSigner->setReferenceUri('');

// Create a signed XML string
$signedXml = $xmlSigner->signXml('<?xml ...');
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

### Verify the Digital Signatures of XML Documents

```php
use Selective\XmlDSig\OpenSslCryptoDecoder;
use Selective\XmlDSig\XmlSignatureValidator;

// Create a crypto decoder instance
$cryptoDecoder = new OpenSslCryptoDecoder();

// load a public key from a string
$cryptoDecoder->loadPublicKey('public key content');

// or load a public key file
$cryptoDecoder->loadPublicKey(file_get_contents('cacert.pem'));

// or load a public key from a PKCS#12 certificate string
$cryptoDecoder->loadPfx('public key content', 'password');

// or load a public key from a PKCS#12 certificate file
$cryptoDecoder->loadPfx(file_get_contents('filename.pfx'), 'password');
```

```php
// Create a verifier instance and pass the crypto decoder
$signatureValidator = new XmlSignatureValidator($cryptoDecoder);

// or create a verifier instance that does not remove redundant white spaces
$signatureValidator = new XmlSignatureValidator($cryptoDecoder, false);
```

```php
// or verify XML from a string
$isValid = $signatureValidator->verifyXml('xml content');

// or verify a XML file
$isValid = $signatureValidator->verifyXml(file_get_contents('signed-example.xml'));

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
