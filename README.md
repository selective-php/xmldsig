# XMLDSIG for PHP

* Sign XML Documents with Digital Signatures ([XMLDSIG](https://www.w3.org/TR/xmldsig-core/))
* Verify the Digital Signatures of XML Documents

[![Latest Version on Packagist](https://img.shields.io/github/release/selective-php/xmldsig.svg?style=flat-square)](https://packagist.org/packages/selective/xmldsig)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/selective-php/xmldsig/master.svg?style=flat-square)](https://travis-ci.org/selective-php/xmldsig)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/selective-php/xmldsig.svg?style=flat-square)](https://scrutinizer-ci.com/g/selective-php/xmldsig/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/quality/g/selective-php/xmldsig.svg?style=flat-square)](https://scrutinizer-ci.com/g/selective-php/xmldsig/?branch=master)
[![Total Downloads](https://img.shields.io/packagist/dt/selective/xmldsig.svg?style=flat-square)](https://packagist.org/packages/selective/xmldsig/stats)

## Requirements

* PHP 7.1.3+
* The openssl extension
* An X.509 digital certificate

## Installation

```
composer require selective/xmldsig
```

## Usage

### Sign XML Documents with Digital Signatures

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
use Selective\XmlDSig\XmlSigner;

$xmlSigner = new XmlSigner('sha512');
$xmlSigner->loadPfx('filename.pfx', 'password');
$xmlSigner->signXmlFile('example.xml', 'signed-example.xml');
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
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
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

$signatureValidator = new XmlSignatureValidator();
$signatureValidator->loadPfx('filename.pfx', 'password');
$isValid = $signatureValidator->verifyXmlFile('signed-example.xml');

if ($isValid) {
    echo 'The XML signature is valid.';
} else {
    echo 'The XML signature is not valid.';
}
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
