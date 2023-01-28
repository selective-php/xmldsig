# Changelog

## [Unreleased]

## 3.0.0

### Added

- Add support for Elliptic Curve Digital Signature Algorithm ECDSA SHA256
- Add support for x509 certificate
- Add possibility to sign specific parts of an XML document

### Changed

- Require PHP 8

### Breaking Changes

- The package has been completely redesigned to meet the new requirements

## 2.0.0

### Added

* A new method: `XmlSigner::loadPrivateKeyFile`
* A `KeyInfo` element with `Modulus` and `Exponent`
* A base64 decoding check
* Tests
* Changelog file

### Changed

* Rename `XmlSigner::setDigestAlgorithm` to `XmlSigner::setAlgorithm`
* Renamed `XmlSignatureValidator::loadPfx` to `XmlSignatureValidator::loadPfxFile`
* Fixed enveloped signature
* Fixed digest method algorithm url
* Tested against:
  * https://tools.chilkat.io/xmlDsigVerify.cshtml
  * https://www.aleksey.com/xmlsec/xmldsig-verifier.html

## 1.0.0

* First release
