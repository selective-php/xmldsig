# Changelog

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
