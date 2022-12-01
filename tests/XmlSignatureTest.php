<?php

namespace Selective\XmlDSig\Test;

use PHPUnit\Framework\TestCase;
use Selective\XmlDSig\DigestAlgorithmType;
use Selective\XmlDSig\OpenSslCryptoDecoder;
use Selective\XmlDSig\OpenSslCryptoEncoder;
use Selective\XmlDSig\XmlSignatureValidator;
use Selective\XmlDSig\XmlSigner;

/**
 * Test.
 *
 * @coversDefaultClass \Selective\XmlDSig\XmlSigner
 */
class XmlSignatureTest extends TestCase
{
    /**
     * Test.
     *
     * @dataProvider providerTestSignAndVerify
     *
     * @param string $privateKeyFile The key file
     * @param string $publicKeyFile The key file
     * @param string $password The file password
     *
     * @return void
     */
    public function testSignAndVerify(string $privateKeyFile, string $publicKeyFile, string $password)
    {
        $files = [
            __DIR__ . '/example1.xml',
            __DIR__ . '/example2.xml',
            __DIR__ . '/example3.xml',
            __DIR__ . '/example4.xml',
        ];

        $algos = [
            DigestAlgorithmType::SHA1,
            DigestAlgorithmType::SHA224,
            DigestAlgorithmType::SHA256,
            DigestAlgorithmType::SHA384,
            DigestAlgorithmType::SHA512,
        ];

        foreach ($files as $filename) {
            foreach ($algos as $algo) {
                $cryptoEncoder = new OpenSslCryptoEncoder($algo);
                $xmlSigner = new XmlSigner($cryptoEncoder);

                if (pathinfo($privateKeyFile, PATHINFO_EXTENSION) === 'pfx') {
                    $cryptoEncoder->loadPfx(file_get_contents($privateKeyFile), $password);
                } else {
                    $cryptoEncoder->loadPrivateKey(file_get_contents($privateKeyFile), $password);
                }

                $xmlSigner->setReferenceUri('');
                $signedXml = $xmlSigner->signXml(file_get_contents($filename));

                // verify
                $cryptoDecoder = new OpenSslCryptoDecoder();
                $verifyXml = new XmlSignatureValidator($cryptoDecoder);

                if (pathinfo($publicKeyFile, PATHINFO_EXTENSION) === 'pfx') {
                    $cryptoDecoder->loadPfx(file_get_contents($publicKeyFile), $password);
                } else {
                    $cryptoDecoder->loadPublicKey(file_get_contents($publicKeyFile));
                }

                $isValid = $verifyXml->verifyXml($signedXml);

                $this->assertTrue($isValid);
            }
        }
    }

    /**
     * Provide.
     *
     * @return array<int, mixed> The data
     */
    public function providerTestSignAndVerify(): array
    {
        $keyFiles = [];

        $keyFiles[] = [
            // Private and public key bundle
            __DIR__ . '/localhost.pfx',
            __DIR__ . '/localhost.pfx',
            '12345678',
        ];

        // https://github.com/lsh123/xmlsec/tree/master/tests/keys
        // https://raw.githubusercontent.com/lsh123/xmlsec/fdb11bf0ab6b61cbb475c6f8154b84ae2e435411/tests/keys/cakey.pem
        // https://www.aleksey.com/xmlsec/xmldsig-verifier.html
        // https://tools.chilkat.io/xmlDsigVerify.cshtml
        $keyFiles[] = [
            // Root CA private key
            __DIR__ . '/cakey.pem',
            __DIR__ . '/cacert.pem',
            'secret',
        ];

        return $keyFiles;
    }
}
