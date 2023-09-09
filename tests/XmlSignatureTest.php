<?php

namespace Selective\XmlDSig\Test;

use PHPUnit\Framework\TestCase;
use Selective\XmlDSig\Algorithm;
use Selective\XmlDSig\CryptoSigner;
use Selective\XmlDSig\CryptoVerifier;
use Selective\XmlDSig\PrivateKeyStore;
use Selective\XmlDSig\PublicKeyStore;
use Selective\XmlDSig\XmlSignatureVerifier;
use Selective\XmlDSig\XmlSigner;

/**
 * Test.
 *
 * @coversDefaultClass \Selective\XmlDSig\XmlSigner
 */
final class XmlSignatureTest extends TestCase
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
            Algorithm::METHOD_SHA1,
            Algorithm::METHOD_SHA224,
            Algorithm::METHOD_SHA256,
            Algorithm::METHOD_SHA384,
            Algorithm::METHOD_SHA512,
        ];

        foreach ($files as $filename) {
            foreach ($algos as $algo) {
                $privateKeyStore = new PrivateKeyStore();

                if (pathinfo($privateKeyFile, PATHINFO_EXTENSION) === 'p12') {
                    $privateKeyStore->loadFromPkcs12(file_get_contents($privateKeyFile), $password);
                } else {
                    $privateKeyStore->loadFromPem(file_get_contents($privateKeyFile), $password);
                }

                $algorithm = new Algorithm($algo, $algo);
                $cryptoSigner = new CryptoSigner($privateKeyStore, $algorithm);

                $xmlSigner = new XmlSigner($cryptoSigner);
                $xmlSigner->setReferenceUri('');

                $signedXml = $xmlSigner->signXml(file_get_contents($filename));

                // verify
                $publicKeyStore = new PublicKeyStore();
                if (pathinfo($publicKeyFile, PATHINFO_EXTENSION) === 'p12') {
                    $publicKeyStore->loadFromPkcs12(file_get_contents($publicKeyFile), $password);
                } else {
                    $publicKeyStore->loadFromPem(file_get_contents($publicKeyFile));
                }

                $cryptoVerifier = new CryptoVerifier($publicKeyStore);
                $xmlSignatureVerifier = new XmlSignatureVerifier($cryptoVerifier);

                $isValid = $xmlSignatureVerifier->verifyXml($signedXml);

                $this->assertTrue($isValid);
            }
        }
    }

    /**
     * Provide.
     *
     * @return array<int, mixed> The data
     */
    public static function providerTestSignAndVerify(): array
    {
        $keyFiles = [];

        $keyFiles[] = [
            // Private and public key bundle
            // openssl pkcs12 -export -out cert.p12 -in cacert.pem -inkey cakey.pem
            // Enter: secret
            // Enter 2x: 12345678
            __DIR__ . '/cert.p12',
            __DIR__ . '/cert.p12',
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
