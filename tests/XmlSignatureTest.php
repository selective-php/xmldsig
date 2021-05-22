<?php

namespace Selective\XmlDSig\Test;

use PHPUnit\Framework\TestCase;
use Selective\XmlDSig\DigestAlgorithmType;
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
     * @var array
     */
    private $algos = [
        DigestAlgorithmType::SHA1,
        DigestAlgorithmType::SHA224,
        DigestAlgorithmType::SHA256,
        DigestAlgorithmType::SHA384,
        DigestAlgorithmType::SHA512,
    ];

    /**
     * Test create object.
     *
     * @return void
     */
    public function testInstance()
    {
        $this->assertInstanceOf(XmlSigner::class, new XmlSigner());
    }

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

        $outputFilename = __DIR__ . '/signed-example.xml';

        foreach ($files as $filename) {
            $this->assertFileExists($filename);

            foreach ($this->algos as $algo) {
                if (file_exists($outputFilename)) {
                    unlink($outputFilename);
                }

                if (method_exists($this, 'assertFileDoesNotExist')) {
                    $this->assertFileDoesNotExist($outputFilename);
                } else {
                    $this->assertFileNotExists($outputFilename);
                }

                $signedXml = new XmlSigner();

                if (pathinfo($privateKeyFile, PATHINFO_EXTENSION) === 'pfx') {
                    $signedXml->loadPfxFile($privateKeyFile, $password);
                } else {
                    $signedXml->loadPrivateKeyFile($privateKeyFile, $password);
                }

                $signedXml->setReferenceUri('');
                $signedXml->signXmlFile($filename, $outputFilename, $algo);

                $this->assertFileExists($outputFilename);

                // verify
                $verifyXml = new XmlSignatureValidator();

                if (pathinfo($publicKeyFile, PATHINFO_EXTENSION) === 'pfx') {
                    $verifyXml->loadPfxFile($publicKeyFile, $password);
                } else {
                    $verifyXml->loadPublicKeyFile($publicKeyFile);
                }

                $isValid = $verifyXml->verifyXmlFile($outputFilename);

                $this->assertTrue($isValid);
            }
        }
    }

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
    public function testSignAndVerifySoap(string $privateKeyFile, string $publicKeyFile, string $password)
    {
        $files = [
            __DIR__ . '/example-soap.xml',
        ];

        $outputFilename = __DIR__ . '/signed-example.xml';

        foreach ($files as $filename) {
            $this->assertFileExists($filename);

            foreach ($this->algos as $algo) {
                if (file_exists($outputFilename)) {
                    unlink($outputFilename);
                }

                if (method_exists($this, 'assertFileDoesNotExist')) {
                    $this->assertFileDoesNotExist($outputFilename);
                } else {
                    $this->assertFileNotExists($outputFilename);
                }

                $signedXml = new XmlSigner();

                if (pathinfo($privateKeyFile, PATHINFO_EXTENSION) === 'pfx') {
                    $signedXml->loadPfxFile($privateKeyFile, $password);
                } else {
                    $signedXml->loadPrivateKeyFile($privateKeyFile, $password);
                }

                $signedXml->setReferenceUri('');
                $signedXml->setSignaturePath('/SOAP-ENV:Envelope/SOAP-ENV:Body/xmlns:RegisterTCRRequest');
                $signedXml->signXmlFile($filename, $outputFilename, $algo);

                $this->assertFileExists($outputFilename);

                // verify
                $verifyXml = new XmlSignatureValidator();

                if (pathinfo($publicKeyFile, PATHINFO_EXTENSION) === 'pfx') {
                    $verifyXml->loadPfxFile($publicKeyFile, $password);
                } else {
                    $verifyXml->loadPublicKeyFile($publicKeyFile);
                }

                $isValid = $verifyXml->verifyXmlFile($outputFilename);

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
