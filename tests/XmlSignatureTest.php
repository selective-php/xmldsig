<?php

namespace Selective\XmlDSig\Test;

use Selective\XmlDSig\DigestAlgorithmType;
use Selective\XmlDSig\XmlSigner;
use Selective\XmlDSig\XmlSignatureValidator;
use PHPUnit\Framework\TestCase;

/**
 * Test.
 *
 * @coversDefaultClass \Selective\XmlDSig\XmlSigner
 */
class XmlSignatureTest extends TestCase
{
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
     * @return void
     */
    public function testSignAndVerify()
    {
        $pfxFilename = __DIR__ . '/localhost.pfx';
        $filename = __DIR__ . '/example.xml';
        $outputFilename = __DIR__ . '/signed-example.xml';

        $password = '12345678';

        $algos = [
            DigestAlgorithmType::SHA1,
            DigestAlgorithmType::SHA224,
            DigestAlgorithmType::SHA256,
            DigestAlgorithmType::SHA384,
            DigestAlgorithmType::SHA512,
        ];

        $this->assertFileExists($filename);

        foreach ($algos as $algo) {
            if (file_exists($outputFilename)) {
                unlink($outputFilename);
            }

            $this->assertFileNotExists($outputFilename);

            $signedXml = new XmlSigner();
            $signedXml->loadPfx($pfxFilename, $password);
            $signedXml->setReferenceUri('');
            $success = $signedXml->signXmlFile($filename, $outputFilename, $algo);

            $this->assertTrue($success);
            $this->assertFileExists($outputFilename);

            // verify
            $verifyXml = new XmlSignatureValidator();
            $verifyXml->loadPfx($pfxFilename, $password);
            $isValid = $verifyXml->verifyXmlFile($outputFilename);

            $this->assertTrue($isValid);
        }
    }
}
