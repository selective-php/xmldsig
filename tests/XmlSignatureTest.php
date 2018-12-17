<?php

namespace Odan\XmlDSig\Test;

use Odan\XmlDSig\SignedXml;
use Odan\XmlDSig\VerifyXml;
use PHPUnit\Framework\TestCase;

/**
 * Test.
 *
 * @coversDefaultClass \Odan\XmlDSig\SignedXml
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
        $this->assertInstanceOf(SignedXml::class, new SignedXml());
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
        $algos = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512'];
        //$algos = ['sha512'];

        $this->assertFileExists($filename);

        foreach ($algos as $algo) {
            if (file_exists($outputFilename)) {
                unlink($outputFilename);
            }

            $this->assertFileNotExists($outputFilename);

            $signedXml = new SignedXml();
            $signedXml->loadPfx($pfxFilename, $password);
            $success = $signedXml->signXmlFile($filename, $outputFilename, $algo);

            $this->assertTrue($success);
            $this->assertFileExists($outputFilename);

            // verify
            $verifyXml = new VerifyXml();
            $verifyXml->loadPfx($pfxFilename, $password);
            $isValid = $verifyXml->verifyXmlFile($outputFilename);

            $this->assertTrue($isValid);
        }
    }
}
