<?php

namespace Odan\XmlDSig\Test;

use Odan\XmlDSig\SignedXml;
use Odan\XmlDSig\VerifyXml;
use PHPUnit\Framework\TestCase;

/**
 * Test.
 *
 * @coversDefaultClass \Odan\XmlDSig\VerifyXmlTest
 */
class VerifyXmlTest extends TestCase
{
    /**
     * Test create object.
     *
     * @return void
     */
    public function testInstance()
    {
        $this->assertInstanceOf(VerifyXml::class, new VerifyXml());
    }
}
