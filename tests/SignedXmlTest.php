<?php

namespace Odan\XmlDSig\Test;

use Odan\XmlDSig\SignedXml;
use PHPUnit\Framework\TestCase;

/**
 * Test.
 *
 * @coversDefaultClass \Odan\XmlDSig\SignedXml
 */
class SignedXmlTest extends TestCase
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
}
