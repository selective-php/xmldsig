<?php

namespace Selective\XmlDSig\Test;

use EllipticCurve\PrivateKey;
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
 */
class XmlEcdsaTest extends TestCase
{
    public function test(): void
    {
        $filename = __DIR__ . '/example1.xml';

        // Generate privateKey from PEM string
        $privateKey = PrivateKey::fromPem(
            '-----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
    oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
    RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
    -----END EC PRIVATE KEY-----'
        );

        $pem = (string)$privateKey->toPem();
        $privateKeyStore = new PrivateKeyStore();
        $privateKeyStore->loadFromPem($pem, '');

        $algorithm = new Algorithm(Algorithm::METHOD_ECDSA_SHA256, Algorithm::METHOD_SHA256);
        $cryptoSigner = new CryptoSigner($privateKeyStore, $algorithm);

        $xmlSigner = new XmlSigner($cryptoSigner);

        $message = file_get_contents($filename);
        $signedXml = $xmlSigner->signXml($message);
        // verify
        $publicKeyStore = new PublicKeyStore();

        $publicKey = $privateKey->publicKey();
        $publicKeyStore->loadFromPem($publicKey->toPem());

        $cryptoVerifier = new CryptoVerifier($publicKeyStore);
        $xmlSignatureVerifier = new XmlSignatureVerifier($cryptoVerifier);

        $isValid = $xmlSignatureVerifier->verifyXml($signedXml);
        $this->assertTrue($isValid);
    }
}
