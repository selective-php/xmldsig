<?php

namespace Selective\XmlDSig;

interface CryptoEncoderInterface
{
    public function computeSignature(string $data): string;

    public function computeDigest(string $data): string;

    public function getSignatureAlgorithm(): string;

    public function getDigestAlgorithm(): string;

    public function getModulus(): string;

    public function getPublicExponent(): string;
}
