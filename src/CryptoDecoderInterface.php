<?php

namespace Selective\XmlDSig;

interface CryptoDecoderInterface
{
    public function verify(string $data, string $signature, string $algorithm): bool;

    public function computeDigest(string $data, string $algorithm): string;
}
