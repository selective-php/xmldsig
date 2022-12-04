<?php

namespace Selective\XmlDSig;

interface CryptoVerifierInterface
{
    public function verify(string $data, string $signature, string $algorithm): bool;

    public function computeDigest(string $data, string $algorithm): string;
}
