<?php

namespace Selective\XmlDSig;

interface CryptoSignerInterface
{
    public function computeSignature(string $data): string;

    public function computeDigest(string $data): string;

    public function getPrivateKeyStore(): PrivateKeyStore;

    public function getAlgorithm(): Algorithm;
}
