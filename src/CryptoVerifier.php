<?php

namespace Selective\XmlDSig;

use EllipticCurve\Ecdsa;
use EllipticCurve\PublicKey;
use EllipticCurve\Signature;
use OpenSSLAsymmetricKey;
use Selective\XmlDSig\Exception\CertificateException;
use Selective\XmlDSig\Exception\XmlSignatureValidatorException;

final class CryptoVerifier implements CryptoVerifierInterface
{
    private PublicKeyStore $publicKeyStore;

    /**
     * The constructor.
     *
     * @param PublicKeyStore $publicKeyStore The public key store
     */
    public function __construct(PublicKeyStore $publicKeyStore)
    {
        $this->publicKeyStore = $publicKeyStore;
    }

    public function verify(string $data, string $signature, string $algorithm): bool
    {
        $publicKeys = $this->publicKeyStore->getPublicKeys();
        if (!$publicKeys) {
            throw new CertificateException('No public key provided');
        }

        if (str_contains($algorithm, 'ecdsa')) {
            return $this->verifyEcdsa($publicKeys, $signature, $data);
        }

        $algo = $this->mapUrlToOpenSslAlgoCode($algorithm);

        foreach ($publicKeys as $publicKey) {
            $status = openssl_verify($data, $signature, $publicKey, $algo);

            if ($status === 1) {
                return true;
            }
        }

        // The XML signature is not valid
        return false;
    }

    private function mapUrlToOpenSslAlgoCode(string $algorithm): int
    {
        $algorithm = strtolower($algorithm);

        $hashes = [
            Algorithm::METHOD_SHA1 => OPENSSL_ALGO_SHA1,
            Algorithm::METHOD_SHA224 => OPENSSL_ALGO_SHA224,
            Algorithm::METHOD_SHA256 => OPENSSL_ALGO_SHA256,
            Algorithm::METHOD_SHA384 => OPENSSL_ALGO_SHA384,
            Algorithm::METHOD_SHA512 => OPENSSL_ALGO_SHA512,
        ];

        foreach ($hashes as $hash => $ssl) {
            if (str_contains($algorithm, $hash)) {
                return $ssl;
            }
        }

        throw new XmlSignatureValidatorException(
            sprintf('Cannot verify: Unsupported Algorithm: %s', $algorithm)
        );
    }

    /**
     * Map algo to OpenSSL method name.
     *
     * @param string $algorithm The url
     *
     * @return string The name of the OpenSSL algorithm
     */
    private function mapUrlToOpenSslDigestAlgo(string $algorithm): string
    {
        $algorithm = strtolower($algorithm);

        $hashes = [
            Algorithm::METHOD_SHA1,
            Algorithm::METHOD_SHA224,
            Algorithm::METHOD_SHA256,
            Algorithm::METHOD_SHA384,
            Algorithm::METHOD_SHA512,
            Algorithm::METHOD_ECDSA_SHA256,
        ];

        foreach ($hashes as $hash) {
            if (str_contains($algorithm, $hash)) {
                return $hash;
            }
        }

        throw new XmlSignatureValidatorException(sprintf('Unsupported algorithm: %s', $algorithm));
    }

    public function computeDigest(string $data, string $algorithm): string
    {
        $digestAlgo = $this->mapUrlToOpenSslDigestAlgo($algorithm);
        $digest = openssl_digest($data, $digestAlgo, true);

        if ($digest === false) {
            throw new XmlSignatureValidatorException('Invalid digest value');
        }

        return $digest;
    }

    /**
     * Verify using the Elliptic Curve Digital Signature Algorithm (ECDSA).
     *
     * @param OpenSSLAsymmetricKey[] $publicKeys The public keys
     * @param string $signature The signature from the xml element
     * @param string $data The data
     *
     * @return bool The status
     */
    private function verifyEcdsa(array $publicKeys, string $signature, string $data): bool
    {
        foreach ($publicKeys as $publicKey) {
            $signature = Signature::fromDer($signature);

            // Convert OpenSSLAsymmetricKey to PEM string
            $details = openssl_pkey_get_details($publicKey);
            $publicKey2 = PublicKey::fromPem($details['key'] ?? '');

            $status = Ecdsa::verify($data, $signature, $publicKey2);
            if ($status) {
                return true;
            }
        }

        return false;
    }
}
