<?php

namespace Selective\XmlDSig;

use OpenSSLCertificate;
use Selective\XmlDSig\Exception\CertificateException;

/**
 * A X509 File Reader.
 */
final class X509Reader
{
    private const PEM_BEGIN_TAG = '-----BEGIN CERTIFICATE-----';
    private const PEM_END_TAG = '-----END CERTIFICATE-----';
    private const PEM_REGEX_PATTERN = '/' . self::PEM_BEGIN_TAG . '(.+)' . self::PEM_END_TAG . '/Us';

    /**
     * Read one or more certificates from string.
     *
     * @param string $pem
     *
     * @return OpenSSLCertificate[]
     */
    public function fromPem(string $pem): array
    {
        $certificateIds = [];

        preg_match_all(self::PEM_REGEX_PATTERN, $pem, $matches);

        foreach ($matches[0] as $certificate) {
            // Read the certificate
            $certificateId = openssl_x509_read($certificate);

            if (!$certificateId) {
                throw new CertificateException('Invalid certificate');
            }

            $certificateIds[] = $certificateId;
        }

        return $certificateIds;
    }

    /**
     * Read certificate from raw base64 string.
     *
     * @param string $base64
     *
     * @return OpenSSLCertificate
     */
    public function fromRawBase64(string $base64): OpenSSLCertificate
    {
        $certificate = openssl_x509_read(self::PEM_BEGIN_TAG . "\n{$base64}\n" . self::PEM_END_TAG);

        if ($certificate === false) {
            throw new CertificateException('Reading certificate failed');
        }

        return $certificate;
    }

    /**
     * Return raw base64 for certificate.
     *
     * @param OpenSSLCertificate $certificate
     *
     * @return string
     */
    public function toRawBase64(OpenSSLCertificate $certificate): string
    {
        if (!openssl_x509_export($certificate, $exportedCertificate)) {
            throw new CertificateException('Exporting certificate failed');
        }

        preg_match(self::PEM_REGEX_PATTERN, $exportedCertificate, $matches);

        return str_replace(["\r\n", "\n"], '', trim($matches[1]));
    }
}
