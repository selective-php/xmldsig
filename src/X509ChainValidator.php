<?php

namespace Selective\XmlDSig;

use OpenSSLCertificate;

/**
 * A X509 chain validator
 */
class X509ChainValidator
{
    private $caFile;
    private $intermediatesFile;

    /**
     * @param OpenSSLCertificate[]|resource[] $caCertificateIds
     * @param OpenSSLCertificate[]|resource[] $intermediateCertificateIds
     */
    public function __construct(array $caCertificateIds, array $intermediateCertificateIds)
    {
        $this->caFile = tempnam(sys_get_temp_dir(), '');
        $this->intermediatesFile = tempnam(sys_get_temp_dir(), '');

        $this->exportCertificates($caCertificateIds, $this->caFile);
        $this->exportCertificates($intermediateCertificateIds, $this->intermediatesFile);
    }

    /**
     * Export certificates to file
     *
     * @param OpenSSLCertificate[]|resource[] $certificateIds
     * @param string                          $file
     *
     * @return void
     */
    private function exportCertificates(array $certificateIds, string $file): void
    {
        foreach ($certificateIds as $certificateId) {
            if (openssl_x509_export($certificateId, $certificate)) {
                file_put_contents($file, $certificate, FILE_APPEND);
            }
        }
    }

    public function __destruct()
    {
        if ($this->caFile && file_exists($this->caFile)) {
            unlink($this->caFile);
        }

        if ($this->intermediatesFile && file_exists($this->intermediatesFile)) {
            unlink($this->intermediatesFile);
        }
    }

    /**
     * Validate certificate against chain
     *
     * @param OpenSSLCertificate[]|resource[] $certificateId
     *
     * @return bool
     */
    public function validateCertificateChain($certificateId): bool
    {
        return openssl_x509_checkpurpose($certificateId, 0, array($this->caFile), $this->intermediatesFile) === true;
    }
}
