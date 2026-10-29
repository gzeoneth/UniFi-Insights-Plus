"""Probe the local API, verifying its certificate when native HTTPS is enabled."""

import http.client
import ssl

from cryptography import x509

from tls_config import TLSSettings, validate_certificate


def check_health():
    settings = TLSSettings.from_env()
    if settings.enabled:
        cert = validate_certificate(settings)
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = names.get_values_for_type(x509.DNSName)
        ips = names.get_values_for_type(x509.IPAddress)
        identity = dns_names[0].replace('*.', 'healthcheck.', 1) if dns_names else str(ips[0])
        context = ssl.create_default_context(cafile=str(settings.cert_file))
        # Trust this exact mounted leaf even if it was issued by a private CA.
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN

        class LoopbackHTTPSConnection(http.client.HTTPConnection):
            def connect(self):
                super().connect()
                self.sock = context.wrap_socket(self.sock, server_hostname=identity)

        connection = LoopbackHTTPSConnection('127.0.0.1', 8000, timeout=10)
    else:
        connection = http.client.HTTPConnection('127.0.0.1', 8000, timeout=10)
    try:
        connection.request('GET', '/api/health')
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f'API health returned HTTP {response.status}')
    finally:
        connection.close()


if __name__ == '__main__':
    check_health()
