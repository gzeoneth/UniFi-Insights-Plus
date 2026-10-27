"""Run the API over HTTP or optional native HTTPS on the same port."""

import os
import ssl

import uvicorn

from tls_config import TLSSettings, prepare_tls


def server_options(settings):
    options = {
        'host': '0.0.0.0', 'port': 8000, 'workers': 1,
        'log_level': os.environ.get('UVICORN_LOG_LEVEL', 'info'),
        # The app verifies X-ULI-Proxy-Auth before trusting forwarded headers.
        'proxy_headers': False,
    }
    if settings.enabled:
        options.update(ssl_certfile=str(settings.cert_file), ssl_keyfile=str(settings.key_file),
                       ssl_version=ssl.PROTOCOL_TLS_SERVER)
    return options


if __name__ == '__main__':
    settings = TLSSettings.from_env()
    prepare_tls(settings)
    uvicorn.run('api:app', **server_options(settings))
