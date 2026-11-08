# Native HTTPS

The container can serve the UI, API and MCP endpoint over HTTPS without an extra proxy. HTTP remains the default for existing reverse-proxy deployments. Both modes use container port `8000`; enabling HTTPS changes that listener to TLS. It does not add an HTTP redirect listener or change UDP syslog.

## Start with a self-signed certificate

Set these values in your private `.env` when using `compose.gzeon.yml`:

```dotenv
HTTPS_ENABLED=true
HTTPS_HOSTNAMES=insights.example.invalid,203.0.113.10
WEB_PORT=8443
# Set this to the Docker host's intended LAN address for access from other devices.
WEB_BIND_IP=127.0.0.1
```

Replace the example hostname and IP with the names you will browse to. Use comma-separated DNS names or IPs, without a scheme, port or URL path. DNS resolution must point to the Docker host separately. Loopback names and addresses are included automatically for local checks.

After selecting a built image, recreate the container:

```sh
docker compose -f compose.gzeon.yml up -d
```

Browse to `https://<configured-hostname>:8443`. First startup creates a certificate and private key in `/var/lib/unifi-log-insight/tls`. The Compose file persists that directory in the `tls` volume, so restarting, recreating or upgrading the container keeps the same certificate. With Container Station or another container manager, add that persistent mount yourself and pass the same environment variables. Do not use `down -v` when retaining the database and certificate.

The generated certificate is self-signed. Clients need to trust it explicitly; it is not automatically trusted by browsers, MCP clients or Cloudflare. Export only the public certificate from the container and verify its fingerprint through your trusted Docker management connection before importing it into a client trust store:

```sh
docker compose -f compose.gzeon.yml cp insights:/var/lib/unifi-log-insight/tls/cert.pem ./insights-cert.pem
openssl x509 -in insights-cert.pem -noout -fingerprint -sha256 -dates
```

For a CLI check, trust that certificate explicitly:

```sh
curl --cacert ./insights-cert.pem https://<configured-hostname>:8443/api/health
```

Keep `key.pem` private. Certificate and key files are excluded from Git and image builds. Even a public certificate can reveal private hostnames, so keep exports out of the public repository.

## Authentication

Native HTTPS meets the application's HTTPS requirement for login and Secure session cookies. Enable authentication and create the administrator in Settings → Security as usual. TLS alone does not enable authentication. Direct HTTPS does not need the reverse-proxy authentication header.

HTTP behind an existing HTTPS reverse proxy remains supported. That proxy must send the application's `X-ULI-Proxy-Auth` header before forwarded HTTPS/client-IP headers are trusted. The server disables Uvicorn's separate implicit proxy-header trust so this check applies consistently. Settings → Security provides the generated header instructions.

If switching the backend behind an existing proxy from HTTP to HTTPS, update the upstream scheme and certificate trust there too. The native HTTPS option does not change external proxy configuration.

## Certificate settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `HTTPS_ENABLED` | `false` | Enable native TLS on port 8000. |
| `HTTPS_HOSTNAMES` | `localhost,127.0.0.1` | DNS/IP subject alternative names for generated certificates. |
| `HTTPS_CERT_DIR` | `/var/lib/unifi-log-insight/tls` | Persistent directory containing generated `cert.pem` and `key.pem`. |
| `HTTPS_CERT_DAYS` | `365` | Generated validity period, 1–825 days. Applies at creation. |
| `HTTPS_CERT_FILE` | unset | Absolute path to an existing PEM certificate or chain. Set with `HTTPS_KEY_FILE`. |
| `HTTPS_KEY_FILE` | unset | Absolute path to the matching unencrypted PEM private key. |

Generated directories have mode 0700; generated certificate and key files have mode 0600. The certificate uses RSA-2048, SHA-256 and DNS/IP SANs. TLS uses Python's server context with a minimum TLS version of 1.2. A single API process serves HTTPS, with no extra proxy container.

For your own certificate, mount its directory read-only and set both file variables. Supplied files are validated but never generated or overwritten. Include a DNS/IP SAN, serve the leaf certificate first in a chain, and use a key without a passphrase. The container health check trusts the configured leaf certificate and verifies TLS and its hostname while connecting over loopback; it does not require public DNS resolution or disable certificate verification.

Invalid settings, a missing half of a certificate/key pair, a mismatched key, expired certificate or changed hostnames not covered by the saved certificate stop startup. HTTPS errors never trigger an HTTP fallback. The health check also detects certificate expiry while the process is running.

## Replace or renew a generated certificate

Certificates are not silently renewed. Startup warns when fewer than 30 days remain. Plan renewal before expiry; a new self-signed certificate must be trusted again by clients.

1. Stop the service and save a private backup of the TLS directory.
2. Change `HTTPS_HOSTNAMES` or `HTTPS_CERT_DAYS` if needed.
3. Move **both** `cert.pem` and `key.pem` out of the mounted TLS directory. Leave the database volume alone.
4. Start the service. It creates a new pair. Export and trust the new certificate on clients.

Restore both old files to roll back, provided that certificate is still valid and covers the configured hostnames. For supplied certificates, replace their files and restart; this service does not run ACME or renew externally supplied certificates.

## References

[Uvicorn's TLS options](https://uvicorn.dev/settings/#https) and [cryptography's X.509 tutorial](https://cryptography.io/en/stable/x509/tutorial/) document the libraries used here.
