"""Pi-hole v6 settings, connection test endpoints."""

import logging
import ipaddress

from fastapi import APIRouter, HTTPException

from db import get_config, set_config, encrypt_api_key
from deps import enricher_db, signal_receiver, pihole_poller

logger = logging.getLogger('api.pihole')

router = APIRouter()


@router.get("/api/settings/pihole")
def get_pihole_settings():
    """Current Pi-hole settings (merged: env + DB + defaults)."""
    return pihole_poller.get_settings_info()


@router.put("/api/settings/pihole")
def update_pihole_settings(body: dict):
    """Save Pi-hole settings to system_config."""
    # Validate all fields before persisting anything
    interval = None
    dns_server = None
    if 'poll_interval' in body:
        try:
            interval = int(body['poll_interval'])
        except (ValueError, TypeError):
            raise HTTPException(400, 'poll_interval must be an integer')
        if interval < 15 or interval > 86400:
            raise HTTPException(400, 'poll_interval must be between 15 and 86400 seconds')
    if 'enrichment' in body:
        if body['enrichment'] not in ('none', 'geoip', 'threat', 'both'):
            raise HTTPException(400, 'enrichment must be one of: none, geoip, threat, both')
    if 'dns_server' in body:
        if not isinstance(body['dns_server'], str):
            raise HTTPException(400, 'dns_server must be a numeric IP address or empty')
        dns_server = body['dns_server'].strip()
        if dns_server:
            try:
                dns_server = str(ipaddress.ip_address(dns_server))
            except ValueError:
                raise HTTPException(400, 'dns_server must be a numeric IP address or empty') from None
    if 'host' in body and not isinstance(body['host'], str):
        raise HTTPException(400, 'host must be a string')

    # All valid — persist
    if 'enabled' in body:
        set_config(enricher_db, 'pihole_enabled', body['enabled'])
        if not body['enabled']:
            set_config(enricher_db, 'pihole_poll_status', None)
    if 'host' in body:
        enricher_db.set_pihole_host(body['host'])
    if 'password' in body:
        val = body['password']
        if val:
            set_config(enricher_db, 'pihole_password', encrypt_api_key(val))
    if interval is not None:
        set_config(enricher_db, 'pihole_poll_interval', interval)
    if 'enrichment' in body:
        set_config(enricher_db, 'pihole_enrichment', body['enrichment'])
    if dns_server is not None:
        set_config(enricher_db, 'pihole_dns_server', dns_server)

    # Only the receiver collects. This API-local instance supplies settings
    # and connection tests, never a second background importer.
    pihole_poller.reload_config(restart_polling=False)
    signal_receiver()

    return {"success": True}


@router.post("/api/settings/pihole/test")
def test_pihole_connection(body: dict):
    """Test Pi-hole connectivity and authentication."""
    host = body.get('host', '').strip()
    password = body.get('password', '')

    result = pihole_poller.test_connection(host, password)
    return result
