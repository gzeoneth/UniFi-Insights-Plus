"""Share validated bearer credentials only within the current HTTP request."""

import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class _BearerContext:
    digest: bytes
    info: dict


def clear_bearer_context(request):
    request.state._uli_bearer_context = None


def remember_bearer_context(request, token, info):
    """Called after validation; never retain the bearer token itself."""
    request.state._uli_bearer_context = _BearerContext(
        hashlib.sha256(token.encode()).digest(), info)


def validated_bearer_context(request, token):
    """Return context only for the same bearer on this request.

    Session authentication and arbitrary state/header values cannot stand in
    for an API token. Each new request must validate credentials again.
    """
    context = getattr(request.state, '_uli_bearer_context', None)
    if not token or not isinstance(context, _BearerContext):
        return None
    digest = hashlib.sha256(token.encode()).digest()
    if not hmac.compare_digest(context.digest, digest):
        return None
    if not context.info.get('token_id'):
        return None
    return context.info
