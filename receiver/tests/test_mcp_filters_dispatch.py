"""MCP filter parity and blocking-work dispatch regression tests."""

import asyncio
import contextvars
import importlib
import json
import sys
import threading
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from starlette.requests import Request


@pytest.fixture
def mcp(monkeypatch):
    for name in list(sys.modules):
        if name.startswith('routes'):
            monkeypatch.delitem(sys.modules, name, raising=False)
    for name in ('deps', 'db', 'routes.logs', 'routes.stats', 'routes.setup',
                 'routes.unifi', 'routes.health', 'routes.threats', 'routes.auth'):
        monkeypatch.setitem(sys.modules, name, MagicMock())
    return importlib.import_module('routes.mcp')


RULES = [{'field': 'ip', 'operator': 'exclude', 'value': '10.0.0.0/24'},
         {'field': 'dst_port', 'operator': 'include', 'value': '443,8000-8100'}]


def test_search_aggregate_and_export_preserve_same_structured_filters(mcp):
    mcp._tool_search_logs({'filter_rules': RULES})
    mcp._tool_aggregate_logs({'group_by': 'src_ip', 'filter_rules': RULES})
    assert json.loads(mcp.logs_routes.get_logs.call_args.kwargs['filter_rules']) == RULES
    assert json.loads(mcp.logs_routes.get_logs_aggregate.call_args.kwargs['filter_rules']) == RULES
    url = mcp._tool_export_logs_csv_url({'filter_rules': RULES, 'limit': 10})['download_url']
    query = parse_qs(urlsplit(url).query)
    assert json.loads(query['filter_rules'][0]) == RULES
    assert query['limit'] == ['10']


def test_all_filtering_tools_advertise_whitelisted_fields(mcp):
    catalog = {tool['name']: tool for tool in mcp._tools_catalog()}
    for name in ('search_logs', 'aggregate_logs', 'export_logs_csv_url'):
        schema = catalog[name]['inputSchema']['properties']['filter_rules']
        assert schema['maxItems'] == 24
        assert 'ips_signature' in schema['items']['properties']['field']['enum']
        assert schema['items']['additionalProperties'] is False


def test_invalid_export_filter_is_rejected_before_issuing_a_broken_url(mcp):
    with pytest.raises(HTTPException) as error:
        mcp._tool_export_logs_csv_url({'filter_rules': [{'field': 'dst_port', 'operator': 'include', 'value': '99999'}]})
    assert error.value.status_code == 400


def test_sync_tool_and_audit_do_not_block_event_loop_and_keep_context(mcp, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    marker = contextvars.ContextVar('request_marker')
    worker_threads = []
    context_seen = []

    def slow_tool(name, args):
        worker_threads.append(threading.get_ident())
        context_seen.append(marker.get())
        entered.set()
        assert release.wait(2), 'event loop did not release worker in time'
        return {'ok': True}

    monkeypatch.setattr(mcp, '_handle_tool_call', slow_tool)
    monkeypatch.setattr(mcp, '_write_audit', lambda *args: worker_threads.append(threading.get_ident()))

    async def exercise():
        marker.set('synthetic request')
        task = asyncio.create_task(mcp._handle_jsonrpc({
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'search_logs', 'arguments': {}},
        }, {'effective_scopes': {'logs.read'}}))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            assert not task.done()
            assert all(thread != threading.get_ident() for thread in worker_threads)
        finally:
            release.set()
        response = await task
        assert json.loads(response.body)['result']['content'][0]['text']

    asyncio.run(exercise())
    assert context_seen == ['synthetic request']
    assert len(worker_threads) == 2  # handler and audit share the worker execution.


def test_post_auth_origin_and_handler_checks_are_all_offloaded(mcp, monkeypatch):
    threads = []
    main_thread = threading.get_ident()
    def record(*args):
        threads.append(threading.get_ident())
    monkeypatch.setattr(mcp, '_require_mcp_enabled', record)
    monkeypatch.setattr(mcp, '_validate_origin', record)
    def lookup(token):
        record()
        return {'effective_scopes': {'logs.read'}}
    monkeypatch.setattr(mcp, '_lookup_token', lookup)
    def handler(body, token):
        record()
        return {'jsonrpc': '2.0', 'id': 1, 'result': {}}
    monkeypatch.setattr(mcp, '_handle_request', handler)
    async def receive():
        return {'type': 'http.request', 'body': b'{"jsonrpc":"2.0","id":1,"method":"ping"}'}
    request = Request({'type': 'http', 'method': 'POST', 'path': '/api/mcp',
                       'headers': [(b'authorization', b'Bearer synthetic-token')]}, receive)
    response = asyncio.run(mcp.mcp_post(request))
    assert response.status_code == 200
    assert len(threads) == 4
    assert all(thread != main_thread for thread in threads)


def test_worker_http_error_still_becomes_tool_error(mcp, monkeypatch):
    def denied(name, args):
        raise HTTPException(status_code=400, detail='Invalid field filter')
    monkeypatch.setattr(mcp, '_handle_tool_call', denied)
    monkeypatch.setattr(mcp, '_write_audit', MagicMock())
    response = asyncio.run(mcp._handle_jsonrpc({
        'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
        'params': {'name': 'search_logs', 'arguments': {}},
    }, {'effective_scopes': {'logs.read'}}))
    body = json.loads(response.body)
    assert body['result']['isError'] is True
    assert body['result']['content'][0]['text'] == 'Invalid field filter'
