"""Top-table equivalence and opt-in measurements on disposable PostgreSQL 16."""

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import statistics
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from ip_identity import IdentityConfig


CUTOFF = datetime(2026, 1, 1, tzinfo=timezone.utc)
WAN = ['203.0.113.254']
GATEWAYS = ['10.20.0.1']


@pytest.fixture
def pg_tables(monkeypatch):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN to a disposable loopback PostgreSQL')
    import psycopg2
    from psycopg2 import sql
    if psycopg2.extensions.parse_dsn(dsn).get('host') not in ('127.0.0.1', 'localhost', '::1'):
        pytest.fail('Dashboard integration tests require a disposable loopback database')
    connection = psycopg2.connect(dsn)
    schema = 'dashboard_tables_' + uuid4().hex
    try:
        with connection.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC'")
            cur.execute("SET work_mem='8MB'")
            cur.execute('SET max_parallel_workers_per_gather=0')
            cur.execute('SET jit=off')
            cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            cur.execute(sql.SQL('SET search_path TO pg_temp, {}, public').format(sql.Identifier(schema)))
            cur.execute(sql.SQL('''CREATE FUNCTION {}.is_public_inet(addr inet) RETURNS boolean
                LANGUAGE SQL IMMUTABLE AS $$ SELECT addr IS NOT NULL AND NOT (
                    addr << '10.0.0.0/8' OR addr << '172.16.0.0/12' OR addr << '192.168.0.0/16'
                    OR addr << 'fc00::/7' OR addr << 'fe80::/10') $$''').format(sql.Identifier(schema)))
            cur.execute('''CREATE TEMP TABLE logs (
                id bigserial PRIMARY KEY,timestamp timestamptz,log_type text,rule_action text,
                direction text,src_ip inet,dst_ip inet,remote_ip inet,geo_country text,
                asn_name text,geo_city text,rdns text,threat_score integer,threat_categories text[],
                service_name text,dns_query text,rule_name text,hostname text,
                event_source text,ips_signature_id text,raw_log text)''')
            cur.execute('''CREATE TEMP TABLE ip_threats(ip inet PRIMARY KEY,threat_categories text[])''')
            cur.execute('''CREATE TEMP TABLE unifi_clients(
                ip inet,device_name text,hostname text,oui text,last_seen timestamptz)''')
            cur.execute('CREATE INDEX ON unifi_clients(ip)')
            cur.execute('CREATE INDEX idx_test_table_time ON logs(timestamp DESC)')
            cur.execute('CREATE INDEX idx_test_table_action ON logs(rule_action,timestamp DESC)')
            cur.execute('CREATE INDEX idx_test_table_type ON logs(log_type,timestamp DESC)')
            cur.execute('CREATE INDEX idx_test_table_threat ON logs(threat_score) WHERE threat_score IS NOT NULL')
        connection.commit()
        monkeypatch.setitem(sys.modules, 'deps', SimpleNamespace(
            get_conn=Mock(return_value=connection),put_conn=Mock(),enricher_db=Mock()))
        path = Path(__file__).parents[1] / 'routes' / 'stats.py'
        spec = importlib.util.spec_from_file_location('synthetic_dashboard_tables_' + uuid4().hex,path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setattr(module,'get_wan_ips_from_config',lambda db: WAN)
        monkeypatch.setattr(module,'get_config',lambda db,key,*args: GATEWAYS if key=='gateway_ips' else None)
        identity = IdentityConfig({'10.20.0.1': {'vlan': 20}}, {}, [], set(GATEWAYS))
        monkeypatch.setattr(module,'load_identity_config',lambda db: identity)
        yield connection,module
    finally:
        connection.rollback()
        with connection.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        connection.commit()
        connection.close()


def add(connection, count=1, **values):
    from psycopg2.extras import execute_values
    row = dict(timestamp=CUTOFF+timedelta(hours=12),log_type='firewall',rule_action='allow',
               direction='outbound',src_ip='10.20.0.10',dst_ip='198.51.100.20',
               remote_ip='198.51.100.20',geo_country='ZZ',asn_name='Example ASN',
               geo_city=None,rdns=None,threat_score=None,threat_categories=None,
               service_name='Example service',dns_query=None,rule_name='Example rule',
               hostname='example-gateway',event_source=None,ips_signature_id=None,raw_log='')
    row.update(values)
    with connection.cursor() as cur:
        execute_values(cur,'INSERT INTO logs('+','.join(row)+') VALUES %s',
                       [tuple(row.values())]*count)
    connection.commit()


def reference(module,cur,scope):
    """The eight shipped .11 query paths, independent of grouping-set SQL."""
    where,params=scope
    out={}
    for suffix,column,alias,extra in (
        ('countries','geo_country','country',"AND (rule_action='block' OR direction='outbound')"),
        ('services','service_name','service_name',''),
    ):
        cur.execute(f'SELECT {column} AS {alias},rule_action,COUNT(*) AS count FROM logs WHERE {where} '
                    f"AND rule_action IN ('block','allow') AND {column} IS NOT NULL {extra} "
                    f'GROUP BY {column},rule_action ORDER BY count DESC',params)
        rows=[dict(row) for row in cur.fetchall()]
        for action,label in (('block','blocked'),('allow','allowed')):
            out[f'top_{label}_{suffix}']=[{alias:row[alias],'count':row['count']}
                for row in rows if row['rule_action']==action][:10]
    excluded=['0.0.0.0',*WAN]
    out['top_blocked_ips']=module._query_top_blocked_ips(cur,CUTOFF,excluded,scope=scope)
    out['top_blocked_internal_ips']=module._query_top_blocked_internal_ips(cur,CUTOFF,scope=scope)
    out['top_allowed_destinations']=module._query_top_allowed_destinations(cur,CUTOFF,excluded,scope=scope)
    out['top_active_internal_ips']=module._query_top_active_internal_ips(cur,CUTOFF,scope=scope)
    out['top_dns']=module._query_top_dns(cur,CUTOFF,scope=scope)
    cur.execute('SELECT host(l.remote_ip) AS ip,COUNT(*) AS count,MAX(l.geo_country) AS country,'
                'MAX(l.asn_name) AS asn,MAX(l.geo_city) AS city,MAX(l.rdns) AS rdns,'
                'MAX(l.threat_score) AS threat_score,'
                'COALESCE(MAX(l.threat_categories),MAX(t.threat_categories)) AS threat_categories,'
                'MAX(l.timestamp) AS last_seen FROM logs l LEFT JOIN ip_threats t ON l.remote_ip=t.ip '
                f'WHERE {where} AND l.threat_score>50 AND l.remote_ip IS NOT NULL '
                'AND host(l.remote_ip)!=ALL(%s) GROUP BY l.remote_ip '
                'ORDER BY MAX(l.threat_score) DESC,count DESC LIMIT 10',[*params,excluded])
    out['top_threat_ips']=[dict(row) for row in cur.fetchall()]
    for row in out['top_threat_ips']:
        if row['last_seen']:
            row['last_seen']=row['last_seen'].isoformat()
    module._annotate_internal_ips(out['top_blocked_internal_ips'],out['top_active_internal_ips'])
    return out


def run(connection,module,scope=None):
    from psycopg2.extras import RealDictCursor
    scope=scope or ('timestamp >= %s',[CUTOFF])
    with connection.cursor(cursor_factory=RealDictCursor) as cur:
        old=reference(module,cur,scope)
        new=module._query_dashboard_tables(cur,CUTOFF,scope=scope)
    # Existing top-N ties have no ordering guarantee. Fixtures below avoid
    # boundary ties; comparing row dictionaries still validates all metadata.
    def ordered(result):
        return {key:sorted(rows,key=lambda row:json.dumps(row,sort_keys=True)) for key,rows in result.items()}
    assert ordered(new)==ordered(old)
    connection.commit()
    return new


def test_weighted_tables_preserve_fields_exclusions_inventory_and_masks(pg_tables):
    connection,module=pg_tables
    add(connection,11,src_ip='198.51.100.10',rule_action='block',threat_score=70,
        threat_categories=['log-category'],geo_city='Example city',rdns='peer.example.test')
    add(connection,7,src_ip='10.20.0.10',rule_action='block',geo_country=None,asn_name=None)
    add(connection,6,src_ip='10.20.0.10/24',rule_action='block',service_name='',geo_country='')
    add(connection,5,src_ip='fd00:db8::10',rule_action='block',remote_ip='fd00:db8::20',threat_score=95)
    add(connection,4,src_ip='2001:db8::10',rule_action='block',dst_ip='2001:db8::20')
    add(connection,3,src_ip=GATEWAYS[0],rule_action='block')
    add(connection,19,src_ip=GATEWAYS[0])  # Exclude from active, retain blocked.
    add(connection,23,src_ip=WAN[0],rule_action='block',dst_ip=WAN[0],remote_ip=WAN[0],threat_score=99)
    add(connection,17,dst_ip=WAN[0],direction='inbound')
    add(connection,13,log_type='dns',dns_query='query.example.test',rule_action=None)
    add(connection,2,log_type='dns',dns_query='',rule_action='block')
    add(connection,29,direction='inbound',geo_country='YY',service_name='Inbound service')
    add(connection,31,remote_ip='198.51.100.30',threat_score=65,threat_categories=None)
    add(connection,37,remote_ip='198.51.100.40',threat_score=60,threat_categories=[])
    add(connection,100,timestamp=CUTOFF-timedelta(seconds=1),threat_score=100)
    with connection.cursor() as cur:
        cur.execute("INSERT INTO ip_threats VALUES('198.51.100.30',ARRAY['cache-category']),"
                    "('198.51.100.40',ARRAY['must-not-replace-empty-array'])")
        cur.execute("INSERT INTO unifi_clients VALUES"
                    "('10.20.0.10','Stale label',NULL,NULL,'2025-01-01'),"
                    "('10.20.0.10',NULL,'Fresh host',NULL,'2026-01-02'),"
                    "('fd00:db8::10',NULL,NULL,'Example manufacturer','2026-01-02')")
    connection.commit()
    result=run(connection,module)
    internal=result['top_blocked_internal_ips']
    assert sum(row['ip']=='10.20.0.10' for row in internal)==2
    assert next(row for row in internal if row['ip']==GATEWAYS[0])['vlan']==20
    assert all(row['ip']!=GATEWAYS[0] for row in result['top_active_internal_ips'])
    assert next(row for row in result['top_threat_ips'] if row['ip']=='198.51.100.30')['threat_categories']==['cache-category']
    assert next(row for row in result['top_threat_ips'] if row['ip']=='198.51.100.40')['threat_categories']==[]


def test_security_profile_retains_protected_rows_and_does_not_materialize_payload(pg_tables):
    connection,module=pg_tables
    add(connection,10,rule_name='Routine',raw_log='Routine raw payload'*100)
    add(connection,3,rule_name='Routine',event_source='unifi_ips',threat_score=85)
    add(connection,2,rule_name='Routine',raw_log='CEF:0|Example|Threat Detected|')
    add(connection,7,rule_name='Other',rule_action='block')
    groups=[{'conditions':[{'field':'rule_name_exact','operator':'include','value':'Routine'}]}]
    scope=module._stats_scope(CUTOFF,json.dumps(groups))
    result=run(connection,module,scope)
    assert sum(row['count'] for row in result['top_allowed_destinations'])==5
    from dashboard_tables import dimension_tables_sql,address_tables_sql
    assert 'SELECT * FROM logs' not in dimension_tables_sql(scope[0])
    assert 'SELECT * FROM logs' not in address_tables_sql(scope[0])


def test_empty_and_zero_contribution_groups_produce_empty_lists(pg_tables):
    connection,module=pg_tables
    assert all(not rows for rows in run(connection,module).values())
    add(connection,5,rule_action=None,log_type='system',dns_query='not-a-dns-event',
        threat_score=None,remote_ip=None)
    assert all(not rows for rows in run(connection,module).values())


def test_top_ten_and_independent_metadata_maxima_are_unchanged(pg_tables):
    connection,module=pg_tables
    for number in range(20):
        country='A'+chr(ord('A')+number)
        add(connection,20-number,src_ip=f'198.51.100.{number+1}',dst_ip=f'203.0.113.{number+1}',
            remote_ip=f'203.0.113.{number+1}',rule_action='block',threat_score=90-number,
            service_name=f'service-{number}',geo_country=country,
            log_type='dns',dns_query=f'q-{number}.example.test')
        add(connection,2*(20-number),src_ip=f'10.20.0.{number+10}',dst_ip=f'203.0.113.{number+1}',
            service_name=f'service-{number}',geo_country=country)
        add(connection,20-number,src_ip=f'10.20.0.{number+10}',rule_action='block',
            service_name=f'service-{number}',geo_country=country)
    result=run(connection,module)
    assert all(len(result[key])==10 for key in result)
    add(connection,5,src_ip='198.51.100.100',remote_ip='198.51.100.100',
        rule_action='block',threat_score=80,geo_country='AA',asn_name='Zeta',
        geo_city='Alpha',rdns='z.example.test',threat_categories=['z'],timestamp=CUTOFF+timedelta(hours=1))
    add(connection,7,src_ip='198.51.100.100',remote_ip='198.51.100.100',
        rule_action='block',threat_score=99,geo_country='ZZ',asn_name='Alpha',
        geo_city='Zeta',rdns='a.example.test',threat_categories=['a'],timestamp=CUTOFF+timedelta(hours=2))
    result=run(connection,module)
    peer=next(row for row in result['top_threat_ips'] if row['ip']=='198.51.100.100')
    assert (peer['country'],peer['asn'],peer['city'],peer['rdns'],peer['threat_categories'])==(
        'ZZ','Zeta','Zeta','z.example.test',['z'])


@pytest.mark.skipif(os.environ.get('RUN_DASHBOARD_TABLE_BENCHMARK')!='1',reason='opt-in synthetic PostgreSQL benchmark')
@pytest.mark.parametrize('high_cardinality',[False,True],ids=['repeated_groups','many_distinct_groups'])
def test_wide_window_table_measurement(pg_tables,record_property,high_cardinality):
    connection,module=pg_tables
    with connection.cursor() as cur:
        cur.execute('''INSERT INTO logs(timestamp,log_type,rule_action,direction,src_ip,dst_ip,
                       remote_ip,geo_country,asn_name,geo_city,rdns,threat_score,
                       threat_categories,service_name,dns_query,rule_name,hostname,raw_log)
            SELECT '2026-01-02'::timestamptz+(i%%86400)*interval '1 second',
                   CASE WHEN i%%7=0 THEN 'dns' ELSE 'firewall' END,
                   CASE WHEN i%%5=0 THEN 'block' ELSE 'allow' END,'outbound',
                   CASE WHEN i%%3=0 THEN '198.18.0.0'::inet+(i%%modulus)
                        ELSE '10.20.0.0'::inet+(i%%modulus) END,
                   '198.19.0.0'::inet+(i%%modulus),'198.19.0.0'::inet+(i%%modulus),
                   'ZZ','Example ASN','Example city','peer.example.test',
                   CASE WHEN i%%997=0 THEN 85 ELSE NULL END,NULL::text[],
                   'service-'||(i%%8),CASE WHEN i%%7=0 THEN 'q-'||
                        (CASE WHEN high_cardinality THEN i ELSE i%%9 END)||'.example.test' ELSE NULL END,
                   'Example rule','example-gateway',repeat(md5(i::text),16)
            FROM generate_series(1,500000) i
            CROSS JOIN (SELECT %s::integer AS modulus,%s::boolean AS high_cardinality) p''',
                    [65536 if high_cardinality else 2048,high_cardinality])
        cur.execute('ANALYZE logs')
    connection.commit()
    from psycopg2.extras import RealDictCursor
    measurements={'old':[],'new':[]}
    calls={}
    statements={}
    results={}
    class RecordingCursor:
        def __init__(self,cur):self.cur=cur;self.queries=[]
        def execute(self,query,params=None):self.queries.append((query,params));return self.cur.execute(query,params)
        def __getattr__(self,name):return getattr(self.cur,name)
    for cycle in range(3):
        for label in (('old','new') if cycle%2==0 else ('new','old')):
            with connection.cursor(cursor_factory=RealDictCursor) as cur:
                recording=RecordingCursor(cur)
                begin=time.perf_counter()
                result=(reference(module,recording,('timestamp >= %s',[CUTOFF])) if label=='old'
                        else module._query_dashboard_tables(recording,CUTOFF))
                measurements[label].append((time.perf_counter()-begin)*1000)
                calls[label]=len(recording.queries)
                statements[label]=recording.queries
                results[label]=result
                assert all(len(rows)<=10 for rows in result.values())
            connection.commit()
    plans={}
    for label in ('old','new'):
        plans[label]=[]
        with connection.cursor() as cur:
            for query,params in statements[label]:
                cur.execute('EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) '+query,params)
                explained=cur.fetchone()[0][0]
                root=explained['Plan']
                def scans(node):
                    return int(node.get('Relation Name')=='logs')+sum(scans(child) for child in node.get('Plans',[]))
                plans[label].append({'execution_ms':explained['Execution Time'],'logs_scan_nodes':scans(root),
                    **{key:root.get(key,0) for key in ('Shared Hit Blocks','Shared Read Blocks',
                                                     'Local Hit Blocks','Local Read Blocks',
                                                     'Temp Read Blocks','Temp Written Blocks')}})
        connection.commit()
    record_property('fixture_rows',500000)
    record_property('high_cardinality',high_cardinality)
    record_property('reference_query_count',calls['old'])
    record_property('new_query_count',calls['new'])
    record_property('reference_median_ms',round(statistics.median(measurements['old']),3))
    record_property('new_median_ms',round(statistics.median(measurements['new']),3))
    record_property('query_plans',json.dumps(plans))
    assert calls['old']==8
    assert calls['new']==3
    assert sum(plan['logs_scan_nodes'] for plan in plans['new'])==3
    for key in results['old']:
        # Specific labels at an equal-count boundary were never deterministic;
        # retain exact top-N metric sequences and metadata for shared keys.
        def metrics(rows):
            return [(row['count'],row.get('threat_score') if key=='top_threat_ips' else None) for row in rows]
        assert metrics(results['old'][key])==metrics(results['new'][key])
        row_key='ip' if 'ip' in (results['new'][key][0] if results['new'][key] else {}) else (
            'country' if key.endswith('countries') else 'service_name' if key.endswith('services') else 'dns_query')
        shared={row[row_key]:row for row in results['old'][key]}
        for row in results['new'][key]:
            if row[row_key] in shared:
                assert row==shared[row[row_key]]
