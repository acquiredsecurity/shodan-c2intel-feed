#!/usr/bin/env python3
"""
Shodan C2 Intelligence Feed
- First run: Fetches last 30 days of C2 indicators
- Subsequent runs: Fetches only new indicators since last run
"""

import shodan
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

API_KEY = os.environ['SHODAN_API_KEY']
api = shodan.Shodan(API_KEY)

# Paths
DATA_DIR = Path('data')
ARCHIVE_DIR = DATA_DIR / 'archive'
STATE_FILE = DATA_DIR / 'state.json'
FEED_FILE = DATA_DIR / 'c2_feed.json'
MASTER_FILE = DATA_DIR / 'c2_master.json'

# C2 framework queries (no tag: filter - requires Corporate API)
C2_QUERIES = [
    # Cobalt Strike
    'product:"Cobalt Strike Beacon"',
    'product:"Cobalt Strike"',
    'ssl.cert.serial:146473198',
    'http.html_hash:-1957161625',
    'ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2',
    
    # Other C2 Frameworks
    'product:"Metasploit"',
    'product:"Covenant"',
    'product:"Sliver"',
    'product:"Mythic"',
    'product:"Brute Ratel"',
    'product:"Havoc"',
    'product:"PoshC2"',
    'product:"Merlin C2"',
    'product:"Deimos"',
    'product:"Empire"',
    'product:"Meterpreter"',
    
    # JARM fingerprints
    'ssl.jarm:2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da',
    'ssl.jarm:00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64',
    
    # HTTP characteristics
    'http.favicon.hash:627523027',
    'http.title:"Deimos C2"',
]

def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return None

def save_state(last_run, total_indicators):
    state = {
        'last_run': last_run,
        'total_indicators_collected': total_indicators
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def load_master_iocs():
    if MASTER_FILE.exists():
        with open(MASTER_FILE) as f:
            data = json.load(f)
            return {f"{i['ip']}:{i['port']}" for i in data.get('indicators', [])}
    return set()

def load_master_data():
    if MASTER_FILE.exists():
        with open(MASTER_FILE) as f:
            return json.load(f)
    return {'indicators': []}

def fetch_c2_data(after_date=None):
    results = []
    
    for query in C2_QUERIES:
        if after_date:
            full_query = f'{query} after:{after_date}'
        else:
            full_query = query
        
        print(f"Querying: {full_query}")
        
        try:
            if after_date is None:
                count = 0
                for match in api.search_cursor(full_query):
                    results.append(parse_match(match, query))
                    count += 1
                    if count >= 500:
                        break
                print(f"  Found {count} results")
            else:
                search = api.search(full_query, limit=200)
                print(f"  Found {len(search['matches'])} results")
                for match in search['matches']:
                    results.append(parse_match(match, query))
                    
        except shodan.APIError as e:
            print(f"  Error: {e}")
            continue
    
    print(f"\nTotal raw results: {len(results)}")
    return results

def parse_match(match, query):
    return {
        'ip': match.get('ip_str'),
        'port': match.get('port'),
        'product': match.get('product'),
        'tags': match.get('tags', []),
        'org': match.get('org'),
        'asn': match.get('asn'),
        'isp': match.get('isp'),
        'country': match.get('location', {}).get('country_code'),
        'city': match.get('location', {}).get('city'),
        'last_seen': match.get('timestamp'),
        'hostnames': match.get('hostnames', []),
        'domains': match.get('domains', []),
        'ssl_cn': match.get('ssl', {}).get('cert', {}).get('subject', {}).get('CN'),
        'ssl_issuer': match.get('ssl', {}).get('cert', {}).get('issuer', {}).get('O'),
        'ssl_fingerprint': match.get('ssl', {}).get('cert', {}).get('fingerprint', {}).get('sha256'),
        'jarm': match.get('ssl', {}).get('jarm'),
        'http_title': match.get('http', {}).get('title'),
        'http_server': match.get('http', {}).get('server'),
        'os': match.get('os'),
        'query_matched': query,
        'collected_at': datetime.utcnow().isoformat() + 'Z'
    }

def deduplicate(new_results, existing_keys):
    unique = []
    seen = set(existing_keys)
    
    for r in new_results:
        key = f"{r['ip']}:{r['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    
    return unique

def main():
    DATA_DIR.mkdir(exist_ok=True)
    ARCHIVE_DIR.mkdir(exist_ok=True)
    
    state = load_state()
    existing_keys = load_master_iocs()
    now = datetime.utcnow()
    
    if state is None:
        print("=" * 50)
        print("FIRST RUN: Backfilling last 30 days of C2 data")
        print("=" * 50)
        after_date = (now - timedelta(days=30)).strftime('%Y-%m-%d')
        c2_data = fetch_c2_data(after_date=after_date)
        is_first_run = True
    else:
        last_run = datetime.fromisoformat(state['last_run'].replace('Z', ''))
        print("=" * 50)
        print(f"INCREMENTAL RUN: Fetching new data since {state['last_run']}")
        print("=" * 50)
        after_date = last_run.strftime('%Y-%m-%d')
        c2_data = fetch_c2_data(after_date=after_date)
        is_first_run = False
    
    new_indicators = deduplicate(c2_data, existing_keys)
    print(f"\nNew unique indicators: {len(new_indicators)}")
    
    master_data = load_master_data()
    master_data['indicators'].extend(new_indicators)
    master_data['last_updated'] = now.isoformat() + 'Z'
    master_data['total_count'] = len(master_data['indicators'])
    
    with open(MASTER_FILE, 'w') as f:
        json.dump(master_data, f, indent=2)
    print(f"Master file updated: {master_data['total_count']} total indicators")
    
    feed_output = {
        'generated_at': now.isoformat() + 'Z',
        'run_type': 'backfill' if is_first_run else 'incremental',
        'new_indicators_count': len(new_indicators),
        'indicators': new_indicators
    }
    
    with open(FEED_FILE, 'w') as f:
        json.dump(feed_output, f, indent=2)
    
    date_str = now.strftime('%Y-%m-%d_%H%M')
    archive_file = ARCHIVE_DIR / f'c2_feed_{date_str}.json'
    with open(archive_file, 'w') as f:
        json.dump(feed_output, f, indent=2)
    print(f"Archived to: {archive_file}")
    
    save_state(now.isoformat() + 'Z', master_data['total_count'])
    
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Run type: {'Initial backfill (30 days)' if is_first_run else 'Incremental update'}")
    print(f"New indicators this run: {len(new_indicators)}")
    print(f"Total indicators in master: {master_data['total_count']}")
    
    if new_indicators:
        print(f"\nSample of new indicators:")
        for ind in new_indicators[:5]:
            print(f"  - {ind['ip']}:{ind['port']} | {ind['product']} | {ind['country']}")

if __name__ == '__main__':
    main()
