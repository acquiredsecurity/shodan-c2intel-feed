#!/usr/bin/env python3
"""
Shodan C2 Intelligence Feed
- First run: Fetches current C2 indicators (no date filter)
- Subsequent runs: Compares against existing data, adds new ones
"""

import shodan
import json
import os
from datetime import datetime
from pathlib import Path

API_KEY = os.environ['SHODAN_API_KEY']
api = shodan.Shodan(API_KEY)

# Paths
DATA_DIR = Path('data')
ARCHIVE_DIR = DATA_DIR / 'archive'
STATE_FILE = DATA_DIR / 'state.json'
FEED_FILE = DATA_DIR / 'c2_feed.json'
MASTER_FILE = DATA_DIR / 'c2_master.json'

# C2 framework queries - trimmed to top 10
C2_QUERIES = [
    'product:"Cobalt Strike"',
    'product:"Metasploit"',
    'product:"Sliver"',
    'product:"Brute Ratel"',
    'product:"Havoc"',
    'product:"Mythic"',
    'http.html_hash:-1957161625',
    'ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2',
    'ssl.jarm:2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da',
    'http.favicon.hash:627523027',
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

def fetch_c2_data():
    """Fetch C2 indicators from Shodan without date filter."""
    results = []
    
    for query in C2_QUERIES:
        print(f"Querying: {query}")
        
        try:
            # Use regular search with limit
            search = api.search(query, limit=100)
            count = len(search['matches'])
            print(f"  Found {count} results")
            
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
    
    is_first_run = state is None
    
    if is_first_run:
        print("=" * 50)
        print("FIRST RUN: Fetching current C2 data")
        print("=" * 50)
    else:
        print("=" * 50)
        print(f"INCREMENTAL RUN: Checking for new C2s")
        print(f"Last run: {state['last_run']}")
        print(f"Existing indicators: {len(existing_keys)}")
        print("=" * 50)
    
    c2_data = fetch_c2_data()
    
    # Deduplicate against existing data
    new_indicators = deduplicate(c2_data, existing_keys)
    print(f"\nNew unique indicators: {len(new_indicators)}")
    
    # Load existing master and append new
    master_data = load_master_data()
    master_data['indicators'].extend(new_indicators)
    master_data['last_updated'] = now.isoformat() + 'Z'
    master_data['total_count'] = len(master_data['indicators'])
    
    # Save master file
    with open(MASTER_FILE, 'w') as f:
        json.dump(master_data, f, indent=2)
    print(f"Master file updated: {master_data['total_count']} total indicators")
    
    # Save current run feed
    feed_output = {
        'generated_at': now.isoformat() + 'Z',
        'run_type': 'first_run' if is_first_run else 'incremental',
        'new_indicators_count': len(new_indicators),
        'indicators': new_indicators
    }
    
    with open(FEED_FILE, 'w') as f:
        json.dump(feed_output, f, indent=2)
    
    # Archive
    date_str = now.strftime('%Y-%m-%d_%H%M')
    archive_file = ARCHIVE_DIR / f'c2_feed_{date_str}.json'
    with open(archive_file, 'w') as f:
        json.dump(feed_output, f, indent=2)
    print(f"Archived to: {archive_file}")
    
    # Update state
    save_state(now.isoformat() + 'Z', master_data['total_count'])
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Run type: {'First run' if is_first_run else 'Incremental'}")
    print(f"New indicators this run: {len(new_indicators)}")
    print(f"Total indicators in master: {master_data['total_count']}")
    
    if new_indicators:
        print(f"\nSample of new indicators:")
        for ind in new_indicators[:5]:
            print(f"  - {ind['ip']}:{ind['port']} | {ind['product']} | {ind['country']}")

if __name__ == '__main__':
    main()
