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

# C2 framework queries
C2_QUERIES = [
    'tag:c2',
    'product:"Cobalt Strike Beacon"',
    'product:"Cobalt Strike"',
    'product:"Metasploit"',
    'product:"Covenant"',
    'product:"Sliver"',
    'product:"Mythic"',
    'product:"Brute Ratel"',
    'product:"Havoc"',
    'product:"PoshC2"',
    'product:"Merlin"',
    'product:"Deimos"',
    'http.html_hash:-1957161625',  
]

def load_state():
    """Load the last run state, or return None for first run."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return None

def save_state(last_run, total_indicators):
    """Save current run state."""
    state = {
        'last_run': last_run,
        'total_indicators_collected': total_indicators
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def load_master_iocs():
    """Load existing master IOC list for deduplication."""
    if MASTER_FILE.exists():
        with open(MASTER_FILE) as f:
            data = json.load(f)
            return {f"{i['ip']}:{i['port']}" for i in data.get('indicators', [])}
    return set()

def load_master_data():
    """Load full master data."""
    if MASTER_FILE.exists():
        with open(MASTER_FILE) as f:
            return json.load(f)
    return {'indicators': []}

def fetch_c2_data(after_date=None):
    """
    Fetch C2 indicators from Shodan.
    
    Args:
        after_date: Only fetch results after this date (YYYY-MM-DD format)
                   If None, fetches without date filter (limited by Shodan)
    """
    results = []
    
    for query in C2_QUERIES:
        # Add date filter if specified
        if after_date:
            full_query = f'{query} after:{after_date}'
        else:
            full_query = query
        
        print(f"Querying: {full_query}")
        
        try:
            # Use search_cursor for pagination on initial backfill
            # Use regular search for incremental (fewer results expected)
            if after_date is None:
                # First run - get more results with cursor
                count = 0
                for match in api.search_cursor(full_query):
                    results.append(parse_match(match, query))
                    count += 1
                    if count >= 500:  # Limit per query to manage API credits
                        break
            else:
                # Incremental - regular search is fine
                search = api.search(full_query, limit=200)
                for match in search['matches']:
                    results.append(parse_match(match, query))
                    
        except shodan.APIError as e:
            print(f"  Error: {e}")
            continue
        
        print(f"  Found {len(results)} total results so far")
    
    return results

def parse_match(match, query):
    """Parse a Shodan match into our indicator format."""
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
    """Remove duplicates based on IP:port combination."""
    unique = []
    seen = set(existing_keys)
    
    for r in new_results:
        key = f"{r['ip']}:{r['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    
    return unique

def main():
    # Create directories
    DATA_DIR.mkdir(exist_ok=True)
    ARCHIVE_DIR.mkdir(exist_ok=True)
    
    # Check state
    state = load_state()
    existing_keys = load_master_iocs()
    now = datetime.utcnow()
    
    if state is None:
        # First run - backfill last 30 days
        print("=" * 50)
        print("FIRST RUN: Backfilling last 30 days of C2 data")
        print("=" * 50)
        after_date = (now - timedelta(days=30)).strftime('%Y-%m-%d')
        c2_data = fetch_c2_data(after_date=after_date)
        is_first_run = True
    else:
        # Incremental run - fetch since last run
        last_run = datetime.fromisoformat(state['last_run'].replace('Z', ''))
        print("=" * 50)
        print(f"INCREMENTAL RUN: Fetching new data since {state['last_run']}")
        print("=" * 50)
        after_date = last_run.strftime('%Y-%m-%d')
        c2_data = fetch_c2_data(after_date=after_date)
        is_first_run = False
    
    # Deduplicate against existing data
    new_indicators = deduplicate(c2_data, existing_keys)
    print(f"\nNew unique indicators: {len(new_indicators)}")
    
    # Load existing master and append new
    master_data = load_master_data()
    master_data['indicators'].extend(new_indicators)
    master_data['last_updated'] = now.isoformat() + 'Z'
    master_data['total_count'] = len(master_data['indicators'])
    
    # Save master file (all IOCs)
    with open(MASTER_FILE, 'w') as f:
        json.dump(master_data, f, indent=2)
    print(f"Master file updated: {master_data['total_count']} total indicators")
    
    # Save current run feed (just new IOCs)
    feed_output = {
        'generated_at': now.isoformat() + 'Z',
        'run_type': 'backfill' if is_first_run else 'incremental',
        'new_indicators_count': len(new_indicators),
        'indicators': new_indicators
    }
    
    with open(FEED_FILE, 'w') as f:
        json.dump(feed_output, f, indent=2)
    
    # Archive this run
    date_str = now.strftime('%Y-%m-%d_%H%M')
    archive_file = ARCHIVE_DIR / f'c2_feed_{date_str}.json'
    with open(archive_file, 'w') as f:
        json.dump(feed_output, f, indent=2)
    print(f"Archived to: {archive_file}")
    
    # Update state
    save_state(now.isoformat() + 'Z', master_data['total_count'])
    
    # Print summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Run type: {'Initial backfill (30 days)' if is_first_run else 'Incremental update'}")
    print(f"New indicators this run: {len(new_indicators)}")
    print(f"Total indicators in master: {master_data['total_count']}")
    
    # Show sample of new indicators
    if new_indicators:
        print(f"\nSample of new indicators:")
        for ind in new_indicators[:5]:
            print(f"  - {ind['ip']}:{ind['port']} | {ind['product']} | {ind['country']}")

if __name__ == '__main__':
    main()
