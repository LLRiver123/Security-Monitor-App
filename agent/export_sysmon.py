"""Export Sysmon events to CSV using the existing collector.

Usage:
  python agent/export_sysmon.py --out data/sysmon_raw.csv --max 10000

This script uses `agent.collector.sysmon_event_stream()` to gather events and
writes a flattened CSV with common fields plus a `text` summary column which can
be used for embedding training.
"""
from __future__ import annotations

import csv
import argparse
from pathlib import Path
from typing import Dict

try:
    from collector import sysmon_event_stream
except Exception as e:
    sysmon_event_stream = None

from ai.analyzer import _event_to_text


def flatten_event(ev: Dict) -> Dict:
    data = ev.get('data', {}) if ev else {}
    out = {
        'event_id': ev.get('event_id') if ev else None,
        'time': ev.get('time') if ev else None,
        'source': ev.get('source') if ev else None,
        'computer': ev.get('computer') if ev else None,
        'xml': ev.get('xml') if ev else None,
    }
    # include all keys from data
    for k, v in (data.items() if data else []):
        out[k] = v

    # text summary for embedding/training
    out['text'] = _event_to_text(ev or {})
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', default='data/sysmon_raw.csv')
    p.add_argument('--max', type=int, default=10000)
    p.add_argument('--sample', type=int, default=1000, 
                   help='Number of events to sample for field discovery')
    args = p.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if sysmon_event_stream is None:
        print('agent.collector.sysmon_event_stream not available.')
        return

    # Phase 1: Discover all possible fields
    print(f'Sampling {args.sample} events to discover fields...')
    all_fields = set(['event_id', 'time', 'source', 'computer', 'xml', 'text'])
    sample_count = 0
    
    for ev in sysmon_event_stream():
        if 'error' in ev:
            continue
        flat = flatten_event(ev)
        all_fields.update(flat.keys())
        sample_count += 1
        if sample_count >= args.sample:
            break
    
    fieldnames = sorted(all_fields)  # Sort for consistent column order
    print(f'Discovered {len(fieldnames)} fields: {fieldnames[:10]}...')

    # Phase 2: Export with all known fields
    print('Starting export...')
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        count = 0
        for ev in sysmon_event_stream():
            if 'error' in ev:
                print('collector error:', ev['error'])
                continue
            
            flat = flatten_event(ev)
            writer.writerow(flat)
            count += 1
            
            if count % 100 == 0:
                print(f'Wrote {count} events...')
            if args.max and count >= args.max:
                break

    print('Export finished. Total events:', count)


if __name__ == '__main__':
    main()
