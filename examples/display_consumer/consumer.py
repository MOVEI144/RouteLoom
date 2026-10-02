#!/usr/bin/env python3
"""API1 display-style consumer: commit records and cursor atomically before polling again."""
from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import time
from pathlib import Path

MAX_RECORDS = 4096


def open_db(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY, network TEXT, origin TEXT, session TEXT,
            sequence TEXT, record TEXT,
            UNIQUE(network, origin, session, sequence));
        CREATE TABLE IF NOT EXISTS cursors (network TEXT PRIMARY KEY, cursor TEXT NOT NULL);
    ''')
    return db


def save_batch(db: sqlite3.Connection, network: str, result: dict) -> None:
    with db:
        for record in result['records']:
            message = record['message']
            db.execute('INSERT OR IGNORE INTO records(network,origin,session,sequence,record) VALUES (?,?,?,?,?)',
                       (record['network'], record['origin'], message['session'], message['sequence'],
                        json.dumps(record, separators=(',', ':'))))
        db.execute('DELETE FROM records WHERE id NOT IN (SELECT id FROM records ORDER BY id DESC LIMIT ?)',
                   (MAX_RECORDS,))
        db.execute('INSERT INTO cursors VALUES (?,?) ON CONFLICT(network) DO UPDATE SET cursor=excluded.cursor',
                   (network, result['next_cursor']))


def poll(path: Path, network: str, cursor: str | None) -> dict:
    params = {'network': network, 'limit': 32}
    params.update({'cursor': cursor} if cursor else {'from': 'earliest'})
    request = {'v': 1, 'request_id': 'display-read', 'method': 'messages.read', 'params': params}
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        conn.sendall(b'API1 ' + json.dumps(request, separators=(',', ':')).encode() + b'\n')
        with conn.makefile('rb') as reader:
            line = reader.readline(65537)
    if len(line) > 65536 or not line.endswith(b'\n'):
        raise ValueError('invalid response line')
    reply = json.loads(line)
    if reply.get('v') != 1 or reply.get('request_id') != 'display-read':
        raise ValueError('response correlation failed')
    if not reply.get('ok'):
        # Keep the durable cursor unchanged; resumption requires an explicit operator choice.
        raise ValueError(json.dumps(reply.get('error'), ensure_ascii=False))
    return reply['result']


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--network', required=True)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--resume-cursor')
    args = parser.parse_args()
    if len(args.network) != 16 or any(c not in '0123456789abcdefABCDEF' for c in args.network):
        parser.error('--network requires 16 hex characters')
    network = args.network.lower()
    db = None
    try:
        db = open_db(args.db)
        if args.resume_cursor is not None:
            with db:
                db.execute('INSERT INTO cursors VALUES (?,?) ON CONFLICT(network) DO UPDATE SET cursor=excluded.cursor',
                           (network, args.resume_cursor))
        while True:
            row = db.execute('SELECT cursor FROM cursors WHERE network=?', (network,)).fetchone()
            result = poll(args.socket, network, row[0] if row else None)
            save_batch(db, network, result)
            print(f"saved {len(result['records'])} records", flush=True)
            if args.once:
                return 0
            if not result['more']:
                time.sleep(1)
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as error:
        print(f'consumer stopped: {error}')
        return 1
    finally:
        if db is not None:
            db.close()


if __name__ == '__main__':
    raise SystemExit(main())
