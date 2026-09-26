"""Versioned SQLite event capture; replay never executes captured commands."""
import json
import sqlite3
from pathlib import Path

from .model import State, reduce

SCHEMA_VERSION = 1


class Capture:
    def __init__(self, path: Path, capture_id: str):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=False)
        (self.path / 'manifest.json').write_text(json.dumps({
            'schema_version': SCHEMA_VERSION, 'capture_id': capture_id,
            'max_uncommitted_seconds': 1}), encoding='utf-8')
        self.db = sqlite3.connect(self.path / 'data.sqlite')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA user_version=1')
        self.db.executescript('''
            CREATE TABLE events(seq INTEGER PRIMARY KEY, t_mono_ns INTEGER NOT NULL,
              t_unix_ns INTEGER NOT NULL, source TEXT, source_epoch TEXT,
              source_seq INTEGER, kind TEXT NOT NULL, scope TEXT, payload_json TEXT NOT NULL);
            CREATE TABLE metric_samples(seq INTEGER PRIMARY KEY, series TEXT, value_json TEXT);
            CREATE TABLE trial_runs(id TEXT PRIMARY KEY, plan_json TEXT);
            CREATE TABLE trial_messages(id TEXT PRIMARY KEY, result_json TEXT);
            CREATE TABLE checkpoints(seq INTEGER PRIMARY KEY, t_mono_ns INTEGER, state_json TEXT);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value_json TEXT);
        ''')
        self.seq = 0

    def add(self, event: dict, clock):
        self.seq += 1
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', (
            self.seq, clock.mono_ns, clock.unix_ms * 1_000_000,
            event['source'], event.get('source_epoch'), event.get('source_seq'),
            event['kind'], event.get('scope'), json.dumps({'schema_version': 1, **event})))
        if event['kind'] == 'sample':
            self.db.execute('INSERT INTO metric_samples VALUES (?,?,?)',
                            (self.seq, event['payload']['series'], json.dumps(event['payload'])))
        # Important operation boundaries can explicitly call flush().
        if self.seq % 1000 == 0:
            self.flush()

    def flush(self):
        self.db.commit()

    def close(self):
        self.flush()
        self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def replay(path: Path, until_seq=None) -> State:
    manifest = json.loads((Path(path) / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['schema_version'] != SCHEMA_VERSION:
        raise ValueError('unsupported capture schema')
    db = sqlite3.connect(f'file:{Path(path) / "data.sqlite"}?mode=ro', uri=True)
    try:
        if db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
            raise ValueError('unsupported SQLite schema')
        state = State()
        for seq, payload in db.execute('SELECT seq,payload_json FROM events ORDER BY seq'):
            if until_seq is not None and seq > until_seq:
                break
            event = json.loads(payload)
            if event['schema_version'] != SCHEMA_VERSION:
                raise ValueError('unsupported event schema')
            reduce(state, event)
        return state
    finally:
        db.close()
