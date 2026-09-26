"""Versioned SQLite event capture; replay never executes captured commands."""
import json
import os
import sqlite3
from dataclasses import asdict
from pathlib import Path

from .model import State, reduce

SCHEMA_VERSION = 1


class Capture:
    def __init__(self, path: Path, capture_id: str):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=False)
        self.manifest = {'schema_version': SCHEMA_VERSION, 'capture_id': capture_id,
                         'max_uncommitted_seconds': 1, 'closed': False}
        (self.path / 'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')
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
        self.state = State()
        self.last_checkpoint_ns = 0

    def add(self, event: dict, clock):
        self.seq += 1
        if self.seq == 1:
            self.last_checkpoint_ns = clock.mono_ns
        self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', (
            self.seq, clock.mono_ns, clock.unix_ms * 1_000_000,
            event['source'], event.get('source_epoch'), event.get('source_seq'),
            event['kind'], event.get('scope'), json.dumps({'schema_version': 1, **event})))
        if event['kind'] == 'sample':
            self.db.execute('INSERT INTO metric_samples VALUES (?,?,?)',
                            (self.seq, event['payload']['series'], json.dumps(event['payload'])))
        reduce(self.state, event)
        if self.seq % 5000 == 0 or clock.mono_ns - self.last_checkpoint_ns >= 30_000_000_000:
            # Checkpoints share the event transaction, so a crash cannot expose a future state.
            snapshot = asdict(self.state)
            snapshot['retired_epochs'] = {k: sorted(v) for k, v in self.state.retired_epochs.items()}
            self.db.execute('INSERT INTO checkpoints VALUES (?,?,?)',
                            (self.seq, clock.mono_ns, json.dumps(snapshot)))
            self.last_checkpoint_ns = clock.mono_ns
        # Important operation boundaries can explicitly call flush().
        if self.seq % 1000 == 0:
            self.flush()

    def flush(self):
        self.db.commit()

    def close(self):
        self.flush()
        self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self.db.close()
        self.manifest['closed'] = True
        tmp = self.path / 'manifest.json.tmp'
        tmp.write_text(json.dumps(self.manifest), encoding='utf-8')
        os.replace(tmp, self.path / 'manifest.json')

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
        checkpoint = db.execute('SELECT seq,state_json FROM checkpoints WHERE seq<=? ORDER BY seq DESC LIMIT 1',
                                (until_seq if until_seq is not None else 2**63 - 1,)).fetchone()
        start = checkpoint[0] if checkpoint else 0
        if checkpoint:
            data = json.loads(checkpoint[1])
            data['retired_epochs'] = {k: set(v) for k, v in data['retired_epochs'].items()}
            data['sources'] = {k: tuple(v) for k, v in data['sources'].items()}
            state = State(**data)
        else:
            state = State()
        for seq, payload in db.execute('SELECT seq,payload_json FROM events WHERE seq>? ORDER BY seq', (start,)):
            if until_seq is not None and seq > until_seq:
                break
            event = json.loads(payload)
            if event['schema_version'] != SCHEMA_VERSION:
                raise ValueError('unsupported event schema')
            reduce(state, event)
        if not manifest.get('closed', False):
            # The last committed event is reliable; an unfinished tail is not.
            state.gaps.append({'reason': 'UncleanEnd'})
        return state
    finally:
        db.close()
