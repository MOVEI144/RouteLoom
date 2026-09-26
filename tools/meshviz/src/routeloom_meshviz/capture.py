"""Versioned SQLite event capture; replay never executes captured commands."""
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import asdict, fields
from pathlib import Path

from .model import State, reduce

SCHEMA_VERSION = 1


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _event_json(event: dict) -> tuple[dict, str]:
    if not isinstance(event, dict):
        raise ValueError('event must be an object')
    version = event.get('schema_version', SCHEMA_VERSION)
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError('unsupported event schema')
    try:
        encoded = json.dumps({'schema_version': SCHEMA_VERSION, **event}, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError('event is not JSON data') from exc
    value = json.loads(encoded)
    kind = value.get('kind')
    if not isinstance(kind, str) or not kind or not isinstance(value.get('source'), str) or not value['source']:
        raise ValueError('event kind and source are required')
    if value.get('source_epoch') is not None and not isinstance(value['source_epoch'], str):
        raise ValueError('invalid source epoch')
    sequence = value.get('source_seq')
    if sequence is not None and (type(sequence) is not int or not 0 <= sequence < 2**63):
        raise ValueError('invalid source sequence')
    payload = value.get('payload')
    if not isinstance(payload, dict):
        raise ValueError('event payload must be an object')
    if kind in ('node', 'link', 'route', 'snapshot', 'sample'):
        if (not isinstance(value.get('scope'), str) or not value['scope'] or
                ':' in value['scope']):
            raise ValueError('observation scope is required')
    fields = {'node': ('node',), 'link': ('observer', 'peer'),
              'route': ('observer', 'destination')}
    def check_item(item, item_kind):
        if (not isinstance(item, dict) or
                any(not isinstance(item.get(key), str) or not item[key] or ':' in item[key]
                    for key in fields[item_kind])):
            raise ValueError('observation identity is invalid')
        if 'removed' in item and type(item['removed']) is not bool:
            raise ValueError('invalid removal marker')
    if kind in fields:
        check_item(payload, kind)
    elif kind == 'snapshot':
        if 'complete' in payload and type(payload['complete']) is not bool:
            raise ValueError('invalid snapshot completeness')
        for section, item_kind in (('nodes', 'node'), ('links', 'link'), ('routes', 'route')):
            entries = payload.get(section)
            if entries is not None:
                if not isinstance(entries, list):
                    raise ValueError('snapshot section must be an array')
                for item in entries:
                    check_item(item, item_kind)
    elif kind == 'sample':
        if not isinstance(payload.get('series'), str) or not payload['series']:
            raise ValueError('sample series is required')
    elif kind == 'clock_adjustment':
        if type(payload.get('delta_ms')) is not int:
            raise ValueError('invalid clock adjustment')
    return value, encoded


class Capture:
    def __init__(self, path: Path, capture_id: str, *, versions=None, scopes=None):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=False)
        self.manifest = {'schema_version': SCHEMA_VERSION, 'capture_id': capture_id,
                         'versions': dict(versions or {}), 'scopes': list(scopes or ()),
                         'max_uncommitted_seconds': 1, 'closed': False}
        (self.path / 'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')
        # The timer commits idle batches; the lock preserves a single SQLite writer.
        self._lock = threading.RLock()
        self._timer = None
        self.closed = False
        self.db = sqlite3.connect(self.path / 'data.sqlite', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA user_version=1')
        self.db.executescript('''
            CREATE TABLE events(seq INTEGER PRIMARY KEY, t_mono_ns INTEGER NOT NULL,
              t_unix_ns INTEGER NOT NULL, source TEXT, source_epoch TEXT,
              source_seq INTEGER, kind TEXT NOT NULL, scope TEXT, payload_json TEXT NOT NULL);
            CREATE TABLE metric_samples(seq INTEGER PRIMARY KEY, t_mono_ns INTEGER NOT NULL,
              t_unix_ns INTEGER NOT NULL, series TEXT NOT NULL, value_json TEXT NOT NULL);
            CREATE INDEX metric_series_time ON metric_samples(series, t_mono_ns);
            CREATE TABLE trial_runs(id TEXT PRIMARY KEY, plan_json TEXT);
            CREATE TABLE trial_messages(id TEXT PRIMARY KEY, result_json TEXT);
            CREATE TABLE checkpoints(seq INTEGER PRIMARY KEY, t_mono_ns INTEGER, state_json TEXT);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value_json TEXT);
        ''')
        self.seq = 0
        self.state = State()
        self.last_checkpoint_ns = 0
        self.last_event_ns = None
        self.failed = False

    def _flush_idle(self):
        with self._lock:
            self._timer = None
            if not self.closed and not self.failed:
                try:
                    self.flush()
                except (sqlite3.Error, OSError):
                    # The next producer sees failed; an idle disk failure is not a clean close.
                    pass

    def add(self, event: dict, clock):
        with self._lock:
            self._add(event, clock)

    def _add(self, event: dict, clock):
        if self.closed:
            raise RuntimeError('capture already closed')
        if self.failed:
            raise RuntimeError('capture recording stopped after storage failure')
        normalized, encoded = _event_json(event)
        mono_ns = clock.mono_ns
        unix_ms = clock.unix_ms
        if (type(mono_ns) is not int or not 0 <= mono_ns < 2**63 or
                type(unix_ms) is not int or not -(2**63) <= unix_ms * 1_000_000 < 2**63 or
                self.last_event_ns is not None and mono_ns < self.last_event_ns):
            raise ValueError('invalid capture clock')
        try:
            self.seq += 1
            if self.seq == 1:
                self.last_checkpoint_ns = mono_ns
            self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', (
                self.seq, mono_ns, unix_ms * 1_000_000,
                normalized['source'], normalized.get('source_epoch'), normalized.get('source_seq'),
                normalized['kind'], normalized.get('scope'), encoded))
            if normalized['kind'] == 'sample':
                self.db.execute('INSERT INTO metric_samples VALUES (?,?,?,?,?)',
                                (self.seq, mono_ns, unix_ms * 1_000_000,
                                 normalized['payload']['series'],
                                 json.dumps(normalized['payload'])))
            reduce(self.state, normalized)
            if self.seq % 5000 == 0 or mono_ns - self.last_checkpoint_ns >= 30_000_000_000:
                # Checkpoints share the event transaction, so a crash cannot expose a future state.
                snapshot = asdict(self.state)
                snapshot['schema_version'] = SCHEMA_VERSION
                snapshot['retired_epochs'] = {k: sorted(v) for k, v in self.state.retired_epochs.items()}
                self.db.execute('INSERT INTO checkpoints VALUES (?,?,?)',
                                (self.seq, mono_ns, json.dumps(snapshot)))
                self.last_checkpoint_ns = mono_ns
            self.last_event_ns = mono_ns
            # Important operation boundaries can explicitly call flush().
            if self.seq % 1000 == 0:
                self.flush()
            elif self._timer is None:
                self._timer = threading.Timer(1.0, self._flush_idle)
                self._timer.daemon = True
                self._timer.start()
        except (sqlite3.Error, OSError):
            # Never accept more events or advertise a clean capture after a write failure.
            self.failed = True
            self.db.rollback()
            raise

    def flush(self):
        with self._lock:
            self._flush()

    def _flush(self):
        if self.closed:
            raise RuntimeError('capture already closed')
        if self.failed:
            raise RuntimeError('capture recording stopped after storage failure')
        try:
            self.db.commit()
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        except (sqlite3.Error, OSError):
            self.failed = True
            self.db.rollback()
            raise

    def close(self):
        with self._lock:
            self._close()

    def _close(self):
        if self.closed:
            return
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self.closed = True
        if self.failed:
            self.db.rollback()
            self.db.close()
            return
        try:
            self.db.commit()
            self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            self.db.close()
            database = self.path / 'data.sqlite'
            checksums = {'schema_version': SCHEMA_VERSION, 'closed': True,
                         'files': {'data.sqlite': {'size': database.stat().st_size,
                                                   'sha256': _file_digest(database)}}}
            checksum_tmp = self.path / 'checksums.json.tmp'
            checksum_tmp.write_text(json.dumps(checksums), encoding='utf-8')
            os.replace(checksum_tmp, self.path / 'checksums.json')
            self.manifest['closed'] = True
            tmp = self.path / 'manifest.json.tmp'
            tmp.write_text(json.dumps(self.manifest), encoding='utf-8')
            os.replace(tmp, self.path / 'manifest.json')
        except (sqlite3.Error, OSError):
            self.failed = True
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def replay(path: Path, until_seq=None) -> State:
    manifest = json.loads((Path(path) / 'manifest.json').read_text(encoding='utf-8'))
    if type(manifest.get('schema_version')) is not int or manifest['schema_version'] != SCHEMA_VERSION:
        raise ValueError('unsupported capture schema')
    db = sqlite3.connect(f'{(Path(path) / "data.sqlite").resolve().as_uri()}?mode=ro', uri=True)
    try:
        if db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
            raise ValueError('unsupported SQLite schema')
        checkpoint = db.execute('SELECT seq,state_json FROM checkpoints WHERE seq<=? ORDER BY seq DESC LIMIT 1',
                                (until_seq if until_seq is not None else 2**63 - 1,)).fetchone()
        start = checkpoint[0] if checkpoint else 0
        if checkpoint:
            data = json.loads(checkpoint[1])
            # Old v1 checkpoints predate the state tag; unknown majors cannot be restored.
            version = data.pop('schema_version', SCHEMA_VERSION)
            if type(version) is not int or version != SCHEMA_VERSION:
                raise ValueError('unsupported checkpoint schema')
            known = {entry.name for entry in fields(State)}
            extra = {key: data.pop(key) for key in list(data) if key not in known}
            if extra:
                data['extensions'] = {**data.get('extensions', {}), **extra}
            data['retired_epochs'] = {k: set(v) for k, v in data['retired_epochs'].items()}
            data['sources'] = {k: tuple(v) for k, v in data['sources'].items()}
            state = State(**data)
        else:
            state = State()
        for seq, payload in db.execute('SELECT seq,payload_json FROM events WHERE seq>? ORDER BY seq', (start,)):
            if until_seq is not None and seq > until_seq:
                break
            event = json.loads(payload)
            if type(event.get('schema_version')) is not int or event['schema_version'] != SCHEMA_VERSION:
                raise ValueError('unsupported event schema')
            reduce(state, event)
        if not manifest.get('closed', False) and until_seq is None:
            # The last committed event is reliable; an unfinished tail is not.
            state.gaps.append({'reason': 'UncleanEnd'})
        return state
    finally:
        db.close()
