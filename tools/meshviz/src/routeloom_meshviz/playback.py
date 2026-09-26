"""Qt-free capture reader for seek/step playback and CSV/JSONL export.

Replay is read-only: captured trial or flash events are shown, never re-executed.
"""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .capture import SCHEMA_VERSION, replay
from .model import reduce
from .trial import summarize

SERIES_POINTS = 2000


class CaptureReader:
    def __init__(self, path):
        self.path = Path(path)
        self.manifest = json.loads((self.path / 'manifest.json').read_text(encoding='utf-8'))
        if self.manifest.get('schema_version') != SCHEMA_VERSION:
            raise ValueError('unsupported capture schema')
        self.db = sqlite3.connect(f'{(self.path / "data.sqlite").resolve().as_uri()}?mode=ro',
                                  uri=True, check_same_thread=False)
        if self.db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
            self.db.close()
            raise ValueError('unsupported SQLite schema')
        # (seq, t_mono_ns, t_unix_ns); a one-hour capture is tens of thousands of rows.
        self.index = self.db.execute('SELECT seq,t_mono_ns,t_unix_ns FROM events ORDER BY seq').fetchall()

    def close(self):
        self.db.close()

    @property
    def closed_cleanly(self):
        return self.manifest.get('closed', False)

    def seq_at(self, t_mono_ns):
        """Last event seq at or before t (0 = before the first event)."""
        low, high = 0, len(self.index)
        while low < high:
            mid = (low + high) // 2
            if self.index[mid][1] <= t_mono_ns:
                low = mid + 1
            else:
                high = mid
        return self.index[low - 1][0] if low else 0

    def state_at(self, seq):
        # Checkpoint + later events, exactly the headless replay semantics.
        return replay(self.path, until_seq=seq)

    def apply(self, state, after_seq, until_seq):
        """Incrementally reduce (after_seq, until_seq] onto state; returns the events."""
        applied = []
        for (payload,) in self.db.execute(
                'SELECT payload_json FROM events WHERE seq>? AND seq<=? ORDER BY seq',
                (after_seq, until_seq)):
            event = json.loads(payload)
            reduce(state, event)
            applied.append(event)
        return applied

    def series(self, until_seq, names=None, points=SERIES_POINTS):
        """series → [(t_unix_ms, value)] up to seq; the newest `points` samples per series."""
        result = {}
        for seq, t_unix_ns, series, value_json in self.db.execute(
                'SELECT seq,t_unix_ns,series,value_json FROM metric_samples WHERE seq<=? ORDER BY seq',
                (until_seq,)):
            if names is not None and series not in names:
                continue
            value = json.loads(value_json)
            observed = value.get('observed_unix_ms')
            points_list = result.setdefault(series, [])
            points_list.append((observed if type(observed) is int else t_unix_ns // 1_000_000,
                                value.get('value')))
            if len(points_list) > points:
                del points_list[0]
        return result

    def trial_messages(self, until_seq=None):
        """Latest ledger entry per (run, index) as recorded; the plan per run."""
        messages, plans = {}, {}
        for (payload,) in self.db.execute(
                "SELECT payload_json FROM events WHERE kind IN ('trial_message','trial_run') "
                'AND seq<=? ORDER BY seq', (until_seq if until_seq is not None else 2**63 - 1,)):
            event = json.loads(payload)
            body = event['payload']
            if event['kind'] == 'trial_run':
                plans[body['run_id']] = body
            else:
                messages[(body['run_id'], body['index'])] = body
        return plans, [messages[key] for key in sorted(messages)]


def _iso(unix_ms):
    if type(unix_ms) is not int:
        return ''
    return datetime.fromtimestamp(unix_ms / 1000, timezone.utc).isoformat(timespec='milliseconds')


def _cell(value):
    # Nullable values stay empty, never 0; nested data is not packed into a CSV cell.
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return value


def _write_csv(path, columns, rows):
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_cell(row.get(column)) for column in columns])


def export_capture(path, out_dir, until_seq=None):
    """events.jsonl, nodes/links/routes/samples/trial_messages CSV and trial_summary.json."""
    reader = CaptureReader(path)
    try:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        limit = until_seq if until_seq is not None else 2**63 - 1
        with (out / 'events.jsonl').open('w', encoding='utf-8') as stream:
            for seq, t_mono, t_unix, payload in reader.db.execute(
                    'SELECT seq,t_mono_ns,t_unix_ns,payload_json FROM events WHERE seq<=? ORDER BY seq',
                    (limit,)):
                stream.write(json.dumps({'seq': seq, 't_mono_ns': t_mono, 't_unix_ns': t_unix,
                                         't_utc': _iso(t_unix // 1_000_000),
                                         'event': json.loads(payload)}, sort_keys=True) + '\n')
        last_seq = reader.index[-1][0] if reader.index else 0
        state = reader.state_at(min(limit, last_seq))
        node_columns = ['scope', 'node', 'role', 'connected', 'listed', 'neighbor', 'direct', 'hops',
                        'next_hop', 'route_metric', 'link_cost', 'rssi_dbm', 'rssi_avg_dbm',
                        'telemetry_stale', 'last_heard_ms', 'last_heard_utc', 'changed_ms', 'source']
        _write_csv(out / 'nodes.csv', node_columns, (
            {**item, 'scope': key.split(':')[0], 'source': item.get('_source'),
             'last_heard_utc': _iso(item.get('last_heard_ms'))}
            for key, item in sorted(state.nodes.items())))
        _write_csv(out / 'links.csv', ['scope', 'observer', 'peer', 'direction', 'rssi_dbm',
                                       'rssi_avg_dbm', 'link_cost', 'observed_unix_ms', 'evidence',
                                       'source'], (
            {**item, 'scope': key.split(':')[0], 'source': item.get('_source')}
            for key, item in sorted(state.links.items())))
        _write_csv(out / 'routes.csv', ['scope', 'observer', 'destination', 'next_hop', 'metric',
                                        'valid', 'evidence', 'source'], (
            {**item, 'scope': key.split(':')[0], 'source': item.get('_source')}
            for key, item in sorted(state.routes.items())))
        rows = []
        for seq, t_mono, t_unix, series, value_json in reader.db.execute(
                'SELECT seq,t_mono_ns,t_unix_ns,series,value_json FROM metric_samples '
                'WHERE seq<=? ORDER BY seq', (limit,)):
            value = json.loads(value_json)
            rows.append({'seq': seq, 't_mono_ns': t_mono, 't_utc': _iso(t_unix // 1_000_000),
                         'series': series, 'value': value.get('value'), 'unit': value.get('unit'),
                         'observed_unix_ms': value.get('observed_unix_ms')})
        _write_csv(out / 'samples.csv', ['seq', 't_mono_ns', 't_utc', 'series', 'value', 'unit',
                                         'observed_unix_ms'], rows)
        plans, messages = reader.trial_messages(until_seq)
        message_columns = ['run_id', 'index', 'destination', 'payload_len', 'key', 'operation_id',
                           'planned_ms', 'submit_ms', 'admitted_ms', 'terminal_ms', 'admission',
                           'dispatch_state', 'result']
        _write_csv(out / 'trial_messages.csv', message_columns, messages)
        summaries = {run: summarize([m for m in messages if m['run_id'] == run], None,
                                    plan.get('state'), plan.get('stop_reason'))
                     for run, plan in plans.items()}
        for run, summary in summaries.items():
            summary['plan'] = plans[run].get('plan')
        (out / 'trial_summary.json').write_text(json.dumps(summaries, indent=1, sort_keys=True),
                                                encoding='utf-8')
        return out
    finally:
        reader.close()


def read_trial_csv(path):
    """Parse trial_messages.csv back into ledger dicts (for independent re-aggregation)."""
    ints = ('index', 'payload_len', 'planned_ms', 'submit_ms', 'admitted_ms', 'terminal_ms')
    with Path(path).open(encoding='utf-8', newline='') as stream:
        return [{key: (int(value) if key in ints and value != '' else value or None)
                 for key, value in row.items()} for row in csv.DictReader(stream)]
