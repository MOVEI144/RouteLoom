#!/usr/bin/env python3
"""Replay API1 JSON fixtures over stdio or a private Unix socket; no mesh engine."""
from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def response(line: bytes, cases: list[dict]) -> dict:
    request_id = None
    try:
        if len(line) > 8192 or not line.endswith(b'\n') or not line.startswith(b'API1 '):
            raise ValueError('invalid line')
        req = json.loads(line[5:])
        request_id = req.get('request_id')
        if (set(req) - {'v', 'request_id', 'method', 'params'}
                or req.get('v') != 1 or not isinstance(request_id, str)
                or not 1 <= len(request_id) <= 64
                or any(not 32 <= ord(c) <= 126 for c in request_id)
                or not isinstance(req.get('method'), str)
                or not isinstance(req.get('params', {}), dict)):
            request_id = request_id if isinstance(request_id, str) else None
            raise ValueError('invalid envelope')
        for case in cases:
            expected = case['request']
            if req.get('method') == expected['method'] and req.get('params', {}) == expected.get('params', {}):
                result = dict(case['response'])
                result['request_id'] = request_id
                return result
        code = 'UNSUPPORTED_METHOD'
    except (ValueError, UnicodeError, AttributeError):
        code = 'INVALID_REQUEST'
    return {'v': 1, 'request_id': request_id, 'ok': False,
            'error': {'code': code, 'detail': {'message': 'mock fixture unavailable'}, 'retryable': False}}


def replay(reader, writer, cases: list[dict]) -> None:
    while line := reader.readline(8193):
        writer.write(json.dumps(response(line, cases), separators=(',', ':')).encode() + b'\n')
        writer.flush()
        if len(line) > 8192:
            return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path)
    parser.add_argument('--fixture', type=Path, action='append')
    args = parser.parse_args()
    cases = [json.loads(p.read_text()) for p in (args.fixture or sorted((ROOT / 'protocol/api1/fixtures').glob('*.json')))]
    if args.socket is None:
        import sys
        replay(sys.stdin.buffer, sys.stdout.buffer, cases)
        return
    with socket.socket(socket.AF_UNIX) as server:
        # Refuse an existing path; never unlink another daemon's socket.
        server.bind(str(args.socket))
        args.socket.chmod(0o600)
        try:
            server.listen(1)
            while True:
                conn, _ = server.accept()
                with conn, conn.makefile('rb') as reader, conn.makefile('wb') as writer:
                    replay(reader, writer, cases)
        finally:
            args.socket.unlink()


if __name__ == '__main__':
    main()
