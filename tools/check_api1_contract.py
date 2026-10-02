#!/usr/bin/env python3
"""Validate API1 kit fixtures; production parser and Owner E2E remain authoritative."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def check() -> None:
    base = ROOT / 'protocol/api1'
    validators = {}
    for name in ('request', 'response', 'read-result'):
        schema = json.loads((base / f'{name}.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)
    fixtures = list((base / 'fixtures').glob('*.json'))
    if not fixtures:
        raise ValueError('API1 fixtures missing')
    for path in fixtures:
        case = json.loads(path.read_text())
        validators['request'].validate(case['request'])
        validators['response'].validate(case['response'])
        if case['request']['method'] == 'messages.read' and case['response']['ok']:
            validators['read-result'].validate(case['response']['result'])
        if case['request']['request_id'] != case['response']['request_id']:
            raise ValueError(f'{path}: request_id mismatch')
    print(f'API1 schemas and {len(fixtures)} fixtures valid')


if __name__ == '__main__':
    check()
