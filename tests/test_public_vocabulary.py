"""#194: the SDK's public surface names no integrating product.

History (docs/hil, design records) is out of scope. The only allowed hit
is the deprecated `decision_mode` input alias, one constant per parser.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SURFACE = ['components', 'protocol', 'firmware', 'examples',
           'host/*/src', 'host/*/examples', 'tools/*/src']
PATTERN = re.compile(r'KGuard|KGUARD|Kguard|kguard|\bKG\b')
ALLOWED = {
    ('host/routeloom-host/src/api1/site.rs',
     'pub(crate) const DEPRECATED_EXTERNAL_ALIAS: &str = "kguard";'),
    ('host/routeloomctl/src/main.rs',
     'const DEPRECATED_EXTERNAL_ALIAS: &str = "kguard";'),
}


class PublicVocabularyTest(unittest.TestCase):
    def test_no_product_names_on_public_surface(self):
        hits = []
        for pattern in SURFACE:
            for base in sorted(ROOT.glob(pattern)):
                for path in sorted(p for p in base.rglob('*') if p.is_file()):
                    rel = path.relative_to(ROOT).as_posix()
                    try:
                        text = path.read_text(encoding='utf-8')
                    except (UnicodeDecodeError, OSError):
                        continue
                    for number, line in enumerate(text.splitlines(), 1):
                        if PATTERN.search(line) and (rel, line.strip()) not in ALLOWED:
                            hits.append(f'{rel}:{number}: {line.strip()}')
        self.assertEqual(hits, [], '\n'.join(hits))


if __name__ == '__main__':
    unittest.main()
