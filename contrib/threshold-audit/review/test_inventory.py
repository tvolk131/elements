"""Review inventory must hash source and skip runtime/private artifacts."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit_review_inventory', HERE / 'inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def test_only_source_and_explicit_public_json_are_fingerprinted(self):
        with tempfile.TemporaryDirectory(prefix='audit-review-inventory-') as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                            'commit', '--allow-empty', '-qm', 'base'], check=True)
            public = root / 'contrib' / 'threshold-audit' / 'review' / 'vectors'
            public.mkdir(parents=True)
            (public / 'public-v1.json').write_text('{"public_test_only":true}')
            source = root / 'contrib' / 'threshold-audit' / 'sample.py'
            source.write_text('PUBLIC = True\n')
            (source.parent / 'credentials.json').write_text('{"password":"NOT REAL TEST PASSWORD"}')
            cache = source.parent / '__pycache__'; cache.mkdir(); (cache / 'generated.py').write_text('not source')
            (source.parent / 'report.json').write_text('{}')
            outside = root / 'outside.txt'; outside.write_text('not selected')
            (source.parent / 'linked.txt').symlink_to(outside)
            paths = {entry['path'] for entry in inventory.source_files(root)}
            self.assertIn('contrib/threshold-audit/sample.py', paths)
            self.assertIn('contrib/threshold-audit/review/vectors/public-v1.json', paths)
            self.assertFalse(any('credentials' in path or '__pycache__' in path or 'report.json' in path or 'linked' in path for path in paths))


if __name__ == '__main__':
    unittest.main()
