"""Public cryptographic review-vector checks; no sandbox credentials are read."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit_review_vectors', HERE / 'vectors.py')
vectors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vectors)


class ReviewVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = os.environ.get('THRESHOLD_AUDIT_SECP256K1') or os.environ.get('SECP256K1_ZKP_LIBRARY')
        if not library or not Path(library).is_file():
            raise unittest.SkipTest('set THRESHOLD_AUDIT_SECP256K1 to the built shared library')
        cls.engine = vectors.Curve(library)
        cls.fixture = json.loads(vectors.FIXTURE.read_text())

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'engine'):
            cls.engine.close()

    def test_fixed_public_fixture_reproduces_and_verifies(self):
        result = vectors.verify(self.engine, self.fixture)
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['deterministic_regeneration'])
        self.assertEqual(result['governance_cases'], 2)

    def test_vector_tampering_and_live_data_refused(self):
        changed = copy.deepcopy(self.fixture)
        changed['public_test_only'] = False
        with self.assertRaises(ValueError):
            vectors.verify(self.engine, changed)
        changed = copy.deepcopy(self.fixture)
        encoded = bytearray.fromhex(changed['packet']['packet_hex'])
        encoded[-1] ^= 1
        changed['packet']['packet_hex'] = encoded.hex()
        with self.assertRaises(AssertionError):
            vectors.verify(self.engine, changed)

    def test_mutated_public_statement_is_rejected(self):
        changed = vectors.statement_from(self.fixture['packet']['statement'])
        packet = vectors.chunked.ChunkPacket.from_bytes(bytes.fromhex(self.fixture['packet']['packet_hex']), changed, self.engine)
        from dataclasses import replace
        self.assertFalse(vectors.chunked.verify_chunked(self.engine, replace(changed, output_index=changed.output_index + 1), packet))


if __name__ == '__main__':
    unittest.main()
