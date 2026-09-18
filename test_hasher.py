"""
Unit tests for HashTrace forensic integrity engine.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from hasher import compute_hashes, format_bytes, get_file_metadata


class TestHashTrace(unittest.TestCase):
    def setUp(self):
        """Create a temporary known-state file before each test."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.test_dir.name) / "evidence.txt"
        # Known payload: b"forensic-test-data\n"
        self.payload = b"forensic-test-data\n"
        self.test_file.write_bytes(self.payload)

        # Pre-calculated reference hashes for this exact payload
        self.expected_md5 = hashlib.md5(self.payload).hexdigest()
        self.expected_sha256 = hashlib.sha256(self.payload).hexdigest()

    def tearDown(self):
        """Clean up temporary test artifacts."""
        self.test_dir.cleanup()

    def test_hash_computation(self):
        """Verify computed hashes match reference implementations bit-for-bit."""
        digests = compute_hashes(self.test_file, ["md5", "sha256"])
        self.assertEqual(digests["MD5"], self.expected_md5)
        self.assertEqual(digests["SHA256"], self.expected_sha256)

    def test_byte_formatting(self):
        """Test human-readable byte conversions."""
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1048576), "1.00 MB")
        self.assertEqual(format_bytes(1073741824), "1.00 GB")

    def test_metadata_extraction(self):
        """Verify filesystem metadata includes size and UTC timestamp keys."""
        meta = get_file_metadata(self.test_file)
        self.assertEqual(meta["size_bytes"], len(self.payload))
        self.assertIn("UTC", meta["created_utc"])
        self.assertIn("UTC", meta["modified_utc"])
        self.assertIn("UTC", meta["accessed_utc"])


if __name__ == "__main__":
    unittest.main()
