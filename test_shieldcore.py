import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "shieldcore.py"
spec = importlib.util.spec_from_file_location("shieldcore_under_test", MODULE)
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

class ShieldCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        sc.DATA_DIR = self.root / "data"
        sc.DB = sc.DATA_DIR / "test.db"
        sc.QUARANTINE = sc.DATA_DIR / "quarantine"
        sc.ROOT = self.root

    def tearDown(self):
        self.tmp.cleanup()

    def test_eicar_detected_across_chunk_boundary(self):
        p = self.root / "sample.bin"
        p.write_bytes(b"A" * (1024 * 1024 - 9) + sc.EICAR + b"Z")
        c = sc.connect()
        result = sc.inspect(p, c)
        c.close()
        self.assertEqual(result[1], "EICAR test file")
        self.assertTrue(result[0])

    def test_sha_signature_and_stream_hash(self):
        p = self.root / "hashme.bin"
        p.write_bytes(b"known test bytes")
        sc.add_hash(p, "test indicator")
        c = sc.connect()
        self.assertEqual(sc.inspect(p, c)[1], "test indicator")
        c.close()

    def test_quarantine_restore_and_no_overwrite(self):
        p = self.root / "eicar.txt"
        p.write_bytes(sc.EICAR)
        c = sc.connect()
        sha, _, _ = sc.inspect(p, c)
        qid = sc.quarantine(p, sha, c)
        c.close()
        destination = self.root / "restored.txt"
        sc.restore(qid, destination)
        self.assertEqual(destination.read_bytes(), sc.EICAR)
        with self.assertRaises(ValueError):
            sc.restore(qid, destination)

    def test_quarantine_directory_is_private_on_posix(self):
        p = self.root / "eicar.txt"
        p.write_bytes(sc.EICAR)
        c = sc.connect()
        sha, _, _ = sc.inspect(p, c)
        sc.quarantine(p, sha, c)
        c.close()
        if __import__('os').name != "nt":
            self.assertEqual(sc.QUARANTINE.stat().st_mode & 0o777, 0o700)

    def test_quarantine_refuses_changed_content(self):
        p = self.root / "eicar.txt"
        p.write_bytes(sc.EICAR)
        c = sc.connect()
        scanned_hash, _, _ = sc.inspect(p, c)
        p.write_bytes(b"changed after scan")
        with self.assertRaises(RuntimeError):
            sc.quarantine(p, scanned_hash, c)
        self.assertTrue(p.exists())
        c.close()

    def test_symlink_is_skipped(self):
        target = self.root / "real.txt"
        target.write_bytes(b"ordinary")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported")
        c = sc.connect()
        self.assertEqual(sc.inspect(link, c)[1], "skipped: symbolic link")
        c.close()

    def test_inert_suspicious_script_heuristic(self):
        p = self.root / "synthetic.ps1"
        # Plain text only; this sample is never executed.
        p.write_text("Invoke-WebRequest example.invalid; FromBase64String('not-a-payload')", encoding="utf-8")
        c = sc.connect()
        self.assertIn("Suspicious script", sc.inspect(p, c)[1])
        c.close()

    def test_benign_script_is_not_flagged(self):
        p = self.root / "benign.ps1"
        p.write_text("Write-Output 'hello world'", encoding="utf-8")
        c = sc.connect()
        self.assertIsNone(sc.inspect(p, c)[1])
        c.close()

    def test_json_feed_import_and_provenance(self):
        feed = self.root / "feed.json"
        data = {"format_version": 1, "feed_name": "test-only", "signatures": [
            {"name": "known test hash", "sha256": "a" * 64, "severity": "test"}]}
        feed.write_text(json.dumps(data), encoding="utf-8")
        sc.import_feed(feed)
        c = sc.connect()
        row = c.execute("SELECT name,source FROM signatures WHERE value=?", ("a" * 64,)).fetchone()
        self.assertEqual(row, ("known test hash", "test-only"))
        self.assertEqual(c.execute("SELECT records_added FROM db_updates ORDER BY id DESC LIMIT 1").fetchone()[0], 1)
        c.close()

    def test_demo_feed_hash_matches_harmless_eicar_marker(self):
        feed = MODULE.parent / "signature-feed.example.json"
        sc.import_feed(feed)
        p = self.root / "eicar.txt"
        p.write_bytes(sc.EICAR)
        c = sc.connect()
        result = sc.inspect(p, c)
        self.assertEqual(result[1], "EICAR test file SHA-256 (harmless test marker)")
        self.assertEqual(result[2], "test")
        c.close()

    def test_bad_feed_is_rejected_without_partial_import(self):
        feed = self.root / "bad.json"
        data = {"format_version": 1, "feed_name": "bad-test", "signatures": [
            {"name": "valid first", "sha256": "b" * 64},
            {"name": "invalid second", "sha256": "not-a-hash"}]}
        feed.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError): sc.import_feed(feed)
        c = sc.connect()
        self.assertEqual(c.execute("SELECT count(*) FROM signatures WHERE value=?", ("b" * 64,)).fetchone()[0], 0)
        c.close()

    def test_oversized_file_is_skipped_without_reading(self):
        p = self.root / "large.bin"
        with p.open("wb") as f:
            f.truncate(sc.MAX_FILE_SIZE + 1)
        c = sc.connect()
        self.assertEqual(sc.inspect(p, c)[1], "skipped: over 250 MiB limit")
        c.close()

    def test_size_limit_is_250_mib(self):
        self.assertEqual(sc.MAX_FILE_SIZE, 250 * 1024 * 1024)

    def test_windows_defender_adapter_refuses_non_windows(self):
        if __import__('os').name == "nt": self.skipTest("Windows-only adapter")
        with self.assertRaises(RuntimeError): sc.defender_status()
        with self.assertRaises(RuntimeError): sc.defender_scan(self.root)

    def test_database_lookup_indexes_exist(self):
        c = sc.connect()
        indexes = {r[1] for r in c.execute("PRAGMA index_list(signatures)")}
        self.assertIn("idx_signatures_lookup", indexes)
        meta = c.execute("SELECT value FROM db_meta WHERE key='schema_version'").fetchone()[0]
        self.assertEqual(meta, "2")
        c.close()

    def test_cancel_file_stops_scan_and_records_cancelled(self):
        folder = self.root / "target"
        folder.mkdir(); (folder / "eicar.txt").write_bytes(sc.EICAR)
        cancel = self.root / "cancel.flag"; cancel.write_text("cancel")
        with __import__('contextlib').redirect_stdout(__import__('io').StringIO()):
            sc.scan(folder, False, cancel)
        c = sc.connect()
        self.assertEqual(c.execute("SELECT status FROM scans ORDER BY rowid DESC LIMIT 1").fetchone()[0], "cancelled")
        self.assertEqual(c.execute("SELECT count(*) FROM findings").fetchone()[0], 0)
        self.assertFalse(cancel.exists())
        c.close()

    def test_user_exclusion_is_respected(self):
        folder = self.root / "excluded"; folder.mkdir(); (folder / "eicar.txt").write_bytes(sc.EICAR)
        sc.exclusion_add(folder)
        with __import__('contextlib').redirect_stdout(__import__('io').StringIO()):
            sc.scan(self.root, False)
        c = sc.connect()
        self.assertEqual(c.execute("SELECT count(*) FROM findings").fetchone()[0], 0)
        self.assertTrue(c.execute("SELECT message FROM events WHERE message LIKE '%excluded by user setting%' ").fetchone())
        c.close()

    def test_directory_scan_logs_finding(self):
        folder = self.root / "target"
        folder.mkdir()
        p = folder / "eicar.txt"
        p.write_bytes(sc.EICAR)
        with __import__('contextlib').redirect_stdout(__import__('io').StringIO()):
            sc.scan(folder, False)
        c = sc.connect()
        self.assertEqual(c.execute("SELECT count(*) FROM findings WHERE rule='EICAR test file'").fetchone()[0], 1)
        self.assertEqual(c.execute("SELECT status FROM scans ORDER BY rowid DESC LIMIT 1").fetchone()[0], "completed")
        c.close()

if __name__ == "__main__":
    unittest.main()
