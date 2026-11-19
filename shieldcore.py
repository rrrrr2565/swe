#!/usr/bin/env python3
"""ShieldCore educational scanner. Standard library only; not a full antivirus."""
import argparse, hashlib, os, shutil, sqlite3, time, uuid
from pathlib import Path
from signature_feed import load_feed
from windows_defender import defender_scan, defender_status

ROOT = Path(__file__).resolve().parent
if os.name == "nt":
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ShieldCore"
else:
    DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "shieldcore"
DB = DATA_DIR / "shieldcore.db"
QUARANTINE = DATA_DIR / "quarantine"
MAX_FILE_SIZE = 250 * 1024 * 1024
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures(id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
 value TEXT NOT NULL UNIQUE, severity TEXT NOT NULL DEFAULT 'high', enabled INTEGER NOT NULL DEFAULT 1,
 source TEXT NOT NULL DEFAULT 'local', added_at TEXT, expires_at TEXT);
CREATE TABLE IF NOT EXISTS db_updates(id INTEGER PRIMARY KEY, imported_at TEXT NOT NULL, feed_name TEXT NOT NULL,
 records_received INTEGER NOT NULL, records_added INTEGER NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS db_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_signatures_lookup ON signatures(kind,enabled,value);
CREATE TABLE IF NOT EXISTS exclusions(id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, started_at TEXT NOT NULL, target TEXT NOT NULL,
 status TEXT NOT NULL, files_seen INTEGER NOT NULL DEFAULT 0, detections INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, scan_id TEXT, path TEXT NOT NULL, sha256 TEXT,
 rule TEXT NOT NULL, severity TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id,created_at);
CREATE TABLE IF NOT EXISTS quarantine(id TEXT PRIMARY KEY, original_path TEXT NOT NULL, stored_path TEXT NOT NULL,
 sha256 TEXT NOT NULL, created_at TEXT NOT NULL, restored INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
"""

def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=30)
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=30000")
    c.executescript(SCHEMA)
    # Upgrade databases created by earlier prototype versions.
    cols = {row[1] for row in c.execute("PRAGMA table_info(signatures)")}
    for col, declaration in (("source", "TEXT NOT NULL DEFAULT 'local'"), ("added_at", "TEXT"), ("expires_at", "TEXT")):
        if col not in cols:
            c.execute(f"ALTER TABLE signatures ADD COLUMN {col} {declaration}")
    c.execute("INSERT OR IGNORE INTO db_meta(key,value) VALUES('schema_version','2')")
    c.execute("INSERT OR IGNORE INTO signatures(name,kind,value,severity,source,added_at) VALUES(?,?,?,?,?,?)",
              ("EICAR test file", "contains", EICAR.decode("ascii"), "test", "builtin-eicar-test", now()))
    c.commit()
    return c

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")

def event(c, level, msg):
    c.execute("INSERT INTO events(created_at,level,message) VALUES(?,?,?)", (now(), level, msg))
    c.commit()

def inspect(path, c):
    """Return (sha256, rule, severity); use bounded streaming reads."""
    try:
        if path.is_symlink():
            return None, "skipped: symbolic link", None
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            return None, "skipped: over 250 MiB limit", None
        signatures = c.execute("SELECT name,value,severity FROM signatures WHERE kind='contains' AND enabled=1").fetchall()
        patterns = [(name, value.encode("utf-8"), sev) for name, value, sev in signatures if value]
        sha = hashlib.sha256()
        tail = b""
        script_prefix = bytearray()
        found = None
        with open(path, "rb") as f:
            while True:
                block = f.read(1024 * 1024)
                if not block:
                    break
                sha.update(block)
                if len(script_prefix) < 2_000_000:
                    script_prefix.extend(block[:2_000_000-len(script_prefix)])
                if patterns and found is None:
                    data = tail + block
                    for name, pattern, sev in patterns:
                        if pattern in data:
                            found = (name, sev)
                            break
                    maxlen = max(len(pat) for _, pat, _ in patterns)
                    tail = data[-maxlen+1:] if maxlen > 1 else b""
        hexdigest = sha.hexdigest()
        hit = c.execute("SELECT name,severity FROM signatures WHERE kind='sha256' AND value=? AND enabled=1", (hexdigest,)).fetchone()
        if hit:
            return hexdigest, hit[0], hit[1]
        if found:
            return hexdigest, found[0], found[1]
        if path.suffix.lower() in {'.ps1', '.vbs', '.js', '.bat', '.cmd'}:
            low = bytes(script_prefix).decode('utf-8', 'ignore').lower()
            if (('downloadstring' in low or 'invoke-webrequest' in low or 'bitsadmin' in low) and
                ('frombase64string' in low or ' -enc' in low or 'wscript.shell' in low)):
                return hexdigest, "Suspicious script: download plus obfuscation indicators", "medium"
        return hexdigest, None, None
    except (OSError, PermissionError) as e:
        return None, "error: " + str(e), None

def _copy_verified(source, destination, expected_sha):
    """Create destination exclusively, stream-copy, fsync, and verify before reporting success."""
    h = hashlib.sha256()
    with open(source, "rb") as src, open(destination, "xb") as dst:
        before = os.fstat(src.fileno())
        if not os.path.isfile(source) or Path(source).is_symlink():
            raise RuntimeError("source is not a regular file")
        for block in iter(lambda: src.read(1024 * 1024), b""):
            h.update(block); dst.write(block)
        dst.flush(); os.fsync(dst.fileno())
        after = os.fstat(src.fileno())
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or h.hexdigest() != expected_sha:
            raise RuntimeError("file changed during copy; operation cancelled")
    if digest(destination) != expected_sha:
        raise RuntimeError("copied file hash mismatch")

def quarantine(path, sha, c):
    """Stage a verified copy, recheck source, then isolate; never overwrite another file."""
    if not sha or path.is_symlink() or digest(path) != sha:
        raise RuntimeError("file changed since scan; quarantine cancelled")
    QUARANTINE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try: QUARANTINE.chmod(0o700)
        except OSError: pass
    qid = uuid.uuid4().hex
    dest = QUARANTINE / (qid + ".bin")
    staged = QUARANTINE / (qid + ".tmp")
    try:
        _copy_verified(path, staged, sha)
        if os.name != "nt":
            try: staged.chmod(0o600)
            except OSError: pass
        # Verify that the original still contains the bytes scanned before unlinking it.
        if path.is_symlink() or digest(path) != sha:
            raise RuntimeError("source changed before isolation; original left in place")
        os.replace(staged, dest)  # unique destination; atomic within quarantine directory
        # Recheck after publication; if anything fails, retain original and remove staged copy.
        if digest(dest) != sha:
            dest.unlink(missing_ok=True)
            raise RuntimeError("quarantine copy hash mismatch; original left in place")
        path.unlink()
        c.execute("INSERT INTO quarantine(id,original_path,stored_path,sha256,created_at) VALUES(?,?,?,?,?)",
                  (qid, str(path), str(dest), sha, now()))
        c.commit()
        return qid
    except Exception:
        try:
            if dest.exists() and not path.exists():
                # Preserve recoverable data if a failure occurs after the source unlink.
                _copy_verified(dest, path, sha)
        except Exception:
            pass
        try:
            if staged.exists(): staged.unlink()
        except OSError:
            pass
        try:
            if dest.exists() and path.exists(): dest.unlink()
        except OSError:
            pass
        raise

def restore(qid, destination=None):
    c = connect()
    row = c.execute("SELECT original_path,stored_path,sha256 FROM quarantine WHERE id=? AND restored=0", (qid,)).fetchone()
    if not row:
        raise ValueError("active quarantine entry not found")
    original, stored, sha = row
    stored = Path(stored)
    dest = Path(destination).expanduser().resolve() if destination else Path(original)
    if not stored.is_file() or digest(stored) != sha:
        raise RuntimeError("quarantine item missing or hash mismatch; restore refused")
    if dest.exists():
        raise FileExistsError("destination already exists; refusing to overwrite: " + str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        _copy_verified(stored, dest, sha)  # exclusive create; never overwrites an existing file
        if os.name != "nt":
            try: dest.chmod(0o600)
            except OSError: pass
        c.execute("UPDATE quarantine SET restored=1 WHERE id=?", (qid,)); c.commit()
        try: stored.unlink()
        except OSError: pass  # verified restored copy remains; stale quarantine copy can be cleaned manually
        event(c, "warning", "Restored quarantined file to " + str(dest))
        print("Restored:", dest)
    except Exception:
        try:
            if dest.exists(): dest.unlink()
        except OSError: pass
        raise

def scan(target, do_quarantine=False, cancel_file=None):
    c = connect()
    original_target = Path(target).expanduser()
    if original_target.is_symlink():
        raise SystemExit("Refusing to scan a symbolic link directly")
    target = original_target.resolve()
    if not target.exists():
        raise SystemExit("Target does not exist: " + str(target))
    sid = uuid.uuid4().hex
    c.execute("INSERT INTO scans(id,started_at,target,status) VALUES(?,?,?,'running')", (sid, now(), str(target))); c.commit()
    exclusion_rows = c.execute("SELECT path FROM exclusions WHERE enabled=1").fetchall()
    exclusion_paths = [Path(row[0]) for row in exclusion_rows]
    seen = hits = 0
    cancelled = False
    cancel_path = Path(cancel_file).resolve() if cancel_file else None
    try:
        if target.is_file():
            candidates = iter([target])
        else:
            # Do not follow directory symlinks. File symlinks are skipped by inspect().
            candidates = (p for p in target.rglob('*') if p.is_file() and not p.is_symlink())
        for p in candidates:
            if cancel_path and cancel_path.exists():
                cancelled = True
                break
            if cancel_path and p.resolve() == cancel_path: continue
            if p == QUARANTINE or QUARANTINE in p.parents or p == DATA_DIR or DATA_DIR in p.parents: continue
            resolved = p.resolve()
            if any(resolved == ex or ex in resolved.parents for ex in exclusion_paths):
                seen += 1
                event(c, "warning", f"excluded by user setting: {p}")
                if seen % 25 == 0: print(f"PROGRESS {seen} {hits}", flush=True)
                continue
            seen += 1
            sha, name, severity = inspect(p, c)
            if name and name.startswith(("error:", "skipped:")):
                print(f"[{name}] {p}")
                event(c, "warning" if name.startswith("skipped:") else "error", f"{name}: {p}")
                continue
            if name:
                action = "detected"
                if do_quarantine and sha:
                    try: action = "quarantined:" + quarantine(p, sha, c)
                    except (OSError, RuntimeError) as e: action = "quarantine_failed:" + str(e)
                print(f"[{severity}] {p} — {name} ({action})")
                c.execute("INSERT INTO findings(scan_id,path,sha256,rule,severity,action,created_at) VALUES(?,?,?,?,?,?,?)",
                          (sid, str(p), sha, name, severity, action, now())); hits += 1
            if seen % 25 == 0:
                print(f"PROGRESS {seen} {hits}", flush=True)
        status = "cancelled" if cancelled else "completed"
        c.execute("UPDATE scans SET status=?,files_seen=?,detections=? WHERE id=?", (status, seen, hits, sid)); c.commit()
        event(c, "warning" if cancelled else "info", f"Scan {sid} {status}; {seen} files, {hits} findings")
        print(f"Done. status={status}, files={seen}, detections={hits}, scan_id={sid}")
        if cancel_path:
            try: cancel_path.unlink(missing_ok=True)
            except OSError: pass
    except Exception as e:
        c.execute("UPDATE scans SET status='failed',files_seen=?,detections=? WHERE id=?", (seen, hits, sid)); c.commit()
        event(c, "error", f"Scan {sid} failed: {e}")
        raise
    finally:
        if cancel_path:
            try: cancel_path.unlink(missing_ok=True)
            except OSError: pass
        c.close()

def report():
    c = connect()
    print("Recent findings:")
    for row in c.execute("SELECT created_at,path,rule,severity,action FROM findings ORDER BY id DESC LIMIT 50"):
        print(" | ".join(map(str, row)))
    print("\nQuarantine entries (use ID with restore):")
    for row in c.execute("SELECT id,original_path,created_at FROM quarantine WHERE restored=0 ORDER BY created_at DESC"):
        print(" | ".join(map(str, row)))
    print("\nRecent events:")
    for row in c.execute("SELECT created_at,level,message FROM events ORDER BY id DESC LIMIT 30"):
        print(" | ".join(map(str, row)))
    c.close()

def add_hash(path, name):
    sha = digest(Path(path)); c = connect()
    c.execute("INSERT OR IGNORE INTO signatures(name,kind,value,severity,source,added_at) VALUES(?,?,?,?,?,?)",
              (name, "sha256", sha, "high", "manual-local", now())); c.commit(); c.close()
    print("Added SHA-256 signature:", sha)

def import_feed(feed_path):
    """Import a reviewed local JSON feed atomically. No network update is performed."""
    feed_name, prepared = load_feed(feed_path)
    c = connect()
    try:
        c.execute("BEGIN IMMEDIATE")
        added = 0
        for name, value, severity in prepared:
            cur = c.execute("INSERT OR IGNORE INTO signatures(name,kind,value,severity,source,added_at) VALUES(?,?,?,?,?,?)",
                            (name, "sha256", value, severity, feed_name.strip(), now()))
            added += cur.rowcount
        c.execute("INSERT INTO db_updates(imported_at,feed_name,records_received,records_added,status) VALUES(?,?,?,?,?)",
                  (now(), feed_name.strip(), len(prepared), added, "imported"))
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
    print(f"Feed {feed_name}: received={len(prepared)}, added={added}")

def db_info():
    c = connect()
    print("Signature counts:")
    for row in c.execute("SELECT kind,severity,count(*) FROM signatures WHERE enabled=1 GROUP BY kind,severity ORDER BY kind,severity"):
        print(" | ".join(map(str, row)))
    print("Recent imports:")
    for row in c.execute("SELECT imported_at,feed_name,records_received,records_added,status FROM db_updates ORDER BY id DESC LIMIT 10"):
        print(" | ".join(map(str, row)))
    c.close()

def exclusion_add(path):
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir(): raise ValueError("exclusion must be an existing directory")
    c = connect()
    c.execute("INSERT OR IGNORE INTO exclusions(path,created_at,enabled) VALUES(?,?,1)", (str(resolved), now()))
    c.commit(); c.close()
    print("Exclusion added:", resolved)

def exclusion_remove(path):
    resolved = str(Path(path).expanduser().resolve())
    c = connect(); cur = c.execute("DELETE FROM exclusions WHERE path=?", (resolved,)); c.commit(); c.close()
    print("Exclusion removed" if cur.rowcount else "No matching exclusion", resolved)

def exclusion_list():
    c = connect(); rows = c.execute("SELECT path,created_at FROM exclusions WHERE enabled=1 ORDER BY path").fetchall(); c.close()
    print("Exclusions:")
    for path, created in rows: print(f"{path} | {created}")
    if not rows: print("(none)")

def main():
    p = argparse.ArgumentParser(description="ShieldCore educational scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan file or directory"); s.add_argument("path"); s.add_argument("--quarantine", action="store_true"); s.add_argument("--cancel-file", help=argparse.SUPPRESS)
    sub.add_parser("report", help="show findings and quarantine")
    h = sub.add_parser("add-hash", help="add a SHA-256 signature"); h.add_argument("file"); h.add_argument("--name", required=True)
    r = sub.add_parser("restore", help="restore a quarantined file after hash verification"); r.add_argument("id"); r.add_argument("--to", help="optional restore destination path; must not already exist")
    imp = sub.add_parser("import-db", help="import reviewed local JSON SHA-256 feed"); imp.add_argument("json_file")
    sub.add_parser("db-info", help="show local signature database counts and import history")
    ex = sub.add_parser("exclude-add", help="exclude a directory from scans"); ex.add_argument("path")
    ex = sub.add_parser("exclude-remove", help="remove an exact directory exclusion"); ex.add_argument("path")
    sub.add_parser("exclude-list", help="list configured directory exclusions")
    ds = sub.add_parser("defender-scan", help="scan a path using Microsoft Defender on Windows"); ds.add_argument("path")
    sub.add_parser("defender-status", help="show Microsoft Defender status on Windows")
    a = p.parse_args()
    if a.cmd == "scan": scan(a.path, a.quarantine, a.cancel_file)
    elif a.cmd == "report": report()
    elif a.cmd == "add-hash": add_hash(a.file, a.name)
    elif a.cmd == "restore": restore(a.id, a.to)
    elif a.cmd == "import-db": import_feed(a.json_file)
    elif a.cmd == "db-info": db_info()
    elif a.cmd == "exclude-add": exclusion_add(a.path)
    elif a.cmd == "exclude-remove": exclusion_remove(a.path)
    elif a.cmd == "exclude-list": exclusion_list()
    elif a.cmd == "defender-scan": defender_scan(a.path)
    elif a.cmd == "defender-status": defender_status()
if __name__ == "__main__": main()
