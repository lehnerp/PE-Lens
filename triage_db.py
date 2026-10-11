"""
SQLite store for PE Triage.

Everything the dashboard finds is written here so it can be queried later with
any SQLite client (DB Browser for SQLite, the sqlite3 CLI, pandas, ...).

The sample itself is stored zlib-compressed and XOR-encoded (key 0x5A), so the
database never contains a runnable executable and AV won't flag the .db file.
To recover the original bytes:

    data = zlib.decompress(bytes(b ^ 0x5A for b in blob))
"""
import contextlib
import json
import pathlib
import sqlite3
import time
import zlib

XOR_KEY = 0x5A
_XOR_TABLE = bytes(i ^ XOR_KEY for i in range(256))
BLOB_ENCODING = "zlib+xor:0x5a"

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS samples(
  id INTEGER PRIMARY KEY,
  sha256 TEXT UNIQUE NOT NULL, md5 TEXT, sha1 TEXT, imphash TEXT,
  name TEXT, size INTEGER, arch TEXT, is_dll INTEGER, compile_ts INTEGER,
  image_base INTEGER, entry INTEGER, entropy REAL, signed INTEGER, pdb TEXT,
  packer_signals TEXT,
  parent_id INTEGER REFERENCES samples(id) ON DELETE SET NULL, parent_offset INTEGER,
  blob BLOB, blob_encoding TEXT,
  added_at TEXT, analysed_at TEXT, analysis_phase TEXT);

CREATE TABLE IF NOT EXISTS sections(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  name TEXT, va INTEGER, vsize INTEGER, rsize INTEGER, flags TEXT, entropy REAL);

CREATE TABLE IF NOT EXISTS resources(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  type TEXT, name TEXT, lang INTEGER, size INTEGER, entropy REAL, magic TEXT, embedded_pe INTEGER);

CREATE TABLE IF NOT EXISTS imports(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  dll TEXT, name TEXT, iat_va INTEGER, category TEXT, delayed INTEGER);

CREATE TABLE IF NOT EXISTS exports(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE, name TEXT, va INTEGER);

CREATE TABLE IF NOT EXISTS strings(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  sid INTEGER, offset INTEGER, va INTEGER, enc TEXT, text TEXT, cats TEXT,
  PRIMARY KEY(sample_id, sid));

CREATE TABLE IF NOT EXISTS constants(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  name TEXT, offset INTEGER, va INTEGER);

CREATE TABLE IF NOT EXISTS functions(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  va INTEGER, name TEXT, end_va INTEGER, insns INTEGER, blocks INTEGER,
  score INTEGER, tags TEXT, notes TEXT, stack_strings TEXT,
  PRIMARY KEY(sample_id, va));

CREATE TABLE IF NOT EXISTS calls(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE, caller INTEGER, callee INTEGER);

CREATE TABLE IF NOT EXISTS api_calls(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  func_va INTEGER, api TEXT, category TEXT, count INTEGER);

CREATE TABLE IF NOT EXISTS string_refs(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE, func_va INTEGER, sid INTEGER);

CREATE TABLE IF NOT EXISTS indicators(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  kind TEXT, value TEXT, source TEXT, offset INTEGER,
  UNIQUE(sample_id, kind, value));

CREATE TABLE IF NOT EXISTS annotations(
  sample_id INTEGER REFERENCES samples(id) ON DELETE CASCADE,
  va INTEGER, kind TEXT CHECK(kind IN ('name','comment')), text TEXT, updated_at TEXT,
  PRIMARY KEY(sample_id, va, kind));

CREATE INDEX IF NOT EXISTS ix_calls_callee ON calls(sample_id, callee);
CREATE INDEX IF NOT EXISTS ix_api_calls ON api_calls(sample_id, api);
CREATE INDEX IF NOT EXISTS ix_string_refs ON string_refs(sample_id, sid);
CREATE INDEX IF NOT EXISTS ix_strings_text ON strings(text);
CREATE INDEX IF NOT EXISTS ix_imports_name ON imports(name);

CREATE VIEW IF NOT EXISTS v_functions AS
  SELECT f.sample_id, printf('0x%X', f.va) AS addr, f.va, COALESCE(a.text, f.name) AS name,
         f.score, f.tags, f.insns, f.blocks, f.notes, f.stack_strings
  FROM functions f
  LEFT JOIN annotations a ON a.sample_id=f.sample_id AND a.va=f.va AND a.kind='name';

CREATE VIEW IF NOT EXISTS v_api_usage AS
  SELECT c.sample_id, c.api, c.category, printf('0x%X', c.func_va) AS func_addr,
         COALESCE(a.text, f.name) AS func_name, c.count
  FROM api_calls c
  JOIN functions f ON f.sample_id=c.sample_id AND f.va=c.func_va
  LEFT JOIN annotations a ON a.sample_id=f.sample_id AND a.va=f.va AND a.kind='name';

CREATE VIEW IF NOT EXISTS v_string_xrefs AS
  SELECT r.sample_id, s.sid, s.text, s.cats, printf('0x%X', r.func_va) AS func_addr,
         COALESCE(a.text, f.name) AS func_name
  FROM string_refs r
  JOIN strings s ON s.sample_id=r.sample_id AND s.sid=r.sid
  JOIN functions f ON f.sample_id=r.sample_id AND f.va=r.func_va
  LEFT JOIN annotations a ON a.sample_id=f.sample_id AND a.va=f.va AND a.kind='name';

CREATE VIEW IF NOT EXISTS v_call_graph AS
  SELECT c.sample_id, printf('0x%X', c.caller) AS caller_addr,
         COALESCE(a1.text, f1.name, printf('sub_%X', c.caller)) AS caller,
         printf('0x%X', c.callee) AS callee_addr,
         COALESCE(a2.text, f2.name, printf('sub_%X', c.callee)) AS callee
  FROM calls c
  LEFT JOIN functions f1 ON f1.sample_id=c.sample_id AND f1.va=c.caller
  LEFT JOIN functions f2 ON f2.sample_id=c.sample_id AND f2.va=c.callee
  LEFT JOIN annotations a1 ON a1.sample_id=c.sample_id AND a1.va=c.caller AND a1.kind='name'
  LEFT JOIN annotations a2 ON a2.sample_id=c.sample_id AND a2.va=c.callee AND a2.kind='name';
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS strings_fts USING fts5(sample_id UNINDEXED, sid UNINDEXED, text);
"""

STATIC_TABLES = ("sections", "resources", "imports", "exports", "strings", "constants")
ANALYSIS_TABLES = ("functions", "calls", "api_calls", "string_refs")


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def encode_blob(data):
    return zlib.compress(data, 6).translate(_XOR_TABLE)


def decode_blob(blob):
    return zlib.decompress(bytes(blob).translate(_XOR_TABLE))


class TriageDB:
    def __init__(self, path):
        self.path = str(pathlib.Path(path).resolve())
        with self.tx() as c:
            c.executescript(SCHEMA)
            try:
                c.executescript(FTS_SCHEMA)
                self.fts = True
            except sqlite3.OperationalError:
                self.fts = False

    @contextlib.contextmanager
    def tx(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ---------------- writes ----------------

    def upsert_sample(self, s, parent_id=None, parent_offset=None, store_blob=True):
        o = s.overview
        blob = encode_blob(s.data) if store_blob else None
        meta = (o["md5"], o["sha1"], o["imphash"], o["name"], o["size"], o["arch"],
                int(o["dll"]), o["timestamp"], o["image_base"], o["entry"], o["entropy"],
                int(o["signed"]), o["pdb"], json.dumps(o["packer"]))
        with self.tx() as c:
            row = c.execute("SELECT id FROM samples WHERE sha256=?", (o["sha256"],)).fetchone()
            if row:
                sid = row[0]
                c.execute("""UPDATE samples SET md5=?, sha1=?, imphash=?, name=?, size=?, arch=?,
                             is_dll=?, compile_ts=?, image_base=?, entry=?, entropy=?, signed=?,
                             pdb=?, packer_signals=?,
                             parent_id=COALESCE(parent_id, ?), parent_offset=COALESCE(parent_offset, ?),
                             blob=COALESCE(?, blob), blob_encoding=COALESCE(?, blob_encoding)
                             WHERE id=?""",
                          meta + (parent_id, parent_offset, blob,
                                  BLOB_ENCODING if blob else None, sid))
            else:
                cur = c.execute("""INSERT INTO samples(md5, sha1, imphash, name, size, arch, is_dll,
                             compile_ts, image_base, entry, entropy, signed, pdb, packer_signals,
                             sha256, parent_id, parent_offset, blob, blob_encoding, added_at)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                meta + (o["sha256"], parent_id, parent_offset, blob,
                                        BLOB_ENCODING if blob else None, now()))
                sid = cur.lastrowid
        return sid

    def _replace(self, c, sid, tables, rows):
        for t in tables:
            c.execute(f"DELETE FROM {t} WHERE sample_id=?", (sid,))
            data = rows.get(t) or []
            if data:
                ph = ",".join("?" * (len(data[0]) + 1))
                c.executemany(f"INSERT INTO {t} VALUES ({ph})", [(sid,) + tuple(r) for r in data])

    def _indicators(self, c, sid, iocs):
        c.executemany("INSERT OR IGNORE INTO indicators VALUES (?,?,?,?,?)",
                      [(sid, k, v, src, off) for k, v, src, off in iocs])

    def save_static(self, sid, s):
        rows = s.static_rows()
        with self.tx() as c:
            self._replace(c, sid, STATIC_TABLES, rows)
            c.execute("DELETE FROM indicators WHERE sample_id=?", (sid,))
            self._indicators(c, sid, s.indicators())
            if self.fts:
                c.execute("DELETE FROM strings_fts WHERE sample_id=?", (sid,))
                c.executemany("INSERT INTO strings_fts VALUES (?,?,?)",
                              [(sid, r[0], r[4]) for r in rows["strings"]])

    def save_analysis(self, sid, s):
        rows = s.analysis_rows()
        with self.tx() as c:
            self._replace(c, sid, ANALYSIS_TABLES, rows)
            self._indicators(c, sid, s.indicators())
            c.execute("UPDATE samples SET analysed_at=?, analysis_phase='complete' WHERE id=?",
                      (now(), sid))

    def set_annotation(self, sid, va, kind, text):
        with self.tx() as c:
            if text:
                c.execute("INSERT OR REPLACE INTO annotations VALUES (?,?,?,?,?)",
                          (sid, va, kind, text, now()))
            else:
                c.execute("DELETE FROM annotations WHERE sample_id=? AND va=? AND kind=?",
                          (sid, va, kind))

    # ---------------- reads ----------------

    def annotations(self, sid):
        names, comments = {}, {}
        with self.tx() as c:
            for va, kind, text in c.execute(
                    "SELECT va, kind, text FROM annotations WHERE sample_id=?", (sid,)):
                (names if kind == "name" else comments)[va] = text
        return names, comments

    def list_samples(self):
        with self.tx() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("""
                SELECT s.id, s.name, s.sha256, s.size, s.arch, s.is_dll, s.pdb, s.parent_id,
                       s.parent_offset, s.added_at, s.analysed_at, s.blob IS NOT NULL AS has_blob,
                       (SELECT COUNT(*) FROM functions f WHERE f.sample_id=s.id) AS functions,
                       (SELECT MAX(score) FROM functions f WHERE f.sample_id=s.id) AS top_score,
                       (SELECT COUNT(*) FROM indicators i WHERE i.sample_id=s.id) AS iocs
                FROM samples s ORDER BY COALESCE(s.parent_id, s.id), s.parent_id IS NOT NULL, s.id
            """).fetchall()
        return [dict(r) for r in rows]

    def get_sample(self, sid):
        with self.tx() as c:
            r = c.execute("SELECT name, blob, parent_id, parent_offset FROM samples WHERE id=?",
                          (sid,)).fetchone()
        if not r:
            return None
        name, blob, pid, poff = r
        return {"name": name, "data": decode_blob(blob) if blob else None,
                "parent_id": pid, "parent_offset": poff}

    def iocs(self, sid):
        with self.tx() as c:
            return c.execute("SELECT kind, value, source, offset FROM indicators "
                             "WHERE sample_id=? ORDER BY kind, value", (sid,)).fetchall()

    def query_readonly(self, sql, params=None, max_rows=2000, timeout=10.0):
        uri = pathlib.Path(self.path).as_uri() + "?mode=ro"
        c = sqlite3.connect(uri, uri=True, timeout=5)
        deadline = time.time() + timeout
        c.set_progress_handler(lambda: int(time.time() > deadline), 10000)
        try:
            c.execute("PRAGMA query_only=ON")
            cur = c.execute(sql, params or ())
            cols = [d[0] for d in cur.description or []]
            rows = []
            for r in cur:
                rows.append([f"<blob {len(v)} bytes>" if isinstance(v, (bytes, memoryview)) else v
                             for v in r])
                if len(rows) >= max_rows:
                    break
            return cols, rows, len(rows) >= max_rows
        finally:
            c.close()
