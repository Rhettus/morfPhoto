#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Comprehensive tests for morfPhoto docker/clip worker (search, backfill, index)."""

import json
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from threading import Event

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "docker" / "clip"))

from backfill import PhotoFailure, PhotoStalled, fingerprint, pass_catalog  # noqa: E402
from index import EmbeddingIndex, parse_revision  # noqa: E402
from search import SemanticSearch  # noqa: E402


# Exact SQLite schema from include/morfphoto/PhotoSchema.h (v1..v8)
SCHEMA_V1 = [
    """CREATE TABLE folders (
      id            INTEGER PRIMARY KEY,
      path          TEXT    NOT NULL UNIQUE,
      root_path     TEXT    NOT NULL,
      label         TEXT,
      enabled       INTEGER NOT NULL DEFAULT 1,
      auto_disabled INTEGER NOT NULL DEFAULT 0,
      recursive     INTEGER NOT NULL DEFAULT 1,
      added_at      TEXT    NOT NULL,
      last_scan_at  TEXT
    )""",
    """CREATE TABLE files (
      id                    INTEGER PRIMARY KEY,
      folder_id             INTEGER NOT NULL REFERENCES folders(id),
      path                  TEXT    NOT NULL UNIQUE,
      directory             TEXT    NOT NULL,
      filename              TEXT    NOT NULL,
      extension             TEXT,
      file_type             TEXT,
      size                  INTEGER NOT NULL,
      mtime                 INTEGER NOT NULL,
      taken_at              TEXT,
      taken_year            INTEGER GENERATED ALWAYS AS
                            (CAST(strftime('%Y', taken_at) AS INTEGER)) STORED,
      make                  TEXT,
      camera_model          TEXT,
      lens                  TEXT,
      focal_length          REAL,
      focal_length_35mm     REAL,
      aperture              REAL,
      shutter_speed         TEXT,
      shutter_speed_s       REAL,
      iso                   INTEGER,
      exposure_compensation REAL,
      rating                INTEGER,
      latitude              REAL,
      longitude             REAL,
      raw_exif              TEXT,
      state                 TEXT    NOT NULL DEFAULT 'present',
      exif_ok               INTEGER NOT NULL DEFAULT 0,
      first_seen_at         TEXT    NOT NULL,
      last_seen_at          TEXT    NOT NULL,
      last_indexed_at       TEXT    NOT NULL,
      disappeared_at        TEXT
    )""",
    "CREATE INDEX idx_files_folder ON files(folder_id)",
    "CREATE INDEX idx_files_state  ON files(state)",
    "CREATE INDEX idx_files_year   ON files(taken_year)",
    "CREATE INDEX idx_files_camera ON files(camera_model)",
    "CREATE INDEX idx_files_lens   ON files(lens)",
    "CREATE INDEX idx_files_type   ON files(file_type)",
    """CREATE TABLE index_runs (
      id            INTEGER PRIMARY KEY,
      started_at    TEXT    NOT NULL,
      finished_at   TEXT,
      mode          TEXT    NOT NULL,
      trigger       TEXT    NOT NULL DEFAULT 'watch',
      state         TEXT    NOT NULL,
      files_seen    INTEGER NOT NULL DEFAULT 0,
      files_new     INTEGER NOT NULL DEFAULT 0,
      files_updated INTEGER NOT NULL DEFAULT 0,
      files_missing INTEGER NOT NULL DEFAULT 0,
      errors_count  INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE index_errors (
      id          INTEGER PRIMARY KEY,
      run_id      INTEGER NOT NULL REFERENCES index_runs(id),
      path        TEXT,
      stage       TEXT    NOT NULL,
      message     TEXT    NOT NULL,
      occurred_at TEXT    NOT NULL
    )""",
]

SCHEMA_V2 = ["ALTER TABLE folders ADD COLUMN deleted_at TEXT"]
SCHEMA_V3 = ["ALTER TABLE index_runs ADD COLUMN files_unavailable INTEGER NOT NULL DEFAULT 0"]
SCHEMA_V4 = [
    "ALTER TABLE folders ADD COLUMN removable INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE folders ADD COLUMN volume_label TEXT",
    "ALTER TABLE folders ADD COLUMN analytics_excluded INTEGER NOT NULL DEFAULT 0",
]
SCHEMA_V5 = [
    """CREATE TABLE folder_contexts (
      directory     TEXT    PRIMARY KEY,
      schema        INTEGER,
      context       TEXT,
      subject       TEXT,
      motif         TEXT,
      description   TEXT,
      created       TEXT,
      updated       TEXT,
      source_mtime  INTEGER,
      status        TEXT    NOT NULL,
      warnings      TEXT,
      error         TEXT,
      indexed_at    TEXT    NOT NULL
    )""",
    "CREATE INDEX idx_ctx_context ON folder_contexts(context)",
    "CREATE INDEX idx_ctx_subject ON folder_contexts(subject)",
]
SCHEMA_V6 = ["CREATE INDEX IF NOT EXISTS idx_files_dir_state ON files(directory, state)"]
SCHEMA_V7 = [
    """CREATE TABLE library_files (
      file_id        INTEGER PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
      fingerprint    TEXT NOT NULL,
      kind_label     TEXT NOT NULL,
      ext_label      TEXT NOT NULL,
      camera_label   TEXT NOT NULL,
      body_key       TEXT NOT NULL,
      body_serial    TEXT NOT NULL,
      iso_label      TEXT NOT NULL,
      aperture_label TEXT NOT NULL,
      focal_label    TEXT NOT NULL,
      shutter_label  TEXT NOT NULL
    )""",
    """CREATE TABLE library_versions (
      id           INTEGER PRIMARY KEY,
      file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      version      INTEGER NOT NULL,
      is_copy      INTEGER NOT NULL,
      sidecar      TEXT,
      rating       INTEGER NOT NULL,
      rejected     INTEGER NOT NULL,
      labels       INTEGER NOT NULL,
      edited       INTEGER,
      taken_at     TEXT,
      latitude     REAL,
      longitude    REAL,
      title        TEXT,
      description  TEXT,
      creator      TEXT,
      rights       TEXT,
      version_name TEXT,
      raw_xmp      TEXT,
      UNIQUE (file_id, version)
    )""",
    """CREATE TABLE library_keywords (
      version_id INTEGER NOT NULL REFERENCES library_versions(id) ON DELETE CASCADE,
      keyword    TEXT    NOT NULL,
      PRIMARY KEY (version_id, keyword)
    ) WITHOUT ROWID""",
    "CREATE INDEX idx_library_keyword ON library_keywords(keyword)",
    "CREATE INDEX idx_library_rating  ON library_versions(rating, rejected)",
    "CREATE INDEX idx_library_taken   ON library_versions(taken_at)",
    "CREATE INDEX idx_library_camera  ON library_files(camera_label)",
]
SCHEMA_V8 = [
    "CREATE INDEX IF NOT EXISTS idx_files_folder_dir ON files(folder_id, directory)",
    "CREATE INDEX IF NOT EXISTS idx_files_state_taken ON files(state, taken_at, id)",
    "CREATE INDEX IF NOT EXISTS idx_library_ver_lookup ON library_versions(version, edited, file_id)",
    "CREATE INDEX IF NOT EXISTS idx_library_rejected_rating ON library_versions(rejected, rating)",
    "CREATE INDEX IF NOT EXISTS idx_library_ext ON library_files(ext_label)",
    "CREATE INDEX IF NOT EXISTS idx_library_kind ON library_files(kind_label)",
]
SCHEMA_V9 = [
    """CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
      filename,
      content='files',
      content_rowid='id',
      tokenize='trigram'
    )""",
    """CREATE TRIGGER IF NOT EXISTS files_fts_ai AFTER INSERT ON files BEGIN
      INSERT INTO files_fts(rowid, filename) VALUES (new.id, new.filename);
    END""",
    """CREATE TRIGGER IF NOT EXISTS files_fts_ad AFTER DELETE ON files BEGIN
      INSERT INTO files_fts(files_fts, rowid, filename) VALUES ('delete', old.id, old.filename);
    END""",
    """CREATE TRIGGER IF NOT EXISTS files_fts_au AFTER UPDATE OF filename ON files BEGIN
      INSERT INTO files_fts(files_fts, rowid, filename) VALUES ('delete', old.id, old.filename);
      INSERT INTO files_fts(rowid, filename) VALUES (new.id, new.filename);
    END""",
    "INSERT INTO files_fts(files_fts) VALUES('rebuild')",
]


def create_catalog_db(path: Path, version: int = 9):
    with closing(sqlite3.connect(path)) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")
        migrations = (
            SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4,
            SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, SCHEMA_V8, SCHEMA_V9,
        )
        for stmts in migrations[:version]:
            for s in stmts:
                db.execute(s)
        db.execute(f"PRAGMA user_version = {version}")
        db.commit()


def unit_vec(seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(512).astype(np.float32)
    return v / np.linalg.norm(v)


def basis_vec(idx: int) -> np.ndarray:
    v = np.zeros(512, dtype=np.float32)
    v[idx] = 1.0
    return v


class FakeTextModel:
    def __init__(self, mapping=None, default=None):
        self.mapping = mapping or {}
        self.default = default if default is not None else basis_vec(0)

    def text(self, q):
        return self.mapping.get(q, self.default)


class FakeApi:
    def __init__(self, catalog_path: Path, is_indexing=False):
        self.catalog_path = catalog_path
        self.is_indexing = is_indexing
        self.requests = []
        self.override_items = None
        self.indexing_calls = 0

    def indexing(self):
        self.indexing_calls += 1
        if callable(self.is_indexing):
            return self.is_indexing(self.indexing_calls)
        return self.is_indexing

    def get(self, path, maximum):
        self.requests.append((path, maximum))
        if path.startswith("/api/v1/library?ids="):
            assert "&raw=true" in path
            if self.override_items is not None:
                return json.dumps({"items": self.override_items}).encode()
            ids_str = path.split("ids=", 1)[1].split("&", 1)[0]
            ids = [int(x) for x in ids_str.split(",") if x]
            with closing(sqlite3.connect(self.catalog_path)) as db:
                db.row_factory = sqlite3.Row
                items = []
                # Return in reverse order to ensure SemanticSearch restores rank order
                for pid in reversed(ids):
                    row = db.execute(
                        "SELECT id, path, size, mtime, filename FROM files WHERE id = ?",
                        (pid,),
                    ).fetchone()
                    if row:
                        items.append(dict(row))
            return json.dumps({"items": items}).encode()
        raise AssertionError(f"Unexpected API path: {path}")


class FakeVision:
    def __init__(self, handler=None):
        self.calls = []
        self.handler = handler

    def image(self, path, report_phase):
        self.calls.append(path)
        report_phase("preview")
        report_phase("decode_inference")
        if self.handler is not None:
            return self.handler(path, report_phase)
        return basis_vec(len(self.calls) % 512)


class TestEmbeddingIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.emb_db = self.dir / "embeddings.db"
        self.version = "rev1:v1"

    def tearDown(self):
        self.tmp.cleanup()

    def test_init_store_growth_and_reload(self):
        idx = EmbeddingIndex(self.emb_db, self.version)
        self.addCleanup(idx.close)
        self.assertEqual(len(idx._photo_ids), 1024)
        self.assertEqual(idx._count, 0)

        # Store 1024 items (fills initial capacity), using batched commit=False + flush()
        for i in range(1, 1025):
            fp = fingerprint(f"/p/{i}.jpg", 100 + i, 1000 + i)
            idx.store(i, fp, unit_vec(i), commit=False)
        idx.flush()
        self.assertEqual(idx._count, 1024)
        self.assertEqual(len(idx._photo_ids), 1024)
        self.assertEqual(len(idx._photo_id_list), 1024)

        # 1025th triggers growth: 1024 + max(1024, 1024 // 4) = 2048
        fp_1025 = fingerprint("/p/1025.jpg", 1125, 2025)
        v_1025 = unit_vec(1025)
        idx.store(1025, fp_1025, v_1025)
        self.assertEqual(idx._count, 1025)
        self.assertEqual(len(idx._photo_ids), 2048)
        self.assertEqual(len(idx._revisions), 2048)
        self.assertEqual(idx._vectors.shape, (2048, 512))

        # Update existing item (photo_id=5)
        fp_5_new = fingerprint("/p/5.jpg", 9999, 8888)
        v_5_new = unit_vec(99999)
        idx.store(5, fp_5_new, v_5_new)
        self.assertEqual(idx._count, 1025)
        self.assertTrue(idx.current(5, fp_5_new))
        self.assertFalse(idx.current(5, fingerprint("/p/5.jpg", 105, 1005)))

        # Record failure with commit=False + flush() and verify persistence across reload
        fp_fail = fingerprint("/p/bad.jpg", 50, 60)
        idx.record_failure(2000, fp_fail, "HTTP 404", commit=False)
        idx.flush()
        self.assertTrue(idx.is_failed(2000, parse_revision(fp_fail)))

        # Storing a photo clears any prior failure for that photo_id
        idx.record_failure(5, fp_5_new, "transient")
        self.assertTrue(idx.is_failed(5, parse_revision(fp_5_new)))
        idx.store(5, fp_5_new, v_5_new)
        self.assertFalse(idx.is_failed(5, parse_revision(fp_5_new)))

        # Reload from SQLite (>1024 items -> initial capacity = count = 1025)
        with closing(idx.connect()) as db, db:
            db.execute(
                "INSERT INTO embedding VALUES (?, ?, ?, ?)",
                (999999, fingerprint("/p/other.jpg", 1, 1), "other-version", unit_vec(1).astype("<f4").tobytes()),
            )
        reloaded = EmbeddingIndex(self.emb_db, self.version)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded._count, 1025)
        self.assertEqual(len(reloaded._photo_ids), 1025)
        self.assertEqual(len(reloaded._photo_id_list), 1025)
        self.assertTrue(reloaded.current(1025, fp_1025))
        self.assertTrue(reloaded.current(5, fp_5_new))
        self.assertTrue(reloaded.is_failed(2000, parse_revision(fp_fail)))
        self.assertFalse(reloaded.has_revision(999999, ("/p/other.jpg", 1, 1)))
        np.testing.assert_allclose(
            reloaded._vectors[reloaded._id_to_slot[1025]], v_1025, atol=1e-6
        )

        # Verify diff_catalog returns exact counts and pending list in one lock acquisition
        rows = [
            (5, "/p/5.jpg", 9999, 8888),
            (2000, "/p/bad.jpg", 50, 60),
            (3000, "/p/new.jpg", 77, 88),
        ]
        n_idx, n_fail, pending = reloaded.diff_catalog(rows)
        self.assertEqual((n_idx, n_fail), (1, 1))
        self.assertEqual(pending, [(3000, "/p/new.jpg", 77, 88)])

        # Verify 1.25x growth past initial capacity when loaded > 4096
        big_db = self.dir / "big_embeddings.db"
        with closing(sqlite3.connect(big_db)) as db, db:
            db.execute("""
                CREATE TABLE embedding (
                    photo_id INTEGER PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vector BLOB NOT NULL CHECK (length(vector) = 2048)
                )
            """)
            db.execute("""
                CREATE TABLE failed_embedding (
                    photo_id INTEGER PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    version TEXT NOT NULL,
                    error TEXT NOT NULL
                )
            """)
            blob = unit_vec(1).astype("<f4").tobytes()
            db.executemany(
                "INSERT INTO embedding VALUES (?, ?, ?, ?)",
                [(i, fingerprint(f"/big/{i}.jpg", i, i), self.version, blob) for i in range(1, 5001)],
            )
        big_idx = EmbeddingIndex(big_db, self.version)
        self.addCleanup(big_idx.close)
        self.assertEqual(big_idx._count, 5000)
        self.assertEqual(len(big_idx._photo_ids), 5000)
        big_idx.store(5001, fingerprint("/big/5001.jpg", 5001, 5001), unit_vec(2))
        self.assertEqual(big_idx._count, 5001)
        self.assertEqual(len(big_idx._photo_ids), 6250)  # 5000 + 5000 // 4

    def test_prune_noop_swap_compaction_and_large_batch(self):
        idx = EmbeddingIndex(self.emb_db, self.version)
        self.addCleanup(idx.close)
        vecs = {}
        fps = {}
        for i in range(1, 7):
            fp = fingerprint(f"/p/{i}.jpg", i * 10, i * 100)
            v = unit_vec(i)
            idx.store(i, fp, v)
            fps[i] = fp
            vecs[i] = v

        # No-op when all active
        self.assertEqual(idx.prune({1, 2, 3, 4, 5, 6}), 0)
        self.assertEqual(idx._count, 6)

        # Remove first (1), middle (3), and last (6) together -> swap-with-last compaction
        pruned = idx.prune({2, 4, 5})
        self.assertEqual(pruned, 3)
        self.assertEqual(idx._count, 3)
        self.assertEqual(len(idx._photo_id_list), 3)
        self.assertEqual(set(idx._id_to_slot.keys()), {2, 4, 5})
        for pid in (2, 4, 5):
            slot = idx._id_to_slot[pid]
            self.assertEqual(int(idx._photo_ids[slot]), pid)
            self.assertEqual(idx._photo_id_list[slot], pid)
            self.assertEqual(idx._revisions[slot], parse_revision(fps[pid]))
            np.testing.assert_allclose(idx._vectors[slot], vecs[pid], atol=1e-6)
        for pid in (1, 3, 6):
            self.assertFalse(idx.current(pid, fps[pid]))

        # Reload verifies SQLite rows were also deleted
        reloaded = EmbeddingIndex(self.emb_db, self.version)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded._count, 3)
        self.assertEqual(set(reloaded._id_to_slot.keys()), {2, 4, 5})

        # >500 batch delete (store 650 items, prune 620 of them)
        for i in range(100, 750):
            idx.store(i, fingerprint(f"/b/{i}.jpg", i, i), unit_vec(i), commit=False)
            if i % 2 == 0:
                idx.record_failure(i + 10000, fingerprint(f"/f/{i}.jpg", i, i), "err", commit=False)
        idx.flush()
        keep_ids = {2, 4, 5} | set(range(100, 130))
        pruned_big = idx.prune(keep_ids)
        self.assertEqual(pruned_big, 620)
        self.assertEqual(idx._count, 33)
        self.assertEqual(len(idx._photo_id_list), 33)
        self.assertEqual(len(idx._failed), 0)

    def test_rank_paths_tie_breaking_and_legacy_candidates(self):
        idx = EmbeddingIndex(self.emb_db, self.version)
        self.addCleanup(idx.close)
        same_v = basis_vec(0)
        revs = {}
        str_cands = {}
        for i in range(1, 7):
            fp = fingerprint(f"/t/{i}.jpg", 100, i)
            idx.store(i, fp, same_v)
            revs[i] = parse_revision(fp)
            str_cands[i] = fp

        query = np.zeros(512, dtype=np.float32)
        query[0] = 0.6
        query[1] = 0.8

        v7 = np.zeros(512, dtype=np.float32)
        v7[0] = 0.6
        v7[1] = 0.8  # dot = 1.0
        idx.store(7, fingerprint("/t/7.jpg", 100, 7), v7)
        revs[7] = parse_revision(fingerprint("/t/7.jpg", 100, 7))

        v8 = basis_vec(2)  # dot = 0.0
        idx.store(8, fingerprint("/t/8.jpg", 100, 8), v8)
        revs[8] = parse_revision(fingerprint("/t/8.jpg", 100, 8))

        for i in range(9, 13):
            fp = fingerprint(f"/t/{i}.jpg", 100, i)
            idx.store(i, fp, -basis_vec(1))  # dot = -0.8
            revs[i] = parse_revision(fp)

        # Small candidate dict (< 25% of count=12 -> 2 candidates)
        small_cands = {2: revs[2], 7: revs[7]}
        ranked_small, indexed_small = idx.rank(query, small_cands, limit=2)
        self.assertEqual(indexed_small, 2)
        self.assertEqual([pid for _, pid in ranked_small], [7, 2])

        # Mid-density candidate dict (25% <= density < 100% -> zero-copy contiguous matmul path)
        mid_cands = {i: revs[i] for i in (1, 2, 7, 8, 9)}
        ranked_mid, indexed_mid = idx.rank(query, mid_cands, limit=5)
        self.assertEqual(indexed_mid, 5)
        self.assertEqual([pid for _, pid in ranked_mid], [7, 1, 2, 8, 9])

        # Legacy string candidate dict
        ranked_str, indexed_str = idx.rank(query, str_cands, limit=3)
        self.assertEqual(indexed_str, 6)
        self.assertEqual([pid for _, pid in ranked_str], [1, 2, 3, 4])

        # High-density candidate dict (11/12 valid, 1 stale) + exact tie-break pagination
        full_cands = dict(revs)
        full_cands[8] = ("/t/8.jpg", 999999, 8)  # stale mismatch -> excluded!
        seen = []
        after = None
        while True:
            page, indexed = idx.rank(query, full_cands, limit=2, after=after)
            self.assertEqual(indexed, 11)  # 12 stored minus stale #8
            top = page[:2]
            seen.extend(pid for _, pid in top)
            if len(page) <= 2:
                break
            after = page[1]
        self.assertEqual(seen, [7, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12])

        # Invalid limit
        with self.assertRaises(ValueError):
            idx.rank(query, full_cands, limit=0)
        with self.assertRaises(ValueError):
            idx.rank(query, full_cands, limit=251)

    def test_benchmark_150k_ranking(self):
        idx = EmbeddingIndex(self.emb_db, self.version)
        self.addCleanup(idx.close)
        n = 150_000
        rng = np.random.default_rng(42)
        t0 = time.perf_counter()
        vecs = rng.standard_normal((n, 512), dtype=np.float32)
        vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
        idx._photo_ids = np.arange(1, n + 1, dtype=np.int64)
        idx._photo_id_list = list(range(1, n + 1))
        idx._vectors = np.ascontiguousarray(vecs)
        idx._revisions = [("/p", 1, i) for i in range(1, n + 1)]
        idx._id_to_slot = {i + 1: i for i in range(n)}
        idx._count = n
        setup_s = time.perf_counter() - t0

        query = unit_vec(777)
        full_cands = {i: ("/p", 1, i) for i in range(1, n + 1)}
        almost_full_cands = {i: ("/p", 1, i) for i in range(1, n)}  # N-1: exercises zero-copy path!
        small_cands = {i: ("/p", 1, i) for i in range(1, 5001)}

        # Warm up + measure full 150k
        idx.rank(query, full_cands, limit=100)
        t1 = time.perf_counter()
        ranked_full, indexed_full = idx.rank(query, full_cands, limit=100)
        full_ms = (time.perf_counter() - t1) * 1000.0
        self.assertEqual(indexed_full, n)
        self.assertEqual(len(ranked_full), 101)

        # Measure N-1 (149,999 out of 150,000 - previously triggered 307 MB copy!)
        t1b = time.perf_counter()
        ranked_almost, indexed_almost = idx.rank(query, almost_full_cands, limit=100)
        almost_ms = (time.perf_counter() - t1b) * 1000.0
        self.assertEqual(indexed_almost, n - 1)
        self.assertEqual(len(ranked_almost), 101)

        # Measure subset 5k out of 150k
        t2 = time.perf_counter()
        ranked_sub, indexed_sub = idx.rank(query, small_cands, limit=100)
        sub_ms = (time.perf_counter() - t2) * 1000.0
        self.assertEqual(indexed_sub, 5000)
        self.assertEqual(len(ranked_sub), 101)

        print(
            f"\n[BENCHMARK] 150k vectors: setup={setup_s:.3f}s, "
            f"full_150k={full_ms:.2f}ms, almost_full_149999={almost_ms:.2f}ms, subset_5k={sub_ms:.2f}ms",
            flush=True,
        )


class TestSemanticSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.catalog = self.dir / "photos.db"
        self.emb_db = self.dir / "embeddings.db"
        create_catalog_db(self.catalog)
        self.idx = EmbeddingIndex(self.emb_db, "rev1:v1")
        self.api = FakeApi(self.catalog)
        self.model = FakeTextModel()
        self._populate_catalog()
        self.searcher = SemanticSearch(self.api, self.model, self.idx, self.catalog)

    def tearDown(self):
        self.searcher.close()
        self.idx.close()
        self.tmp.cleanup()

    def _populate_catalog(self):
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute(
                "INSERT INTO folders (id, path, root_path, enabled, added_at) VALUES "
                "(1, '/photos', '/photos', 1, '2026-01-01T00:00:00Z'),"
                "(2, '/photos2', '/photos2', 1, '2026-01-01T00:00:00Z')"
            )

            files = [
                (1, 1, "/photos/a.jpg", "/photos", "a.jpg", ".jpg", "jpeg", 1001, 1700000001, "2026-05-01T10:00:00", "Canon", "Canon EOS R5", "RF 50mm", 50.0, 2.8, "1/500", 100, "present"),
                (2, 1, "/photos/sub/b.arw", "/photos/sub", "b.arw", ".arw", "raw", 1002, 1700000002, "2026-05-10T10:00:00", "Sony", "ILCE-7M4", "FE 85mm", 85.0, 1.4, "1/1000", 800, "present"),
                (3, 1, "/photos/sub/deep/c.jpg", "/photos/sub/deep", "c.jpg", ".jpg", "jpeg", 1003, 1700000003, "2026-06-01T10:00:00", "Nikon", "NIKON Z 8", "Z 35mm", 35.0, 2.0, "1/250", 400, "present"),
                (4, 2, "/photos2/d.jpg", "/photos2", "d.jpg", ".jpg", "jpeg", 1004, 1700000004, "2026-06-15T10:00:00", "Canon", "Canon EOS R5", "RF 50mm", 50.0, 2.8, "1/500", 100, "present"),
                (5, 1, "/photos/e.jpg", "/photos", "e.jpg", ".jpg", "jpeg", 1005, 1700000005, "2026-05-05T10:00:00", "Canon", "Canon EOS R5", "RF 50mm", 50.0, 2.8, "1/500", 100, "present"),
                (6, 1, "/photos/f.jpg", "/photos", "f.jpg", ".jpg", "jpeg", 1006, 1700000006, "2026-05-06T10:00:00", "Canon", "Canon EOS R5", "RF 50mm", 50.0, 2.8, "1/500", 100, "present"),
                (7, 1, "/photos/g.jpg", "/photos", "g.jpg", ".jpg", "jpeg", 1007, 1700000007, "2026-05-07T10:00:00", "Canon", "Canon EOS R5", "RF 50mm", 50.0, 2.8, "1/500", 100, "missing"),
                (8, 1, "/h.jpg", "/", "h.jpg", ".jpg", "jpeg", 1008, 1700000008, "2026-04-01T10:00:00", "Fuji", "X-T5", "XF 23mm", 23.0, 2.0, "1/125", 200, "present"),
            ]
            for row in files:
                db.execute(
                    "INSERT INTO files (id, folder_id, path, directory, filename, extension, file_type, "
                    "size, mtime, taken_at, make, camera_model, lens, focal_length, aperture, shutter_speed, "
                    "iso, state, first_seen_at, last_seen_at, last_indexed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "'2026-01-01', '2026-01-01', '2026-01-01')",
                    row,
                )

            lib_files = [
                (1, "fp1", "JPEG", "jpg", "Canon R5", "canon-r5", "SN1", "100", "f/2.8", "50 mm", "1/500 s"),
                (2, "fp2", "RAW", "arw", "Sony A7IV", "sony-a7iv", "SN2", "800", "f/1.4", "85 mm", "1/1000 s"),
                (3, "fp3", "JPEG", "jpg", "Nikon Z8", "nikon-z8", "SN3", "400", "f/2", "35 mm", "1/250 s"),
                (4, "fp4", "JPEG", "jpg", "Canon R5", "canon-r5", "SN1", "100", "f/2.8", "50 mm", "1/500 s"),
                (5, "fp5", "JPEG", "jpg", "Canon R5", "canon-r5", "SN1", "100", "f/2.8", "50 mm", "1/500 s"),
                (6, "fp6", "JPEG", "jpg", "Canon R5", "canon-r5", "SN1", "100", "f/2.8", "50 mm", "1/500 s"),
                (7, "fp7", "JPEG", "jpg", "Canon R5", "canon-r5", "SN1", "100", "f/2.8", "50 mm", "1/500 s"),
                (8, "fp8", "JPEG", "jpg", "Fuji X-T5", "fuji-xt5", "SN4", "200", "f/2", "23 mm", "1/125 s"),
            ]
            for row in lib_files:
                db.execute("INSERT INTO library_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", row)

            versions = [
                (1, 1, 0, 0, None, 5, 0, 1, 0, "2026-05-01T10:00:00"),
                (2, 2, 0, 0, "b.xmp", 3, 1, 2, 0, "2026-05-10T10:00:00"),
                (3, 3, 0, 0, None, 0, 0, 0, 0, "2026-06-01T10:00:00"),
                (4, 4, 0, 0, None, 4, 0, 4, 0, "2026-06-15T10:00:00"),
                (5, 5, 0, 0, "e.xmp", 5, 0, 1, 1, "2026-05-05T10:00:00"),
                (6, 6, 0, 0, None, 1, 0, 0, 0, "2026-05-06T10:00:00"),
                (7, 6, 1, 1, "f_01.xmp", 5, 0, 1, 0, "2026-05-06T10:00:00"),
                (8, 7, 0, 0, None, 5, 0, 1, 0, "2026-05-07T10:00:00"),
                (9, 8, 0, 0, None, 2, 0, 0, 0, "2026-04-01T10:00:00"),
            ]
            for row in versions:
                db.execute(
                    "INSERT INTO library_versions (id, file_id, version, is_copy, sidecar, rating, rejected, labels, edited, taken_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    row,
                )

            kws = [
                (1, "animal|bird|eagle"),
                (2, "animal|cat"),
                (3, "animals"),
                (7, "animal"),  # version=1 of file 6 -> must NOT match!
                (9, "animal"),
            ]
            for vid, kw in kws:
                db.execute("INSERT INTO library_keywords VALUES (?, ?)", (vid, kw))
            db.commit()

            for pid in range(1, 9):
                row = db.execute("SELECT path, size, mtime FROM files WHERE id = ?", (pid,)).fetchone()
                v = np.zeros(512, dtype=np.float32)
                v[0] = 1.0 - pid * 0.05
                v[1] = float(np.sqrt(max(0.0, 1.0 - v[0] ** 2)))
                self.idx.store(pid, fingerprint(row[0], row[1], row[2]), v)

    def _ids(self, folder="/photos", recursive=True, filters=None, **extra):
        req = {"text": "test", "folder_path": folder, "recursive": recursive, "filters": filters or {}, **extra}
        res = self.searcher.search(req)
        return [item["photo"]["id"] for item in res["items"]], res

    def test_folder_and_recursive(self):
        ids, _ = self._ids("/photos", recursive=False)
        self.assertEqual(ids, [1, 6])

        ids_slash, _ = self._ids("/photos/", recursive=False)
        self.assertEqual(ids_slash, [1, 6])

        ids_rec, _ = self._ids("/photos", recursive=True)
        self.assertEqual(ids_rec, [1, 2, 3, 6])

        ids_root_nr, _ = self._ids("/", recursive=False)
        self.assertEqual(ids_root_nr, [8])

        ids_root_rec, _ = self._ids("/", recursive=True)
        self.assertEqual(ids_root_rec, [1, 2, 3, 4, 6, 8])

    def test_all_filters(self):
        ids, _ = self._ids("/", True, {"min_rating": 3})
        self.assertEqual(ids, [1, 4])
        ids, _ = self._ids("/", True, {"min_rating": "4"})
        self.assertEqual(ids, [1, 4])

        self.assertEqual(self._ids("/", True, {"rejected": "hide"})[0], [1, 3, 4, 6, 8])
        self.assertEqual(self._ids("/", True, {"rejected": "only"})[0], [2])
        self.assertEqual(self._ids("/", True, {"rejected": "all"})[0], [1, 2, 3, 4, 6, 8])

        self.assertEqual(self._ids("/", True, {"labels": 1})[0], [1])
        self.assertEqual(self._ids("/", True, {"labels": 6})[0], [2, 4])
        self.assertEqual(self._ids("/", True, {"unlabeled": True})[0], [3, 6, 8])
        self.assertEqual(self._ids("/", True, {"labels": 1, "unlabeled": "1"})[0], [1, 3, 6, 8])
        self.assertEqual(self._ids("/", True, {"labels": 1, "unlabeled": "false"})[0], [1])

        self.assertEqual(self._ids("/", True, {"kind": "arw"})[0], [2])
        self.assertEqual(self._ids("/", True, {"kind": "RAW"})[0], [2])
        self.assertEqual(self._ids("/", True, {"kind": ["arw", "JPEG"]})[0], [1, 2, 3, 4, 6, 8])

        self.assertEqual(self._ids("/", True, {"camera": "Sony A7IV"})[0], [2])
        self.assertEqual(self._ids("/", True, {"body": ["sony-a7iv", "fuji-xt5"]})[0], [2, 8])
        self.assertEqual(self._ids("/", True, {"lens": "Z 35mm"})[0], [3])
        self.assertEqual(self._ids("/", True, {"iso": "800"})[0], [2])
        self.assertEqual(self._ids("/", True, {"aperture": "f/1.4"})[0], [2])
        self.assertEqual(self._ids("/", True, {"focal": "23 mm"})[0], [8])
        self.assertEqual(self._ids("/", True, {"shutter": "1/250 s"})[0], [3])

        self.assertEqual(self._ids("/", True, {"keyword": "animal"})[0], [1, 2, 8])
        self.assertEqual(self._ids("/", True, {"keyword": "animal|bird"})[0], [1])
        self.assertEqual(self._ids("/", True, {"keyword": "animal|bird|eagle"})[0], [1])
        self.assertEqual(self._ids("/", True, {"keyword": "animals"})[0], [3])

        self.assertEqual(self._ids("/", True, {"filename": "B.AR"})[0], [2])

        # Sargable taken_from / taken_to inclusive date bounds
        self.assertEqual(self._ids("/", True, {"taken_from": "2026-05-06", "taken_to": "2026-06-01"})[0], [2, 3, 6])
        self.assertEqual(self._ids("/", True, {"taken_from": "2026-06-01", "taken_to": "2026-06-01"})[0], [3])
        self.assertEqual(self._ids("/", True, {"taken_to": "2026-05-01"})[0], [1, 8])

    def test_candidate_cache_invalidates_on_catalog_write(self):
        # First query populates cache
        ids1, _ = self._ids("/photos", recursive=False)
        self.assertEqual(ids1, [1, 6])
        self.assertEqual(len(self.searcher._candidate_cache), 1)

        # Second identical query hits cache
        ids2, _ = self._ids("/photos", recursive=False)
        self.assertEqual(ids2, [1, 6])
        self.assertEqual(len(self.searcher._candidate_cache), 1)

        # External writer updates catalog -> PRAGMA data_version invalidates cache immediately
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("UPDATE files SET state = 'missing' WHERE id = 6")
            db.commit()
        ids3, _ = self._ids("/photos", recursive=False)
        self.assertEqual(ids3, [1])

    def test_invalid_inputs_raise_value_error(self):
        bad_requests = [
            {"text": 123, "folder_path": "/"},
            {"text": "cat", "folder_path": "relative"},
            {"text": "cat", "folder_path": "/", "recursive": "yes"},
            {"text": "cat", "folder_path": "/", "size": 0},
            {"text": "cat", "folder_path": "/", "size": 251},
            {"text": "cat", "folder_path": "/", "size": True},
            {"text": "cat", "folder_path": "/", "filters": {"unknown_key": "x"}},
            {"text": "cat", "folder_path": "/", "filters": {"min_rating": 6}},
            {"text": "cat", "folder_path": "/", "filters": {"min_rating": -1}},
            {"text": "cat", "folder_path": "/", "filters": {"min_rating": True}},
            {"text": "cat", "folder_path": "/", "filters": {"min_rating": "bad"}},
            {"text": "cat", "folder_path": "/", "filters": {"labels": 32}},
            {"text": "cat", "folder_path": "/", "filters": {"rejected": "maybe"}},
            {"text": "cat", "folder_path": "/", "filters": {"unlabeled": "maybe"}},
            {"text": "cat", "folder_path": "/", "filters": {"kind": [123]}},
            {"text": "cat", "folder_path": "/", "filters": {"camera": 42}},
            {"text": "cat", "folder_path": "/", "filters": {"filename": 42}},
            {"text": "cat", "folder_path": "/", "filters": {"taken_from": "2026/01/01"}},
            {"text": "cat", "folder_path": "/", "filters": {"taken_to": "2026-02-30"}},
        ]
        for req in bad_requests:
            with self.subTest(req=req), self.assertRaises(ValueError):
                self.searcher.search(req)

    def test_pagination_signature_mismatch_and_hydration(self):
        collected = []
        cursor = None
        while True:
            res = self.searcher.search({
                "text": "test", "folder_path": "/", "recursive": True, "size": 2, "next": cursor
            })
            self.assertEqual(res["eligible"], 6)
            self.assertEqual(res["indexed"], 6)
            self.assertEqual(res["revision"], "rev1:v1")
            collected.extend(item["photo"]["id"] for item in res["items"])
            if res["next"] is None:
                break
            cursor = res["next"]
        self.assertEqual(collected, [1, 2, 3, 4, 6, 8])

        self.assertTrue(self.api.requests[0][0].startswith("/api/v1/library?ids=1,2&raw=true"))

        first = self.searcher.search({"text": "test", "folder_path": "/", "recursive": True, "size": 2})
        cur = first["next"]
        for mutated in (
            {"text": "other", "folder_path": "/", "recursive": True, "size": 2, "next": cur},
            {"text": "test", "folder_path": "/photos", "recursive": True, "size": 2, "next": cur},
            {"text": "test", "folder_path": "/", "recursive": False, "size": 2, "next": cur},
            {"text": "test", "folder_path": "/", "recursive": True, "filters": {"min_rating": 1}, "size": 2, "next": cur},
        ):
            with self.assertRaises(ValueError):
                self.searcher.search(mutated)

        self.api.override_items = [
            {"id": 3, "path": "/photos/sub/deep/c.jpg", "size": 1003, "mtime": 1700000003},
            {"id": 2, "path": "/photos/sub/b.arw", "size": 999999, "mtime": 1700000002},
            {"id": 1, "path": "/photos/a.jpg", "size": 1001, "mtime": 1700000001},
        ]
        res = self.searcher.search({"text": "test", "folder_path": "/", "recursive": True, "size": 3})
        self.assertEqual([item["photo"]["id"] for item in res["items"]], [1, 3])

    def test_fts5_filename_search_and_legacy_fallback(self):
        # v9 catalog has files_fts -> detected on connection and used for >=3 char substrings
        ids_fts, _ = self._ids("/", True, {"filename": "B.AR"})
        self.assertEqual(ids_fts, [2])
        self.assertTrue(getattr(self.searcher._local, "has_files_fts", False))

        # < 3 char filename filter still works via instr fallback
        ids_short, _ = self._ids("/", True, {"filename": "a."})
        self.assertEqual(ids_short, [1])

        # Embedded double quote does not break FTS5 MATCH syntax
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("UPDATE files SET filename = 'odd\"name.jpg' WHERE id = 8")
            db.commit()
        ids_quote, _ = self._ids("/", True, {"filename": 'odd"na'})
        self.assertEqual(ids_quote, [8])

        # Legacy v8 catalog without files_fts falls back cleanly to instr()
        v8_catalog = self.dir / "photos_v8.db"
        create_catalog_db(v8_catalog, version=8)
        with closing(sqlite3.connect(v8_catalog)) as db:
            db.execute("INSERT INTO folders (id, path, root_path, enabled, added_at) VALUES (1, '/photos', '/photos', 1, '2026-01-01')")
            db.execute(
                "INSERT INTO files (id, folder_id, path, directory, filename, size, mtime, state, "
                "first_seen_at, last_seen_at, last_indexed_at) "
                "VALUES (1, 1, '/photos/legacy_sunset.jpg', '/photos', 'legacy_sunset.jpg', 100, 1000, 'present', "
                "'2026-01-01', '2026-01-01', '2026-01-01')"
            )
            db.execute(
                "INSERT INTO library_versions (id, file_id, version, is_copy, rating, rejected, labels, edited) "
                "VALUES (1, 1, 0, 0, 0, 0, 0, 0)"
            )
            db.commit()
        v8_idx = EmbeddingIndex(self.dir / "emb_v8.db", "rev1:v1")
        self.addCleanup(v8_idx.close)
        v8_idx.store(1, fingerprint("/photos/legacy_sunset.jpg", 100, 1000), basis_vec(0))
        v8_searcher = SemanticSearch(FakeApi(v8_catalog), self.model, v8_idx, v8_catalog)
        self.addCleanup(v8_searcher.close)
        res = v8_searcher.search({"text": "test", "folder_path": "/photos", "recursive": False, "filters": {"filename": "sunset"}})
        self.assertEqual([item["photo"]["id"] for item in res["items"]], [1])
        self.assertFalse(getattr(v8_searcher._local, "has_files_fts", True))


class TestBackfill(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.catalog = self.dir / "photos.db"
        self.emb_db = self.dir / "embeddings.db"
        create_catalog_db(self.catalog)
        self.idx = EmbeddingIndex(self.emb_db, "rev1:v1")
        self.api = FakeApi(self.catalog)
        self.searching = Event()
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("INSERT INTO folders (id, path, root_path, enabled, added_at) VALUES (1, '/photos', '/photos', 1, '2026-01-01')")
            db.commit()

    def tearDown(self):
        self.idx.close()
        self.tmp.cleanup()

    def _add_file(self, pid, name, size=100, mtime=1000, state="present"):
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute(
                "INSERT INTO files (id, folder_id, path, directory, filename, size, mtime, state, "
                "first_seen_at, last_seen_at, last_indexed_at) "
                "VALUES (?, 1, ?, '/photos', ?, ?, ?, ?, '2026-01-01', '2026-01-01', '2026-01-01')",
                (pid, f"/photos/{name}", name, size, mtime, state),
            )
            db.commit()

    def _run_pass(self, vision, indexing_poll_interval=5.0):
        events = []

        def report(state, progress):
            events.append((state, dict(progress)))

        worked = pass_catalog(
            self.catalog, self.api, vision, self.idx, report, self.searching,
            indexing_poll_interval=indexing_poll_interval,
        )
        return worked, events

    def test_zero_pending_one_new_and_modified(self):
        self._add_file(1, "p1.jpg", 100, 1000)
        self._add_file(2, "p2.jpg", 200, 2000)
        self.idx.store(1, fingerprint("/photos/p1.jpg", 100, 1000), unit_vec(1))
        self.idx.store(2, fingerprint("/photos/p2.jpg", 200, 2000), unit_vec(2))

        vision = FakeVision()
        worked, events = self._run_pass(vision)
        self.assertFalse(worked)
        self.assertEqual(vision.calls, [])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "idle")
        self.assertEqual(events[0][1]["indexed"], 2)
        self.assertEqual(events[0][1]["eligible"], 2)
        self.assertEqual(events[0][1]["phase"], "waiting")
        self.assertTrue(all(st != "warming" for st, _ in events))

        # Add 1 new photo -> processes only that 1 photo, indexed goes 2 -> 3
        self._add_file(3, "p3.jpg", 300, 3000)
        worked, events = self._run_pass(vision)
        self.assertTrue(worked)
        self.assertEqual(vision.calls, ["/photos/p3.jpg"])
        warming_indexed = [p["indexed"] for st, p in events if st == "warming"]
        self.assertEqual(warming_indexed[0], 2)
        self.assertEqual(events[-1][0], "idle")
        self.assertEqual(events[-1][1]["indexed"], 3)

        # Verify batched commit actually flushed to SQLite
        reloaded = EmbeddingIndex(self.emb_db, "rev1:v1")
        self.addCleanup(reloaded.close)
        self.assertTrue(reloaded.current(3, fingerprint("/photos/p3.jpg", 300, 3000)))

        # Modify p2 (mtime/size changed) -> re-CLIPs ONLY p2
        vision.calls.clear()
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("UPDATE files SET size = 201, mtime = 2001 WHERE id = 2")
            db.commit()
        worked, events = self._run_pass(vision)
        self.assertTrue(worked)
        self.assertEqual(vision.calls, ["/photos/p2.jpg"])
        self.assertTrue(self.idx.current(2, fingerprint("/photos/p2.jpg", 201, 2001)))
        self.assertEqual(events[-1][1]["indexed"], 3)

    def test_failure_and_stalled_retry_on_change(self):
        self._add_file(10, "fail.jpg", 100, 1000)
        self._add_file(11, "stall.jpg", 100, 1000)

        def fail_handler(path, _phase):
            if path.endswith("fail.jpg"):
                raise PhotoFailure("HTTP 404")
            if path.endswith("stall.jpg"):
                raise PhotoStalled("photo deadline exceeded")
            return unit_vec(99)

        vision = FakeVision(fail_handler)
        worked, events = self._run_pass(vision)
        self.assertTrue(worked)
        self.assertEqual(events[-1][0], "idle")
        self.assertEqual(events[-1][1]["failed"], 2)
        self.assertEqual(events[-1][1]["indexed"], 0)
        self.assertTrue(self.idx.is_failed(10, ("/photos/fail.jpg", 100, 1000)))
        self.assertTrue(self.idx.is_failed(11, ("/photos/stall.jpg", 100, 1000)))

        # Subsequent pass skips both without hitting vision
        vision.calls.clear()
        worked2, events2 = self._run_pass(vision)
        self.assertFalse(worked2)
        self.assertEqual(vision.calls, [])
        self.assertEqual(events2[-1][1]["failed"], 2)

        # Changing size/mtime retries them and clears failure on success
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("UPDATE files SET size = 101 WHERE id = 10")
            db.execute("UPDATE files SET mtime = 1002 WHERE id = 11")
            db.commit()
        vision_ok = FakeVision()
        worked3, events3 = self._run_pass(vision_ok)
        self.assertTrue(worked3)
        self.assertEqual(vision_ok.calls, ["/photos/fail.jpg", "/photos/stall.jpg"])
        self.assertEqual(events3[-1][1]["indexed"], 2)
        self.assertEqual(events3[-1][1]["failed"], 0)
        self.assertFalse(self.idx.is_failed(10, ("/photos/fail.jpg", 101, 1000)))

    def test_indexing_poll_throttling(self):
        for i in range(1, 6):
            self._add_file(i, f"t{i}.jpg", 100 + i, 1000 + i)
        self.api.indexing_calls = 0
        vision = FakeVision()
        worked, _ = self._run_pass(vision, indexing_poll_interval=5.0)
        self.assertTrue(worked)
        self.assertEqual(len(vision.calls), 5)
        # 5 photos processed quickly -> api.indexing() polled only ONCE
        self.assertEqual(self.api.indexing_calls, 1)

    def test_pause_resume_and_missing_prune(self):
        for i in range(1, 5):
            self._add_file(i, f"p{i}.jpg", 100 + i, 1000 + i)

        # Pause due to semantic_search after processing photo 1
        def pause_on_first(path, _phase):
            if path.endswith("p1.jpg"):
                self.searching.set()
            return unit_vec(1)

        vision = FakeVision(pause_on_first)
        worked, events = self._run_pass(vision)
        self.assertTrue(worked)
        self.assertEqual(vision.calls, ["/photos/p1.jpg"])
        self.assertEqual(events[-1][0], "paused")
        self.assertEqual(events[-1][1]["pause_reason"], "semantic_search")
        self.assertEqual(events[-1][1]["indexed"], 1)

        # Clear searching; pause due to photo_indexing on 2nd check (poll interval 0 for deterministic trigger)
        self.searching.clear()
        self.api.indexing_calls = 0
        self.api.is_indexing = lambda call_n: call_n >= 2
        vision2 = FakeVision()
        worked2, events2 = self._run_pass(vision2, indexing_poll_interval=0.0)
        self.assertTrue(worked2)
        self.assertEqual(vision2.calls, ["/photos/p2.jpg"])
        self.assertEqual(events2[-1][0], "paused")
        self.assertEqual(events2[-1][1]["pause_reason"], "photo_indexing")
        self.assertEqual(events2[-1][1]["indexed"], 2)

        # Resume -> processes only p3 and p4
        self.api.is_indexing = False
        vision3 = FakeVision()
        worked3, events3 = self._run_pass(vision3)
        self.assertTrue(worked3)
        self.assertEqual(vision3.calls, ["/photos/p3.jpg", "/photos/p4.jpg"])
        self.assertEqual(events3[-1][0], "idle")
        self.assertEqual(events3[-1][1]["indexed"], 4)

        # Mark p2 missing -> pruned on next pass even though pending is empty
        with closing(sqlite3.connect(self.catalog)) as db:
            db.execute("UPDATE files SET state = 'missing' WHERE id = 2")
            db.commit()
        vision4 = FakeVision()
        worked4, events4 = self._run_pass(vision4)
        self.assertFalse(worked4)
        self.assertEqual(self.idx._count, 3)
        self.assertFalse(self.idx.current(2, fingerprint("/photos/p2.jpg", 102, 1002)))
        self.assertEqual(events4[-1][1]["indexed"], 3)
        self.assertEqual(events4[-1][1]["eligible"], 3)

    def test_batched_vision_mixed_outcomes_retry_and_stall_fallback(self):
        from urllib.error import URLError

        for i in range(1, 7):
            self._add_file(i, f"b{i}.jpg", 100 + i, 1000 + i)

        class FakeBatchVision:
            def __init__(self, batch_handler, single_handler=None):
                self.batch_calls = []
                self.single_calls = []
                self.batch_handler = batch_handler
                self.single_handler = single_handler

            def images(self, paths, report_phase):
                self.batch_calls.append(list(paths))
                report_phase("preview")
                report_phase("decode_inference")
                return self.batch_handler(paths, report_phase)

            def image(self, path, report_phase):
                self.single_calls.append(path)
                report_phase("preview")
                report_phase("decode_inference")
                if self.single_handler is not None:
                    return self.single_handler(path, report_phase)
                return unit_vec(len(self.single_calls) + 50)

        # 1) Mixed batch: successes + failure, then retry error raises URLError after storing prior successes
        def mixed_handler(paths, _phase):
            out = []
            for idx, p in enumerate(paths):
                if p.endswith("b2.jpg"):
                    out.append(("failure", "HTTP 404"))
                elif p.endswith("b5.jpg"):
                    out.append(("retry", "HTTP 503"))
                else:
                    out.append(("result", unit_vec(idx + 10)))
            return out

        vision = FakeBatchVision(mixed_handler)
        events = []
        with self.assertRaises(URLError):
            pass_catalog(
                self.catalog, self.api, vision, self.idx,
                lambda s, p: events.append((s, dict(p))),
                self.searching, batch_size=3,
            )
        self.assertEqual(len(vision.batch_calls), 2)
        self.assertEqual(vision.batch_calls[0], ["/photos/b1.jpg", "/photos/b2.jpg", "/photos/b3.jpg"])
        self.assertEqual(vision.batch_calls[1], ["/photos/b4.jpg", "/photos/b5.jpg", "/photos/b6.jpg"])
        # b1, b3, b4, b6 stored; b2 recorded failed; b5 left pending (not failed!) for retry
        self.assertTrue(self.idx.current(1, fingerprint("/photos/b1.jpg", 101, 1001)))
        self.assertTrue(self.idx.is_failed(2, ("/photos/b2.jpg", 102, 1002)))
        self.assertTrue(self.idx.current(3, fingerprint("/photos/b3.jpg", 103, 1003)))
        self.assertTrue(self.idx.current(4, fingerprint("/photos/b4.jpg", 104, 1004)))
        self.assertFalse(self.idx.is_failed(5, ("/photos/b5.jpg", 105, 1005)))
        self.assertTrue(self.idx.current(6, fingerprint("/photos/b6.jpg", 106, 1006)))

        # 2) Whole-batch stall falls back to per-photo vision.image(), isolating the stalling photo
        self._add_file(7, "b7.jpg", 107, 1007)
        self._add_file(8, "b8.jpg", 108, 1008)

        def stall_batch(_paths, _phase):
            raise PhotoStalled("batch deadline exceeded")

        def single_fallback(path, _phase):
            if path.endswith("b7.jpg"):
                raise PhotoStalled("photo deadline exceeded")
            return unit_vec(88)

        vision2 = FakeBatchVision(stall_batch, single_fallback)
        events2 = []
        worked = pass_catalog(
            self.catalog, self.api, vision2, self.idx,
            lambda s, p: events2.append((s, dict(p))),
            self.searching, batch_size=3,
        )
        self.assertTrue(worked)
        self.assertEqual(vision2.batch_calls, [["/photos/b5.jpg", "/photos/b7.jpg", "/photos/b8.jpg"]])
        self.assertEqual(vision2.single_calls, ["/photos/b5.jpg", "/photos/b7.jpg", "/photos/b8.jpg"])
        self.assertTrue(self.idx.current(5, fingerprint("/photos/b5.jpg", 105, 1005)))
        self.assertTrue(self.idx.is_failed(7, ("/photos/b7.jpg", 107, 1007)))
        self.assertTrue(self.idx.current(8, fingerprint("/photos/b8.jpg", 108, 1008)))
        self.assertEqual(events2[-1][0], "idle")


class TestPhotoApiKeepAliveGzip(unittest.TestCase):
    def test_keepalive_gzip_and_retry(self):
        import gzip
        import http.client
        from unittest.mock import patch
        from urllib.error import HTTPError
        from backfill import PhotoApi

        payload = json.dumps({"items": [{"id": i} for i in range(100)]}).encode()
        gz_payload = gzip.compress(payload)
        calls = []

        class FakeResp:
            def __init__(self, status, body, headers=None, will_close=False):
                self.status = status
                self.reason = "OK" if status == 200 else "Not Found"
                self._body = body
                self.headers = headers or {}
                self.will_close = will_close

            def read(self, n=-1):
                return self._body if n < 0 else self._body[:n]

            def getheader(self, name, default=None):
                for k, v in self.headers.items():
                    if k.lower() == name.lower():
                        return v
                return default

        conns = []

        class FakeConn:
            def __init__(self, host, port, timeout=30):
                self.closed = False
                self.reqs = 0
                conns.append(self)

            def request(self, method, path, headers=None):
                calls.append((method, path, dict(headers or {})))
                self.reqs += 1
                if len(calls) == 2:
                    raise http.client.RemoteDisconnected("stale")

            def getresponse(self):
                if len(calls) == 1:
                    return FakeResp(200, gz_payload, {"Content-Encoding": "gzip"})
                if len(calls) == 3:
                    return FakeResp(200, b'{"ok":true}')
                return FakeResp(404, b'{"error":"not_found"}')

            def close(self):
                self.closed = True

        api = PhotoApi("secret")
        with patch("backfill.http.client.HTTPConnection", FakeConn):
            # 1) gzip decompression + Keep-Alive header
            out1 = api.get("/api/v1/library?ids=1", 1024 * 1024)
            self.assertEqual(out1, payload)
            self.assertEqual(calls[0][2].get("Accept-Encoding"), "gzip")
            self.assertEqual(calls[0][2].get("Authorization"), "Bearer secret")
            # 2) stale socket raises RemoteDisconnected -> auto-reconnect & retry once
            out2 = api.get("/api/v1/healthz", 65536)
            self.assertEqual(out2, b'{"ok":true}')
            self.assertEqual(len(conns), 2)
            self.assertTrue(conns[0].closed)
            # 3) 404 raises HTTPError with code 404
            with self.assertRaises(HTTPError) as ctx:
                api.get("/api/v1/thumbnail?path=/x", 65536)
            self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
