# SPDX-License-Identifier: GPL-3.0-only
"""Persistent embeddings, isolated from the photo catalog database."""

import json
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

import numpy as np


def parse_revision(fingerprint):
    """Parse a JSON fingerprint string into a (path, size, mtime) tuple."""
    if not isinstance(fingerprint, str):
        return None
    try:
        data = json.loads(fingerprint)
    except (ValueError, TypeError):
        return None
    if (
        isinstance(data, list)
        and len(data) == 3
        and isinstance(data[0], str)
        and isinstance(data[1], int)
        and not isinstance(data[1], bool)
        and isinstance(data[2], int)
        and not isinstance(data[2], bool)
    ):
        return (data[0], data[1], data[2])
    return None


class EmbeddingIndex:
    def __init__(self, path, version):
        self.path = path
        self.version = version
        self._lock = threading.RLock()
        self._id_to_slot = {}
        self._failed = {}

        with closing(self.connect()) as db:
            with db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("""
                    CREATE TABLE IF NOT EXISTS embedding (
                        photo_id INTEGER PRIMARY KEY,
                        fingerprint TEXT NOT NULL,
                        version TEXT NOT NULL,
                        vector BLOB NOT NULL CHECK (length(vector) = 2048)
                    )
                """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS failed_embedding (
                        photo_id INTEGER PRIMARY KEY,
                        fingerprint TEXT NOT NULL,
                        version TEXT NOT NULL,
                        error TEXT NOT NULL
                    )
                """)

            db.execute("BEGIN")
            count = db.execute(
                "SELECT COUNT(*) FROM embedding WHERE version=?",
                (self.version,),
            ).fetchone()[0]
            capacity = max(1024, count)
            self._photo_ids = np.empty(capacity, dtype=np.int64)
            self._revisions = [None] * capacity
            self._vectors = np.empty((capacity, 512), dtype=np.float32, order="C")
            self._count = 0

            cursor = db.execute(
                "SELECT photo_id, fingerprint, vector FROM embedding WHERE version=?",
                (self.version,),
            )
            while batch := cursor.fetchmany(4096):
                for photo_id, fp, blob in batch:
                    if self._count == len(self._photo_ids):
                        self._grow()
                    slot = self._count
                    self._id_to_slot[photo_id] = slot
                    self._photo_ids[slot] = photo_id
                    self._revisions[slot] = parse_revision(fp)
                    self._vectors[slot] = np.frombuffer(blob, dtype="<f4")
                    self._count += 1

            failed_cursor = db.execute(
                "SELECT photo_id, fingerprint FROM failed_embedding WHERE version=?",
                (self.version,),
            )
            while batch := failed_cursor.fetchmany(4096):
                for photo_id, fp in batch:
                    self._failed[photo_id] = parse_revision(fp)
            db.commit()

    def connect(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=rwc", uri=True)
        db.execute("PRAGMA busy_timeout = 5000")
        return db

    def _grow(self):
        capacity = len(self._photo_ids)
        new_capacity = capacity + max(1024, capacity // 4)
        new_ids = np.empty(new_capacity, dtype=np.int64)
        new_ids[:self._count] = self._photo_ids[:self._count]
        new_vectors = np.empty((new_capacity, 512), dtype=np.float32, order="C")
        new_vectors[:self._count] = self._vectors[:self._count]
        self._photo_ids = new_ids
        self._vectors = new_vectors
        self._revisions.extend([None] * (new_capacity - capacity))

    def has_revision(self, photo_id, rev):
        if rev is None:
            return False
        with self._lock:
            slot = self._id_to_slot.get(photo_id)
            return slot is not None and self._revisions[slot] == rev

    def is_failed(self, photo_id, rev):
        if rev is None:
            return False
        with self._lock:
            return self._failed.get(photo_id) == rev

    def current(self, photo_id, fingerprint):
        return self.has_revision(photo_id, parse_revision(fingerprint))

    def store(self, photo_id, fingerprint, vector):
        vec = np.asarray(vector, dtype=np.float32).reshape(512)
        blob = np.asarray(vec, dtype="<f4").tobytes()
        rev = parse_revision(fingerprint)
        with closing(self.connect()) as db, db:
            db.execute("""
                INSERT INTO embedding VALUES (?, ?, ?, ?)
                ON CONFLICT(photo_id) DO UPDATE SET
                    fingerprint=excluded.fingerprint,
                    version=excluded.version, vector=excluded.vector
            """, (photo_id, fingerprint, self.version, blob))
            db.execute("DELETE FROM failed_embedding WHERE photo_id=?", (photo_id,))
        with self._lock:
            slot = self._id_to_slot.get(photo_id)
            if slot is None:
                if self._count == len(self._photo_ids):
                    self._grow()
                slot = self._count
                self._id_to_slot[photo_id] = slot
                self._count += 1
            self._photo_ids[slot] = photo_id
            self._revisions[slot] = rev
            self._vectors[slot] = vec
            self._failed.pop(photo_id, None)

    def record_failure(self, photo_id, fingerprint, error):
        rev = parse_revision(fingerprint)
        with closing(self.connect()) as db, db:
            db.execute("""
                INSERT INTO failed_embedding VALUES (?, ?, ?, ?)
                ON CONFLICT(photo_id) DO UPDATE SET
                    fingerprint=excluded.fingerprint,
                    version=excluded.version, error=excluded.error
            """, (photo_id, fingerprint, self.version, error))
        with self._lock:
            self._failed[photo_id] = rev

    def prune(self, active_ids):
        if isinstance(active_ids, Path):
            with closing(sqlite3.connect(active_ids.as_uri() + "?mode=ro", uri=True)) as cat:
                cat.execute("PRAGMA busy_timeout = 5000")
                active_ids = {
                    row[0] for row in cat.execute("SELECT id FROM files WHERE state != 'missing'")
                }

        with self._lock:
            stale_emb = [pid for pid in self._id_to_slot if pid not in active_ids]
            stale_fail = [pid for pid in self._failed if pid not in active_ids]

        if not stale_emb and not stale_fail:
            return 0

        with closing(self.connect()) as db, db:
            for table, ids in (("embedding", stale_emb), ("failed_embedding", stale_fail)):
                for i in range(0, len(ids), 500):
                    chunk = ids[i:i + 500]
                    holders = ",".join("?" * len(chunk))
                    db.execute(f"DELETE FROM {table} WHERE photo_id IN ({holders})", chunk)

        pruned = 0
        with self._lock:
            for pid in stale_emb:
                slot = self._id_to_slot.pop(pid, None)
                if slot is None:
                    continue
                pruned += 1
                last = self._count - 1
                if slot != last:
                    last_pid = int(self._photo_ids[last])
                    self._photo_ids[slot] = last_pid
                    self._revisions[slot] = self._revisions[last]
                    self._vectors[slot] = self._vectors[last]
                    self._id_to_slot[last_pid] = slot
                self._revisions[last] = None
                self._count = last
            for pid in stale_fail:
                self._failed.pop(pid, None)
        return pruned

    def rank(self, query, candidates, limit, after=None):
        """Rank only the candidate IDs and revisions authorized by the catalog."""
        if not 1 <= limit <= 250:
            raise ValueError("Invalid semantic search limit")
        if not candidates:
            return [], 0

        first_val = next(iter(candidates.values()))
        if isinstance(first_val, str):
            candidates = {pid: parse_revision(fp) for pid, fp in candidates.items()}

        with self._lock:
            if self._count == 0:
                return [], 0

            if len(candidates) < self._count // 2:
                slots = []
                for pid, rev in candidates.items():
                    slot = self._id_to_slot.get(pid)
                    if slot is not None and rev is not None and self._revisions[slot] == rev:
                        slots.append(slot)
            else:
                slots = [
                    slot for slot in range(self._count)
                    if (rev := self._revisions[slot]) is not None
                    and candidates.get(int(self._photo_ids[slot])) == rev
                ]

            indexed = len(slots)
            if indexed == 0:
                return [], 0

            if indexed == self._count:
                scores = self._vectors[:self._count] @ query
                matched_ids = self._photo_ids[:self._count]
            else:
                slot_arr = np.asarray(slots, dtype=np.intp)
                scores = self._vectors[slot_arr] @ query
                matched_ids = self._photo_ids[slot_arr]

            neg_scores = -scores.astype(np.float64)
            if after is not None:
                after_neg, after_id = after
                keep = (neg_scores > after_neg) | ((neg_scores == after_neg) & (matched_ids > after_id))
                neg_scores = neg_scores[keep]
                matched_ids = matched_ids[keep]

            if len(neg_scores) == 0:
                return [], indexed

            k = limit + 1
            if len(neg_scores) > k:
                part = np.argpartition(neg_scores, k - 1)
                cutoff = neg_scores[part[k - 1]]
                top_idx = np.flatnonzero(neg_scores <= cutoff)
                neg_scores = neg_scores[top_idx]
                matched_ids = matched_ids[top_idx]

            ranked = sorted(
                (float(ns), int(pid)) for ns, pid in zip(neg_scores, matched_ids)
            )
        return ranked[:k], indexed
