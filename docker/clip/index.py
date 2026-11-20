# SPDX-License-Identifier: GPL-3.0-only
"""Persistent embeddings, isolated from the photo catalog database."""

import heapq
import sqlite3
from contextlib import closing

import numpy as np


class EmbeddingIndex:
    def __init__(self, path, version):
        self.path = path
        self.version = version
        with closing(self.connect()) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS embedding (
                    photo_id INTEGER PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vector BLOB NOT NULL CHECK (length(vector) = 2048)
                )
            """)

    def connect(self):
        return sqlite3.connect(self.path.as_uri() + "?mode=rwc", uri=True)

    def current(self, photo_id, fingerprint):
        with closing(self.connect()) as db:
            return db.execute(
                "SELECT 1 FROM embedding WHERE photo_id=? AND fingerprint=? AND version=?",
                (photo_id, fingerprint, self.version),
            ).fetchone() is not None

    def store(self, photo_id, fingerprint, vector):
        blob = np.asarray(vector, dtype="<f4").tobytes()
        with closing(self.connect()) as db, db:
            db.execute("""
                INSERT INTO embedding VALUES (?, ?, ?, ?)
                ON CONFLICT(photo_id) DO UPDATE SET
                    fingerprint=excluded.fingerprint,
                    version=excluded.version, vector=excluded.vector
            """, (photo_id, fingerprint, self.version, blob))

    def prune(self, catalog):
        with closing(self.connect()) as db, db:
            db.execute("ATTACH DATABASE ? AS catalog", (catalog.as_uri() + "?mode=ro",))
            db.execute("""
                DELETE FROM embedding WHERE NOT EXISTS (
                    SELECT 1 FROM catalog.files WHERE id = embedding.photo_id
                        AND state != 'missing'
                )
            """)

    def rank(self, query, candidates, limit, after=None):
        """Rank only the candidate IDs and fingerprints authorized by the catalog."""
        if not 1 <= limit <= 250:
            raise ValueError("Invalid semantic search limit")

        indexed = 0

        def matches(db):
            nonlocal indexed
            rows = db.execute(
                "SELECT photo_id, fingerprint, vector FROM embedding WHERE version=?",
                (self.version,),
            )
            while batch := rows.fetchmany(512):
                eligible = [row for row in batch if candidates.get(row[0]) == row[1]]
                if not eligible:
                    continue
                indexed += len(eligible)
                matrix = np.frombuffer(b"".join(row[2] for row in eligible), dtype="<f4")
                scores = matrix.reshape(-1, 512) @ query
                for (photo_id, _, _), score in zip(eligible, scores):
                    entry = (-float(score), photo_id)
                    if after is None or entry > after:
                        yield entry

        with closing(self.connect()) as db:
            ranked = heapq.nsmallest(limit + 1, matches(db))
        return ranked, indexed
