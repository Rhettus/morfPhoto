# SPDX-License-Identifier: GPL-3.0-only
"""Build semantic vectors from the saved catalog and existing thumbnail API."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from PIL import UnidentifiedImageError

BATCH_SIZE = 32
MAX_PREVIEW_BYTES = 32 * 1024 * 1024


def catalog_rows(db, after):
    return db.execute("""
        SELECT f.id, f.path, f.size, f.mtime
        FROM files f JOIN folders d ON d.id = f.folder_id
        WHERE f.id > ? AND f.state = 'present' AND d.enabled = 1
            AND d.deleted_at IS NULL ORDER BY f.id LIMIT ?
    """, (after, BATCH_SIZE)).fetchall()


def fingerprint(path, size, mtime):
    return json.dumps([path, size, mtime], separators=(",", ":"))


class PhotoApi:
    def __init__(self, key):
        self.headers = {"Authorization": f"Bearer {key}"} if key else {}

    def get(self, path, maximum):
        request = Request("http://127.0.0.1:8793" + path, headers=self.headers)
        with urlopen(request, timeout=30) as response:
            body = response.read(maximum + 1)
        if len(body) > maximum:
            raise ValueError("morfPhoto response exceeded size limit")
        return body

    def indexing(self):
        return json.loads(self.get("/api/v1/index/status", 65536))["state"] == "indexing"

    def preview(self, path):
        # Both thumbnail routes consult the same on-disk cache. The regular
        # route also works on NAS deployments without the thumbnail bind mount.
        try:
            return self.get("/api/v1/thumbnail?" + urlencode({"path": path}, quote_via=quote),
                            MAX_PREVIEW_BYTES)
        except HTTPError as error:
            if error.code != 404:
                raise
            original = Path(path).resolve()
            if not original.is_relative_to(Path("/photos")) or original.suffix.lower() not in {
                ".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff",
            }:
                raise
            try:
                with original.open("rb") as source:
                    body = source.read(MAX_PREVIEW_BYTES + 1)
            except OSError:
                raise error
            error.close()
            if len(body) > MAX_PREVIEW_BYTES:
                raise ValueError("Original image exceeded size limit")
            return body


def pass_catalog(catalog, api, model, index, report, searching):
    cursor = 0
    progress = {"eligible": 0, "indexed": 0, "failed": 0}
    with closing(sqlite3.connect(catalog.as_uri() + "?mode=ro", uri=True)) as db:
        progress["eligible"] = db.execute("""
            SELECT count(*) FROM files f JOIN folders d ON d.id = f.folder_id
            WHERE f.state = 'present' AND d.enabled = 1 AND d.deleted_at IS NULL
        """).fetchone()[0]

    while True:
        if searching.is_set() or api.indexing():
            report("paused", progress)
            return
        with closing(sqlite3.connect(catalog.as_uri() + "?mode=ro", uri=True)) as db:
            rows = catalog_rows(db, cursor)
        if not rows:
            index.prune(catalog)
            report("idle", progress)
            return
        for photo_id, path, size, mtime in rows:
            revision = fingerprint(path, size, mtime)
            if index.current(photo_id, revision):
                progress["indexed"] += 1
                continue
            if searching.is_set() or api.indexing():
                report("paused", progress)
                return
            try:
                vector = model.image(api.preview(path))
            except HTTPError as error:
                if error.code != 404:
                    raise
                error.close()
                progress["failed"] += 1
                continue
            except (UnidentifiedImageError, ValueError):
                progress["failed"] += 1
                continue
            index.store(photo_id, revision, vector)
            progress["indexed"] += 1
        report("warming", progress)
        cursor = rows[-1][0]
