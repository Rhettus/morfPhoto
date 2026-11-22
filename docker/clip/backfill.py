# SPDX-License-Identifier: GPL-3.0-only
"""Build semantic vectors from the saved catalog and existing thumbnail API."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

MAX_PREVIEW_BYTES = 32 * 1024 * 1024


class PhotoFailure(Exception):
    """A preview or inference failure attributable to an individual photo."""


class PhotoStalled(PhotoFailure):
    """A photo that stopped the vision process from responding."""


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


def pass_catalog(catalog, api, vision, index, report, searching):
    with closing(sqlite3.connect(catalog.as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA busy_timeout = 5000")
        rows = db.execute("""
            SELECT f.id, f.path, f.size, f.mtime
            FROM files f JOIN folders d ON d.id = f.folder_id
            WHERE f.state = 'present' AND d.enabled = 1 AND d.deleted_at IS NULL
            ORDER BY f.id
        """).fetchall()
        non_missing_ids = {
            row[0] for row in db.execute("SELECT id FROM files WHERE state != 'missing'")
        }

    eligible = len(rows)
    indexed_count = 0
    failed_count = 0
    pending = []
    for photo_id, path, size, mtime in rows:
        rev = (path, size, mtime)
        if index.has_revision(photo_id, rev):
            indexed_count += 1
        elif index.is_failed(photo_id, rev):
            failed_count += 1
        else:
            pending.append((photo_id, path, size, mtime))

    index.prune(non_missing_ids)

    if not pending:
        report("idle", {
            "eligible": eligible,
            "indexed": indexed_count,
            "failed": failed_count,
            "photo_id": None,
            "pause_reason": None,
            "phase": "waiting",
        })
        return False

    progress = {
        "eligible": eligible,
        "indexed": indexed_count,
        "failed": failed_count,
        "photo_id": None,
        "pause_reason": None,
    }

    def pause_reason():
        if searching.is_set():
            return "semantic_search"
        if api.indexing():
            return "photo_indexing"
        return None

    for photo_id, path, size, mtime in pending:
        if reason := pause_reason():
            report("paused", {**progress, "phase": "backfill", "pause_reason": reason})
            return True

        revision = fingerprint(path, size, mtime)

        def report_phase(phase):
            report("warming", {**progress, "phase": phase, "photo_id": photo_id})

        try:
            vector = vision.image(path, report_phase)
        except PhotoFailure as error:
            index.record_failure(photo_id, revision, str(error))
            progress["failed"] += 1
            report("warming", {**progress, "phase": "photo_failed", "photo_id": photo_id,
                               "last_error": str(error)})
            print(f"CLIP skipped photo {photo_id}: {error}", flush=True)
            continue

        report_phase("save_embedding")
        index.store(photo_id, revision, vector)
        progress["last_progress_at"] = datetime.now(timezone.utc).isoformat()
        progress["indexed"] += 1
        report("warming", {**progress, "phase": "backfill", "pause_reason": None})

    report("idle", {**progress, "photo_id": None, "phase": "waiting", "pause_reason": None})
    return True
