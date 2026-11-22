# SPDX-License-Identifier: GPL-3.0-only
"""Build semantic vectors from the saved catalog and existing thumbnail API."""

import inspect
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
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


def pass_catalog(catalog, api, vision, index, report, searching, indexing_poll_interval=5.0):
    try:
        sig = inspect.signature(report)
        accepts_force = "force" in sig.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
    except (TypeError, ValueError):
        accepts_force = False

    def emit(state, payload, force=True):
        if accepts_force:
            report(state, payload, force=force)
        else:
            report(state, payload)

    with closing(sqlite3.connect(catalog.as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute("PRAGMA cache_size = -32768")
        db.execute("PRAGMA temp_store = MEMORY")
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
    indexed_count, failed_count, pending = index.diff_catalog(rows)

    index.prune(non_missing_ids)

    if not pending:
        emit("idle", {
            "eligible": eligible,
            "indexed": indexed_count,
            "failed": failed_count,
            "photo_id": None,
            "pause_reason": None,
            "phase": "waiting",
        }, force=True)
        return False

    progress = {
        "eligible": eligible,
        "indexed": indexed_count,
        "failed": failed_count,
        "photo_id": None,
        "pause_reason": None,
    }

    last_indexing_check = None
    last_indexing_result = False

    def pause_reason():
        nonlocal last_indexing_check, last_indexing_result
        if searching.is_set():
            return "semantic_search"
        now = monotonic()
        if last_indexing_check is None or (now - last_indexing_check) >= indexing_poll_interval:
            last_indexing_result = api.indexing()
            last_indexing_check = now
        if last_indexing_result:
            return "photo_indexing"
        return None

    unflushed = 0
    first_warming = True
    try:
        for photo_id, path, size, mtime in pending:
            if reason := pause_reason():
                index.flush()
                emit("paused", {**progress, "phase": "backfill", "pause_reason": reason}, force=True)
                return True

            revision = fingerprint(path, size, mtime)

            def report_phase(phase):
                nonlocal first_warming
                emit("warming", {**progress, "phase": phase, "photo_id": photo_id}, force=first_warming)
                first_warming = False

            try:
                vector = vision.image(path, report_phase)
            except PhotoFailure as error:
                index.record_failure(photo_id, revision, str(error), commit=False)
                unflushed += 1
                if unflushed >= 64:
                    index.flush()
                    unflushed = 0
                progress["failed"] += 1
                first_warming = False
                emit("warming", {**progress, "phase": "photo_failed", "photo_id": photo_id,
                                  "last_error": str(error)}, force=True)
                print(f"CLIP skipped photo {photo_id}: {error}", flush=True)
                continue

            report_phase("save_embedding")
            index.store(photo_id, revision, vector, commit=False)
            unflushed += 1
            if unflushed >= 64:
                index.flush()
                unflushed = 0
            progress["last_progress_at"] = datetime.now(timezone.utc).isoformat()
            progress["indexed"] += 1
            first_warming = False
            emit("warming", {**progress, "phase": "backfill", "pause_reason": None}, force=False)
    finally:
        index.flush()

    emit("idle", {**progress, "photo_id": None, "phase": "waiting", "pause_reason": None}, force=True)
    return True
