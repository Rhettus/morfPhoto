# SPDX-License-Identifier: GPL-3.0-only
"""Private semantic search handler. Public authentication lives in HttpServer."""

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

_LIBRARY_FILE_FILTERS = ("kind", "camera", "body", "iso", "aperture", "focal", "shutter")


def _stat_tuple(path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except FileNotFoundError:
        return None


def _parse_bounded_int(filters, key, maximum):
    val = filters.get(key)
    if val is None or val == "":
        return 0
    if isinstance(val, bool):
        raise ValueError(f"Invalid {key}")
    if isinstance(val, int):
        n = val
    elif isinstance(val, str) and val.isdigit():
        n = int(val)
    else:
        raise ValueError(f"Invalid {key}")
    if not 0 <= n <= maximum:
        raise ValueError(f"{key} out of range")
    return n


def _parse_str_list(filters, key):
    val = filters.get(key)
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, (list, tuple)) and all(isinstance(item, str) for item in val):
        return list(val)
    raise ValueError(f"Invalid {key}")


def _parse_date(filters, key):
    val = filters.get(key)
    if val is None or val == "":
        return ""
    if not isinstance(val, str) or len(val) != 10 or val[4] != "-" or val[7] != "-":
        raise ValueError(f"Invalid {key}")
    datetime.strptime(val, "%Y-%m-%d")
    return val


def _build_where(folder, recursive, filters, has_files_fts=False):
    clauses = ["f.state = 'present'", "v.edited = 0"]
    binds = []

    min_rating = _parse_bounded_int(filters, "min_rating", 5)
    if min_rating > 0:
        clauses.append("v.rejected = 0 AND v.rating >= ?")
        binds.append(min_rating)

    rejected = filters.get("rejected", "")
    if rejected is None:
        rejected = ""
    if not isinstance(rejected, str) or rejected not in {"", "all", "hide", "only"}:
        raise ValueError("Invalid rejected filter")
    if rejected == "hide":
        clauses.append("v.rejected = 0")
    elif rejected == "only":
        clauses.append("v.rejected = 1")

    labels = _parse_bounded_int(filters, "labels", 31)
    raw_unlabeled = filters.get("unlabeled", False)
    if raw_unlabeled is None:
        unlabeled = False
    elif isinstance(raw_unlabeled, bool):
        unlabeled = raw_unlabeled
    elif raw_unlabeled in ("true", "1"):
        unlabeled = True
    elif raw_unlabeled in ("false", "0", ""):
        unlabeled = False
    else:
        raise ValueError("Invalid unlabeled filter")

    if labels or unlabeled:
        clauses.append("((v.labels & ?) != 0 OR v.labels = 0)" if unlabeled else "(v.labels & ?) != 0")
        binds.append(labels)

    kinds = _parse_str_list(filters, "kind")
    if kinds:
        placeholders = ",".join("?" * len(kinds))
        clauses.append(f"(lf.ext_label IN ({placeholders}) OR lf.kind_label IN ({placeholders}))")
        binds.extend(kinds)
        binds.extend(kinds)

    for key, column in (
        ("camera", "lf.camera_label"),
        ("body", "lf.body_key"),
        ("lens", "f.lens"),
        ("iso", "lf.iso_label"),
        ("aperture", "lf.aperture_label"),
        ("focal", "lf.focal_label"),
        ("shutter", "lf.shutter_label"),
    ):
        values = _parse_str_list(filters, key)
        if values:
            placeholders = ",".join("?" * len(values))
            clauses.append(f"{column} IN ({placeholders})")
            binds.extend(values)

    for kw in _parse_str_list(filters, "keyword"):
        clauses.append(
            "EXISTS (SELECT 1 FROM library_keywords k WHERE k.version_id = v.id "
            "AND (k.keyword = ? OR (k.keyword >= ? AND k.keyword < ?)))"
        )
        binds.extend((kw, kw + "|", kw + "}"))

    taken_from = _parse_date(filters, "taken_from")
    if taken_from:
        clauses.append("v.taken_at >= ?")
        binds.append(taken_from)

    taken_to = _parse_date(filters, "taken_to")
    if taken_to:
        next_day = (datetime.strptime(taken_to, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
        clauses.append("v.taken_at < ?")
        binds.append(next_day)

    norm_folder = folder
    while len(norm_folder) > 1 and norm_folder.endswith("/"):
        norm_folder = norm_folder[:-1]
    if recursive:
        if norm_folder == "/":
            clauses.append("f.directory >= '/' AND f.directory < '0'")
        else:
            clauses.append(
                "f.directory >= ? AND f.directory < ? "
                "AND (f.directory = ? OR f.directory >= ?)"
            )
            binds.extend((norm_folder, norm_folder + "0", norm_folder, norm_folder + "/"))
    else:
        clauses.append("f.directory = ?")
        binds.append(norm_folder)

    filename = filters.get("filename", "")
    if filename is not None and filename != "":
        if not isinstance(filename, str):
            raise ValueError("Invalid filename filter")
        if has_files_fts and len(filename) >= 3:
            fts_query = '"' + filename.replace('"', '""') + '"'
            clauses.append(
                "f.id IN (SELECT rowid FROM files_fts WHERE filename MATCH ?) "
                "AND instr(lower(f.filename), lower(?)) > 0"
            )
            binds.extend((fts_query, filename))
        else:
            clauses.append("instr(lower(f.filename), lower(?)) > 0")
            binds.append(filename)

    return " AND ".join(clauses), binds


class SemanticSearch:
    _MAX_CACHE_ENTRIES = 4

    def __init__(self, api, model, index, catalog):
        self.api = api
        self.model = model
        self.index = index
        self.catalog = catalog
        self._catalog_wal = Path(str(catalog) + "-wal")
        self._local = threading.local()
        self._cache_lock = threading.Lock()
        self._candidate_cache = OrderedDict()

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None
            self._local.inode = None
            self._local.has_files_fts = False
            self._local.has_cover_idx = False

    def _get_db(self):
        try:
            st = self.catalog.stat()
        except FileNotFoundError as exc:
            raise sqlite3.OperationalError(f"Catalog database not found: {self.catalog}") from exc
        inode = st.st_ino
        db_stat = (st.st_mtime_ns, st.st_size, inode)
        conn = getattr(self._local, "conn", None)
        conn_inode = getattr(self._local, "inode", None)
        if conn is not None and conn_inode == inode:
            return conn, inode, db_stat
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None
            self._local.inode = None
            self._local.has_files_fts = False
            self._local.has_cover_idx = False
        conn = sqlite3.connect(self.catalog.as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA cache_size = -32768")
            conn.execute("PRAGMA temp_store = MEMORY")
            has_files_fts = bool(
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='files_fts'"
                ).fetchone()
            )
            has_cover_idx = bool(
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_files_state_dir_meta'"
                ).fetchone()
            )
        except Exception:
            conn.close()
            raise
        self._local.conn = conn
        self._local.inode = inode
        self._local.has_files_fts = has_files_fts
        self._local.has_cover_idx = has_cover_idx
        return conn, inode, db_stat

    def _load_candidates(self, sql, binds, track_hit=False):
        db, inode, db_stat = self._get_db()
        wal_stat = _stat_tuple(self._catalog_wal)
        db.execute("BEGIN")
        try:
            data_version = db.execute("PRAGMA data_version").fetchone()[0]
            cache_key = (inode, data_version, db_stat, wal_stat, sql, tuple(binds))
            with self._cache_lock:
                candidates = self._candidate_cache.get(cache_key)
                if candidates is not None:
                    self._candidate_cache.move_to_end(cache_key)
                    return (candidates, True) if track_hit else candidates
            rows = db.execute(sql, binds).fetchall()
            candidates = {row[0]: (row[1], row[2], row[3]) for row in rows}
            with self._cache_lock:
                self._candidate_cache[cache_key] = candidates
                self._candidate_cache.move_to_end(cache_key)
                while len(self._candidate_cache) > self._MAX_CACHE_ENTRIES:
                    self._candidate_cache.popitem(last=False)
            return (candidates, False) if track_hit else candidates
        finally:
            try:
                db.rollback()
            except sqlite3.Error:
                pass

    def search(self, request):
        debug = os.environ.get("MORFPHOTO_HTTP_DEBUG") == "1"
        t0 = time.perf_counter() if debug else 0.0

        text = request["text"]
        folder = request["folder_path"]
        recursive = request.get("recursive", False)
        if not isinstance(text, str) or not isinstance(recursive, bool):
            raise ValueError("Invalid semantic query")
        limit = request.get("size", 100)
        if not isinstance(folder, str) or not folder.startswith("/"):
            raise ValueError("An absolute folder is required")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 250:
            raise ValueError("Invalid search size")
        filters = request.get("filters", {})
        allowed = {"min_rating", "labels", "rejected", "unlabeled", "kind",
                   "camera", "body", "lens", "keyword", "iso", "aperture",
                   "focal", "shutter", "filename", "taken_from", "taken_to"}
        if not isinstance(filters, dict) or filters.keys() - allowed:
            raise ValueError("Unsupported semantic search filter")

        self._get_db()
        has_files_fts = getattr(self._local, "has_files_fts", False)
        has_cover_idx = getattr(self._local, "has_cover_idx", False)
        where_sql, binds = _build_where(folder, recursive, filters, has_files_fts)
        needs_lf = any(_parse_str_list(filters, key) for key in _LIBRARY_FILE_FILTERS)

        params = {**filters, "folder_path": folder,
                  "recursive": "true" if recursive else "false",
                  "edited": "unedited", "page_size": 250}
        signature = hashlib.sha256(json.dumps(
            [text, params, self.index.version], sort_keys=True
        ).encode()).hexdigest()
        after = request.get("next")
        if after is not None:
            previous, score, photo_id = json.loads(after)
            if previous != signature:
                raise ValueError("Search cursor does not match the query")
            after = (float(score), int(photo_id))

        if debug:
            t_text0 = time.perf_counter()
            query = self.model.text(text)
            text_ms = (time.perf_counter() - t_text0) * 1000.0
        else:
            query = self.model.text(text)

        lf_join = "JOIN library_files lf ON lf.file_id = f.id " if needs_lf else ""
        ver_join = (
            "CROSS JOIN library_versions v ON v.file_id = f.id AND v.version = 0 "
            if (not needs_lf and has_cover_idx)
            else "JOIN library_versions v ON v.file_id = f.id AND v.version = 0 "
        )
        sql = (
            "SELECT f.id, f.path, f.size, f.mtime "
            "FROM files f "
            + lf_join
            + ver_join
            + "WHERE " + where_sql
        )
        if debug:
            t_sql0 = time.perf_counter()
            candidates, cache_hit = self._load_candidates(sql, binds, track_hit=True)
            sql_ms = (time.perf_counter() - t_sql0) * 1000.0
            t_rank0 = time.perf_counter()
            ranked, indexed = self.index.rank(query, candidates, limit, after)
            rank_ms = (time.perf_counter() - t_rank0) * 1000.0
        else:
            candidates = self._load_candidates(sql, binds)
            ranked, indexed = self.index.rank(query, candidates, limit, after)

        items = []
        top = ranked[:limit]
        t_hyd0 = time.perf_counter() if debug else 0.0
        if top:
            ids_param = ",".join(str(photo_id) for _, photo_id in top)
            result = json.loads(
                self.api.get(f"/api/v1/library?ids={ids_param}&raw=true", 32 * 1024 * 1024)
            )
            by_id = {photo["id"]: photo for photo in result["items"]}
            for score, photo_id in top:
                photo = by_id.get(photo_id)
                if photo is not None and candidates[photo_id] == (photo["path"], photo["size"], photo["mtime"]):
                    items.append({"score": -score, "photo": photo})

        next_cursor = None
        if len(ranked) > limit:
            next_cursor = json.dumps([signature, *ranked[limit - 1]], separators=(",", ":"))
        if debug:
            hydrate_ms = (time.perf_counter() - t_hyd0) * 1000.0 if top else 0.0
            total_ms = (time.perf_counter() - t0) * 1000.0
            print(
                f"morfPhoto CLIP search text_ms={text_ms:.1f} sql_ms={sql_ms:.1f} "
                f"rank_ms={rank_ms:.1f} hydrate_ms={hydrate_ms:.1f} total_ms={total_ms:.1f} "
                f"cache_hit={1 if cache_hit else 0} eligible={len(candidates)} "
                f"indexed={indexed} returned={len(items)}",
                flush=True,
            )
        return {"items": items, "next": next_cursor,
                "eligible": len(candidates), "indexed": indexed,
                "revision": self.index.version}
