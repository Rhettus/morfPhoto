# SPDX-License-Identifier: GPL-3.0-only
"""Private semantic search handler. Public authentication lives in HttpServer."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime


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


def _build_where(folder, recursive, filters):
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
        clauses.append("substr(v.taken_at, 1, 10) >= ?")
        binds.append(taken_from)

    taken_to = _parse_date(filters, "taken_to")
    if taken_to:
        clauses.append("substr(v.taken_at, 1, 10) <= ?")
        binds.append(taken_to)

    norm_folder = folder
    while len(norm_folder) > 1 and norm_folder.endswith("/"):
        norm_folder = norm_folder[:-1]
    if recursive:
        if norm_folder == "/":
            clauses.append("f.directory >= '/' AND f.directory < '0'")
        else:
            clauses.append("(f.directory = ? OR (f.directory >= ? AND f.directory < ?))")
            binds.extend((norm_folder, norm_folder + "/", norm_folder + "0"))
    else:
        clauses.append("f.directory = ?")
        binds.append(norm_folder)

    filename = filters.get("filename", "")
    if filename is not None and filename != "":
        if not isinstance(filename, str):
            raise ValueError("Invalid filename filter")
        clauses.append("instr(lower(f.filename), lower(?)) > 0")
        binds.append(filename)

    return " AND ".join(clauses), binds


class SemanticSearch:
    def __init__(self, api, model, index, catalog):
        self.api = api
        self.model = model
        self.index = index
        self.catalog = catalog

    def search(self, request):
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

        where_sql, binds = _build_where(folder, recursive, filters)

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

        query = self.model.text(text)

        sql = (
            "SELECT f.id, f.path, f.size, f.mtime "
            "FROM files f "
            "JOIN library_files lf ON lf.file_id = f.id "
            "JOIN library_versions v ON v.file_id = f.id AND v.version = 0 "
            "WHERE " + where_sql
        )
        with closing(sqlite3.connect(self.catalog.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA busy_timeout = 5000")
            rows = db.execute(sql, binds).fetchall()

        candidates = {row[0]: (row[1], row[2], row[3]) for row in rows}
        ranked, indexed = self.index.rank(query, candidates, limit, after)

        items = []
        top = ranked[:limit]
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
        return {"items": items, "next": next_cursor,
                "eligible": len(candidates), "indexed": indexed,
                "revision": self.index.version}
