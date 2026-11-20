# SPDX-License-Identifier: GPL-3.0-only
"""Private semantic search handler. Public authentication lives in HttpServer."""

import hashlib
import json
from urllib.parse import quote, urlencode

from backfill import fingerprint


class SemanticSearch:
    def __init__(self, api, model, index):
        self.api = api
        self.model = model
        self.index = index

    def search(self, request):
        text = request["text"]
        folder = request["folder_path"]
        recursive = request.get("recursive", False)
        if not isinstance(text, str) or not isinstance(recursive, bool):
            raise ValueError("Invalid semantic query")
        limit = request.get("size", 100)
        if not isinstance(folder, str) or not folder.startswith("/"):
            raise ValueError("An absolute folder is required")
        if not isinstance(limit, int) or not 1 <= limit <= 250:
            raise ValueError("Invalid search size")
        filters = request.get("filters", {})
        allowed = {"min_rating", "labels", "rejected", "unlabeled", "kind",
                   "camera", "body", "lens", "keyword", "iso", "aperture",
                   "focal", "shutter", "filename", "taken_from", "taken_to"}
        if not isinstance(filters, dict) or filters.keys() - allowed:
            raise ValueError("Unsupported semantic search filter")
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
        candidates = {}
        page = 1
        while True:
            tail = urlencode({**params, "page": page}, doseq=True, quote_via=quote)
            result = json.loads(self.api.get("/api/v1/library?" + tail, 16 * 1024 * 1024))
            for photo in result["items"]:
                if any(v["version"] == 0 and 0 in photo["matched_versions"] and not v.get("edited") for v in photo["versions"]):
                    candidates[photo["id"]] = fingerprint(
                        photo["path"], photo["size"], photo["mtime"]
                    )
            if not result["items"] or page * result["page_size"] >= result["total"]:
                break
            page += 1
        ranked, indexed = self.index.rank(query, candidates, limit, after)
        items = []
        for score, photo_id in ranked[:limit]:
            photo = json.loads(self.api.get(f"/api/v1/library/{photo_id}", 1024 * 1024))
            if candidates[photo_id] == fingerprint(photo["path"], photo["size"], photo["mtime"]):
                items.append({"score": -score, "photo": photo})
        next_cursor = None
        if len(ranked) > limit:
            next_cursor = json.dumps([signature, *ranked[limit - 1]], separators=(",", ":"))
        return {"items": items, "next": next_cursor,
                "eligible": len(candidates), "indexed": indexed,
                "revision": self.index.version}
