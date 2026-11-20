# SPDX-License-Identifier: GPL-3.0-only
"""Loopback-only worker for the authenticated morfPhoto HTTP frontend."""

import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Event, Thread
from urllib.error import URLError

from backfill import PhotoApi, pass_catalog
from index import EmbeddingIndex
from model import ClipModel, EMBEDDING_VERSION
from search import SemanticSearch


def main():
    root = Path(os.environ["MORFPHOTO_CLIP_DIR"])
    threads = int(os.environ.get("MORFPHOTO_CLIP_THREADS", "1"))
    if not 1 <= threads <= 16:
        raise ValueError("MORFPHOTO_CLIP_THREADS must be between 1 and 16")
    catalog = Path(os.environ.get("STATE_DIRECTORY", "/data")) / "photos.db"
    api = PhotoApi(os.environ.get("MORFPHOTO_API_KEY"))
    def report(state, progress):
        pending = root / ".status.tmp"
        pending.write_text(json.dumps({"state": state, **progress}))
        pending.replace(root / "status.json")

    report("starting", {})
    try:
        model = ClipModel(root / "model", threads)
    except Exception:
        report("error", {})
        raise
    index = EmbeddingIndex(root / "embeddings.db", EMBEDDING_VERSION)
    search = SemanticSearch(api, model, index)
    searching = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/search":
                self.send_error(404)
                return
            searching.set()
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 131072:
                    raise ValueError("Invalid request length")
                result = search.search(json.loads(self.rfile.read(length)))
                status = 200
            except (ValueError, KeyError, TypeError):
                status, result = 400, {"error": "invalid_semantic_query"}
            except (sqlite3.Error, URLError, TimeoutError):
                status, result = 503, {"error": "semantic_search_unavailable"}
            finally:
                searching.clear()
            body = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def backfill():
        import time

        while True:
            try:
                pass_catalog(catalog, api, model, index, report, searching)
            except (URLError, TimeoutError, sqlite3.OperationalError) as error:
                report("retrying", {})
                print(f"CLIP backfill will retry: {error}", flush=True)
            time.sleep(30)

    with HTTPServer(("127.0.0.1", 8794), Handler) as server:
        Thread(target=backfill, daemon=True).start()
        server.serve_forever()


if __name__ == "__main__":
    main()
