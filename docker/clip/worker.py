# SPDX-License-Identifier: GPL-3.0-only
"""Loopback-only worker for the authenticated morfPhoto HTTP frontend."""

import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Event, Thread
from datetime import datetime, timezone
from urllib.error import URLError

from backfill import PhotoApi, pass_catalog
from index import EmbeddingIndex
from model import TextModel, EMBEDDING_VERSION
from search import SemanticSearch
from vision_worker import VisionWorker


def main():
    root = Path(os.environ["MORFPHOTO_CLIP_DIR"])
    threads = int(os.environ.get("MORFPHOTO_CLIP_THREADS", "1"))
    if not 1 <= threads <= 16:
        raise ValueError("MORFPHOTO_CLIP_THREADS must be between 1 and 16")
    catalog = Path(os.environ.get("STATE_DIRECTORY", "/data")) / "photos.db"
    key = os.environ.get("MORFPHOTO_API_KEY")
    api = PhotoApi(key)
    status = {}

    def report(state, progress):
        now = datetime.now(timezone.utc).isoformat()
        status.update(progress)
        status.update(state=state, updated_at=now)
        pending = root / ".status.tmp"
        pending.write_text(json.dumps(status, ensure_ascii=False))
        pending.replace(root / "status.json")

    print("CLIP worker loading model", flush=True)
    report("starting", {"phase": "model_load"})
    try:
        model = TextModel(root / "model", threads)
        index = EmbeddingIndex(root / "embeddings.db", EMBEDDING_VERSION)
    except Exception as error:
        report("error", {"last_error": type(error).__name__})
        raise
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

        vision = VisionWorker(root / "model", threads, key)
        quarantined = {}
        while True:
            try:
                pass_catalog(catalog, api, vision, index, report, searching, quarantined)
            except (URLError, TimeoutError, sqlite3.OperationalError) as error:
                report("retrying", {"last_error": type(error).__name__})
                print(f"CLIP backfill will retry: {error}", flush=True)
            except Exception as error:
                report("error", {"last_error": type(error).__name__})
                vision.close()
                raise
            time.sleep(30)

    with HTTPServer(("127.0.0.1", 8794), Handler) as server:
        print("CLIP worker ready", flush=True)
        Thread(target=backfill, daemon=True).start()
        server.serve_forever()


if __name__ == "__main__":
    main()
