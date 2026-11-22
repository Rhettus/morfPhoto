# SPDX-License-Identifier: GPL-3.0-only
"""Loopback-only worker for the authenticated morfPhoto HTTP frontend."""

import json
import os
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic
from urllib.error import URLError

from backfill import PhotoApi, pass_catalog
from index import EmbeddingIndex
from model import EMBEDDING_VERSION, TextModel
from search import SemanticSearch
from vision_worker import VisionWorker


def _stat_tuple(path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except FileNotFoundError:
        return None


def main():
    root = Path(os.environ["MORFPHOTO_CLIP_DIR"])
    threads = int(os.environ.get("MORFPHOTO_CLIP_THREADS", "1"))
    if not 1 <= threads <= 16:
        raise ValueError("MORFPHOTO_CLIP_THREADS must be between 1 and 16")
    text_threads = max(threads, min(4, os.cpu_count() or 1))
    catalog = Path(os.environ.get("STATE_DIRECTORY", "/data")) / "photos.db"
    catalog_wal = Path(str(catalog) + "-wal")
    key = os.environ.get("MORFPHOTO_API_KEY")
    api = PhotoApi(key)
    status = {}
    report_lock = Lock()
    last_report_time = 0.0

    def report(state, progress, force=True):
        nonlocal last_report_time
        with report_lock:
            prev_state = status.get("state")
            status.update(progress)
            now_mono = monotonic()
            if not force and state == prev_state and (now_mono - last_report_time) < 1.0:
                return
            now = datetime.now(timezone.utc).isoformat()
            status.update(state=state, updated_at=now)
            pending = root / ".status.tmp"
            pending.write_text(json.dumps(status, ensure_ascii=False))
            pending.replace(root / "status.json")
            last_report_time = now_mono

    print("CLIP worker loading model", flush=True)
    report("starting", {"phase": "model_load"})
    try:
        model = TextModel(root / "model", text_threads)
        index = EmbeddingIndex(root / "embeddings.db", EMBEDDING_VERSION)
    except Exception as error:
        report("error", {"last_error": type(error).__name__})
        raise
    search = SemanticSearch(api, model, index, catalog)
    searching = Event()
    search_lock = Lock()
    active_searches = 0

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal active_searches
            if self.path != "/search":
                self.send_error(404)
                return
            with search_lock:
                active_searches += 1
                if active_searches == 1:
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
                with search_lock:
                    active_searches -= 1
                    if active_searches == 0:
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
        last_catalog_stat = None
        idle_clean = False
        idle_ticks = 0
        while True:
            current_stat = (_stat_tuple(catalog), _stat_tuple(catalog_wal))
            if idle_clean and current_stat == last_catalog_stat:
                idle_ticks += 1
                if idle_ticks >= 6:
                    vision.close()
            else:
                try:
                    worked = pass_catalog(catalog, api, vision, index, report, searching)
                except (URLError, TimeoutError, sqlite3.OperationalError) as error:
                    idle_clean = False
                    idle_ticks = 0
                    report("retrying", {"last_error": type(error).__name__})
                    print(f"CLIP backfill will retry: {error}", flush=True)
                except Exception as error:
                    report("error", {"last_error": type(error).__name__})
                    vision.close()
                    raise
                else:
                    if worked:
                        idle_clean = False
                        idle_ticks = 0
                    else:
                        last_catalog_stat = current_stat
                        idle_clean = True
                        idle_ticks += 1
                        if idle_ticks >= 6:
                            vision.close()
            time.sleep(10)

    try:
        with ThreadingHTTPServer(("127.0.0.1", 8794), Handler) as server:
            print("CLIP worker ready", flush=True)
            Thread(target=backfill, daemon=True).start()
            server.serve_forever()
    finally:
        index.close()


if __name__ == "__main__":
    main()
