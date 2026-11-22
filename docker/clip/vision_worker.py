# SPDX-License-Identifier: GPL-3.0-only
"""Run backfill preview and vision inference in a restartable process."""

import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from time import monotonic
from urllib.error import HTTPError, URLError

from PIL import Image

from backfill import PhotoApi, PhotoFailure, PhotoStalled
from model import VisionModel, preprocess_image

PHOTO_TIMEOUT = 60
START_TIMEOUT = 120


def _prefetch_workers():
    raw = os.environ.get("MORFPHOTO_CLIP_PREFETCH_WORKERS", "4")
    try:
        workers = int(raw)
    except (TypeError, ValueError):
        workers = 4
    return min(4, max(1, workers))


def _classify_error(error, stage):
    if isinstance(error, HTTPError):
        status = error.code
        error.close()
        return ("failure" if status == 404 else "retry", f"HTTP {status}")
    if isinstance(error, TimeoutError):
        return ("stalled", "thumbnail request timed out")
    if isinstance(error, URLError):
        if isinstance(error.reason, TimeoutError):
            return ("stalled", "thumbnail request timed out")
        return ("retry", type(error).__name__)
    if isinstance(error, (OSError, ValueError, Image.DecompressionBombError)):
        return ("failure", type(error).__name__)
    if stage == "preview":
        raise error
    return ("failure", type(error).__name__)


def serve(connection, model_root, threads, key):
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass
    with connection, ThreadPoolExecutor(max_workers=_prefetch_workers()) as executor:
        model = VisionModel(model_root, threads)
        api = PhotoApi(key)
        connection.send(("ready", None))

        def prepare_item(path):
            stage = "preview"
            try:
                preview = api.preview(path)
                stage = "decode_inference"
                return (True, preprocess_image(preview))
            except Exception as error:
                return (False, _classify_error(error, stage))

        while True:
            try:
                request = connection.recv()
            except EOFError:
                return

            if isinstance(request, tuple) and len(request) == 2 and request[0] == "batch":
                paths = list(request[1])
                prepared = list(executor.map(prepare_item, paths)) if paths else []
                connection.send(("phase", "decode_inference"))
                results = [None] * len(paths)
                valid_indices = []
                valid_tensors = []
                for idx, (ok, payload) in enumerate(prepared):
                    if ok:
                        valid_indices.append(idx)
                        valid_tensors.append(payload)
                    else:
                        results[idx] = payload
                if valid_tensors:
                    try:
                        vectors = model.embed_tensors(valid_tensors)
                    except Exception:
                        for idx, tensor in zip(valid_indices, valid_tensors):
                            try:
                                vector = model.embed_tensors([tensor])[0]
                            except Exception as error:
                                results[idx] = ("failure", type(error).__name__)
                            else:
                                results[idx] = ("result", vector)
                    else:
                        for idx, vector in zip(valid_indices, vectors):
                            results[idx] = ("result", vector)
                connection.send(("batch_result", results))
                continue

            path = request
            stage = "preview"
            try:
                preview = api.preview(path)
                stage = "decode_inference"
                connection.send(("phase", stage))
                vector = model.image(preview)
            except Exception as error:
                connection.send(_classify_error(error, stage))
            else:
                connection.send(("result", vector))


class VisionWorker:
    def __init__(self, model_root, threads, key):
        self.args = (model_root, threads, key)
        self.context = multiprocessing.get_context("spawn")
        self.process = None
        self.connection = None

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.process is not None:
            if self.process.is_alive():
                self.process.kill()
            self.process.join(timeout=5)
            if self.process.is_alive():
                raise RuntimeError("CLIP vision process did not exit")
            self.process.close()
            self.process = None

    def start(self):
        parent, child = self.context.Pipe()
        process = self.context.Process(target=serve, args=(child, *self.args), daemon=True)
        try:
            process.start()
        except BaseException:
            parent.close()
            raise
        finally:
            child.close()
        self.process, self.connection = process, parent
        try:
            if not parent.poll(START_TIMEOUT):
                raise TimeoutError("CLIP vision model startup timed out")
            message, _ = parent.recv()
            if message != "ready":
                raise RuntimeError("CLIP vision model did not signal readiness")
        except BaseException:
            self.close()
            raise

    def image(self, path, on_phase):
        if self.connection is None:
            on_phase("vision_startup")
            self.start()
        deadline = monotonic() + PHOTO_TIMEOUT
        try:
            on_phase("preview")
            self.connection.send(path)
            while self.connection.poll(max(0, deadline - monotonic())):
                message, value = self.connection.recv()
                if message == "phase":
                    on_phase(value)
                elif message == "result":
                    return value
                elif message == "failure":
                    raise PhotoFailure(value)
                elif message == "stalled":
                    raise PhotoStalled(value)
                elif message == "retry":
                    raise URLError(value)
            self.close()
            raise PhotoStalled("photo deadline exceeded")
        except (EOFError, BrokenPipeError) as error:
            self.close()
            raise PhotoStalled("vision process exited") from error

    def images(self, paths, on_phase):
        paths = list(paths)
        if not paths:
            return []
        if self.connection is None:
            on_phase("vision_startup")
            self.start()
        deadline = monotonic() + max(PHOTO_TIMEOUT, 30 * len(paths))
        try:
            on_phase("preview")
            self.connection.send(("batch", paths))
            while self.connection.poll(max(0, deadline - monotonic())):
                message, value = self.connection.recv()
                if message == "phase":
                    on_phase(value)
                elif message == "batch_result":
                    return value
            self.close()
            raise PhotoStalled("batch deadline exceeded")
        except (EOFError, BrokenPipeError) as error:
            self.close()
            raise PhotoStalled("vision process exited") from error
