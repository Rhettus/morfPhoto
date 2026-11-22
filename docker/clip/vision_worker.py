# SPDX-License-Identifier: GPL-3.0-only
"""Run backfill preview and vision inference in a restartable process."""

import multiprocessing
import os
from time import monotonic
from urllib.error import HTTPError, URLError

from PIL import Image

from backfill import PhotoApi, PhotoFailure, PhotoStalled
from model import VisionModel

PHOTO_TIMEOUT = 60
START_TIMEOUT = 120


def serve(connection, model_root, threads, key):
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass
    with connection:
        model = VisionModel(model_root, threads)
        api = PhotoApi(key)
        connection.send(("ready", None))
        while True:
            try:
                path = connection.recv()
            except EOFError:
                return
            stage = "preview"
            try:
                preview = api.preview(path)
                stage = "decode_inference"
                connection.send(("phase", stage))
                vector = model.image(preview)
            except HTTPError as error:
                status = error.code
                error.close()
                connection.send(("failure" if status == 404 else "retry", f"HTTP {status}"))
            except TimeoutError:
                connection.send(("stalled", "thumbnail request timed out"))
            except URLError as error:
                if isinstance(error.reason, TimeoutError):
                    connection.send(("stalled", "thumbnail request timed out"))
                else:
                    connection.send(("retry", type(error).__name__))
            except (OSError, ValueError, Image.DecompressionBombError) as error:
                connection.send(("failure", type(error).__name__))
            except Exception as error:
                if stage == "preview":
                    raise
                connection.send(("failure", type(error).__name__))
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
