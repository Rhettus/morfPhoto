# SPDX-License-Identifier: GPL-3.0-only
"""CPU inference for morfPhoto's pinned CLIP package."""

import hashlib
from io import BytesIO

import numpy as np
import onnxruntime as ort
from PIL import Image, ImageOps
from tokenizers import Tokenizer

MODEL_REVISION = "6b7c523703ae26e39be4b03774966f8571c7f523"
EMBEDDING_VERSION = MODEL_REVISION + ":thumbnail-center-crop-v1"
ASSETS = {
    "onnx/text_model.onnx": "3f6571f5bad13a97c469c1622e1cfc4d9aef78b79fdbfcff804ca357bfada8cc",
    "onnx/vision_model.onnx": "fd6e1402a588279d1723c7534d4bcba5bc0b14b47dfab0e46f8c47b8270d7d40",
    "tokenizer.json": "bc1f77d20440541dd073ebae6f6c401087c7d34e",
}


def verify_assets(root, names):
    for name in names:
        expected = ASSETS[name]
        with (root / name).open("rb") as asset:
            if len(expected) == 64:
                digest = hashlib.file_digest(asset, "sha256").hexdigest()
            else:
                data = asset.read()
                header = f"blob {len(data)}\0".encode()
                digest = hashlib.sha1(header + data).hexdigest()
        if digest != expected:
            raise ValueError(f"Invalid CLIP asset: {name}")


def normalize(output):
    vector = np.asarray(output, dtype=np.float32).reshape(-1)
    norm = np.linalg.norm(vector)
    if vector.size != 512 or not np.isfinite(norm) or norm <= 0:
        raise ValueError("Invalid CLIP embedding")
    return vector / norm


def session(root, tower, threads):
    options = ort.SessionOptions()
    options.intra_op_num_threads = threads
    options.inter_op_num_threads = 1
    return ort.InferenceSession(
        str(root / "onnx" / f"{tower}_model.onnx"),
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )


class TextModel:
    def __init__(self, root, threads):
        verify_assets(root, ("onnx/text_model.onnx", "tokenizer.json"))
        self.tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
        self.tokenizer.enable_truncation(max_length=77)
        self.tokenizer.enable_padding(length=77, pad_id=49407, pad_token="<|endoftext|>")
        probe = self.tokenizer.encode("a photo of a cat")
        if probe.ids[:7] != [49406, 320, 1125, 539, 320, 2368, 49407]:
            raise ValueError("Incompatible CLIP tokenizer")
        self.text_session = session(root, "text", threads)

    def text(self, query):
        if not query.strip() or len(query.encode("utf-8")) > 65536:
            raise ValueError("Invalid CLIP query")
        tokens = self.tokenizer.encode(query)
        inputs = {
            "input_ids": np.asarray([tokens.ids], dtype=np.int64),
            "attention_mask": np.asarray([tokens.attention_mask], dtype=np.int64),
        }
        feed = {item.name: inputs[item.name] for item in self.text_session.get_inputs()}
        return normalize(self.text_session.run(["text_embeds"], feed)[0])


class VisionModel:
    def __init__(self, root, threads):
        verify_assets(root, ("onnx/vision_model.onnx",))
        self.vision_session = session(root, "vision", threads)

    def image(self, preview):
        with Image.open(BytesIO(preview)) as image:
            rgb = ImageOps.exif_transpose(image).convert("RGB")
            crop = ImageOps.fit(rgb, (224, 224), method=Image.Resampling.BICUBIC)
        pixels = np.asarray(crop, dtype=np.float32) / np.float32(255)
        mean = np.asarray([0.48145466, 0.4578275, 0.40821073], dtype=np.float32)
        deviation = np.asarray([0.26862954, 0.26130258, 0.27577711], dtype=np.float32)
        tensor = np.ascontiguousarray(((pixels - mean) / deviation).transpose(2, 0, 1)[None])
        return normalize(self.vision_session.run(["image_embeds"], {"pixel_values": tensor})[0])
