"""File storage: Vercel Blob (private store) in the cloud, a local folder otherwise.

On Vercel, connect a private Blob store to the project (Storage > Create > Blob >
Private). Vercel then provides BLOB_STORE_ID plus a short-lived OIDC token on every
request, or a BLOB_READ_WRITE_TOKEN for older stores, and this module uses it.
Without those variables, files go to ./storage (or /tmp/netmon-storage on Vercel,
where the project folder is read-only) and are served by Flask.
"""
from __future__ import annotations

import os
import urllib.parse


class LocalStorage:
    kind = "local"
    label = "local folder"

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = os.path.join(self.root, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return key

    def get(self, key: str) -> bytes:
        with open(os.path.join(self.root, key), "rb") as f:
            return f.read()

    def url(self, key: str) -> str:
        return "/files/" + urllib.parse.quote(key)


class BlobStorage:
    """Private Vercel Blob store. Files are only reachable through the logged-in app."""
    kind = "vercel-blob"
    label = "Vercel Blob"

    def __init__(self):
        from vercel.blob import sync as blob      # imported here so local runs don't need it
        self.blob = blob

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        res = self.blob.put_blob(key, data, access="private", content_type=content_type,
                                 add_random_suffix=True)
        return res.pathname          # includes the random suffix, so keys never collide

    def get(self, key: str) -> bytes:
        return self.blob.get_blob(key, access="private").body


def make_storage(base_dir: str, writable_dir: str | None = None):
    if os.environ.get("BLOB_STORE_ID") or os.environ.get("BLOB_READ_WRITE_TOKEN"):
        return BlobStorage()
    return LocalStorage(os.path.join(writable_dir or base_dir, "storage"))
