"""Checks for the Vercel deployment settings: database URL, storage choice, driver."""
import os

from netmon.db import database_url
from netmon.storage import BlobStorage, LocalStorage, make_storage


def test_neon_urls_use_installed_psycopg2_driver(monkeypatch):
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    for given in ("postgres://u:p@ep-x-pooler.neon.tech/db?sslmode=require",
                  "postgresql://u:p@ep-x-pooler.neon.tech/db?sslmode=require"):
        monkeypatch.setenv("DATABASE_URL", given)
        assert database_url(".") == "postgresql+psycopg2://u:p@ep-x-pooler.neon.tech/db?sslmode=require"


def test_postgres_url_fallback_and_sqlite_in_writable_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("POSTGRES_URL", "postgres://a@b/c")
    assert database_url(".").startswith("postgresql+psycopg2://")
    monkeypatch.delenv("POSTGRES_URL")
    url = database_url(".", str(tmp_path))
    assert url == f"sqlite:///{tmp_path}/netmon.db"


def test_storage_choice(monkeypatch, tmp_path):
    monkeypatch.delenv("BLOB_STORE_ID", raising=False)
    monkeypatch.delenv("BLOB_READ_WRITE_TOKEN", raising=False)
    s = make_storage(".", str(tmp_path))
    assert isinstance(s, LocalStorage) and s.root == os.path.join(str(tmp_path), "storage")
    key = s.put("reports/a.csv", b"x,y\n")
    assert s.get(key) == b"x,y\n"
    monkeypatch.setenv("BLOB_STORE_ID", "store_abc")
    assert isinstance(make_storage("."), BlobStorage)
