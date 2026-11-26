"""
Tests for scripts/migrate_sqlite_to_firestore.py.

Uses a disposable SQLite database created fresh by each test (never a
real backup, never anything resembling production data) and the same
FakeFirestoreClient used by the repository tests, so this never
touches real Firebase or a real production database.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from fake_firestore import FakeFirestoreClient

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from shadowshield.storage import init_db, upsert_approved, save_analysis

_spec = importlib.util.spec_from_file_location(
    "migrate_sqlite_to_firestore",
    BACKEND_ROOT / "scripts" / "migrate_sqlite_to_firestore.py",
)
migrate_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migrate_module)


@pytest.fixture
def seeded_db(tmp_path):
    db_path = str(tmp_path / "seeded.db")
    init_db(db_path)

    upsert_approved(
        {
            "mac": "aa:bb:cc:dd:ee:01",
            "ip": "10.0.0.1",
            "hostname": "h1",
            "vendor": "v1",
            "ports": ["80"],
            "protocols": ["TCP"],
        },
        db_path=db_path,
    )

    save_analysis(
        "x.pcap",
        "pcap",
        [{"mac": "aa:bb:cc:dd:ee:02", "ip": "10.0.0.2"}],
        [{"mac": "aa:bb:cc:dd:ee:02", "status": "Unknown", "risk_score": 30, "risk_band": "Medium"}],
        db_path=db_path,
    )

    return db_path


def test_validate_schema_rejects_non_shadowshield_db(tmp_path):
    import sqlite3

    bogus_path = tmp_path / "not_shadowshield.db"
    conn = sqlite3.connect(str(bogus_path))
    conn.execute("CREATE TABLE unrelated_table (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()

    conn = migrate_module._open_readonly(str(bogus_path))
    try:
        with pytest.raises(ValueError, match="missing expected tables"):
            migrate_module._validate_schema(conn)
    finally:
        conn.close()


def test_open_readonly_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        migrate_module._open_readonly(str(tmp_path / "nope.db"))


def test_migrate_writes_expected_collections(seeded_db):
    conn = migrate_module._open_readonly(seeded_db)
    db = FakeFirestoreClient()

    try:
        migrate_module._validate_schema(conn)
        report = migrate_module.migrate(conn, db, dry_run=False)
    finally:
        conn.close()

    assert report["inventory"]["written"] == 1
    assert report["analyses"]["written"] == 1
    assert report["analyses"]["observations"] == 1
    assert report["analyses"]["results"] == 1
    assert report["alerts"]["written"] == 1  # risk_score 30 triggers an alert
    assert all(
        not section.get("errors")
        for section in report.values()
        if isinstance(section, dict)
    )

    inventory_doc = db.collection("inventory").document("aa:bb:cc:dd:ee:01").get()
    assert inventory_doc.exists
    assert inventory_doc.to_dict()["hostname"] == "h1"


def test_migrate_is_idempotent_on_rerun(seeded_db):
    db = FakeFirestoreClient()

    for _ in range(2):
        conn = migrate_module._open_readonly(seeded_db)
        try:
            migrate_module._validate_schema(conn)
            migrate_module.migrate(conn, db, dry_run=False)
        finally:
            conn.close()

    # Re-running twice must not duplicate the inventory document --
    # same mac, same Firestore document id, second write overwrites.
    all_inventory_docs = list(db.collection("inventory").stream())
    assert len(all_inventory_docs) == 1


def test_migrate_dry_run_writes_nothing(seeded_db):
    conn = migrate_module._open_readonly(seeded_db)
    try:
        migrate_module._validate_schema(conn)
        report = migrate_module.migrate(conn, db=None, dry_run=True)
    finally:
        conn.close()

    assert report["dry_run"] is True
    assert report["inventory"]["written"] == 1  # counted, but never sent to Firestore


def test_migrate_never_modifies_source_backup(seeded_db):
    import os

    before = os.path.getmtime(seeded_db)
    before_size = os.path.getsize(seeded_db)

    conn = migrate_module._open_readonly(seeded_db)
    try:
        migrate_module._validate_schema(conn)
        migrate_module.migrate(conn, FakeFirestoreClient(), dry_run=False)
    finally:
        conn.close()

    assert os.path.getmtime(seeded_db) == before
    assert os.path.getsize(seeded_db) == before_size
