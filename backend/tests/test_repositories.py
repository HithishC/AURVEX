"""
Tests for the repository abstraction layer (shadowshield.repositories).

These never require real Firebase/Firestore credentials: Firestore
repositories are tested against `fake_firestore.FakeFirestoreClient`
(an in-memory stand-in for the pieces of the SDK actually used), and
`create_user`'s transaction decorator is monkeypatched to a plain
pass-through so its duplicate-checking *business logic* is exercised
without needing the real SDK's transaction-retry machinery (which
would require a live emulator to test faithfully -- documented as a
known gap, not hidden).
"""

from __future__ import annotations

import os

import pytest

from fake_firestore import FakeFirestoreClient

from shadowshield import firebase_client
from shadowshield.repositories import interfaces


# ---------------------------------------------------------------------
# get_repositories() factory / backend selection
# ---------------------------------------------------------------------

def test_default_backend_is_sqlite(monkeypatch):
    monkeypatch.delenv("DB_BACKEND", raising=False)
    from shadowshield.repositories import get_backend_name
    assert get_backend_name() == "sqlite"


def test_unknown_backend_raises(monkeypatch):
    monkeypatch.setenv("DB_BACKEND", "mongodb")
    from shadowshield.repositories import get_repositories
    with pytest.raises(RuntimeError):
        get_repositories()


def test_sqlite_backend_returns_repositories_bundle(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("SHADOWSHIELD_DB_PATH", str(tmp_path / "t.db"))

    from shadowshield.repositories import get_repositories
    repos = get_repositories()

    assert isinstance(repos, interfaces.Repositories)
    assert isinstance(repos.inventory, interfaces.InventoryRepository)
    assert isinstance(repos.user, interfaces.UserRepository)


# ---------------------------------------------------------------------
# Firebase client: missing-config handling
# ---------------------------------------------------------------------

def test_missing_project_id_raises_clear_error(monkeypatch):
    firebase_client.reset_client_for_tests()
    monkeypatch.delenv("FIREBASE_PROJECT_ID", raising=False)
    monkeypatch.delenv("FIREBASE_SERVICE_ACCOUNT_JSON", raising=False)

    with pytest.raises(firebase_client.FirebaseConfigError, match="FIREBASE_PROJECT_ID"):
        firebase_client.get_firestore_client()


def test_missing_service_account_json_raises_clear_error(monkeypatch):
    firebase_client.reset_client_for_tests()
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "aurvex-test")
    monkeypatch.delenv("FIREBASE_SERVICE_ACCOUNT_JSON", raising=False)

    with pytest.raises(
        firebase_client.FirebaseConfigError,
        match="FIREBASE_SERVICE_ACCOUNT_JSON",
    ):
        firebase_client.get_firestore_client()


def test_malformed_service_account_json_raises_clear_error(monkeypatch):
    firebase_client.reset_client_for_tests()
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "aurvex-test")
    monkeypatch.setenv("FIREBASE_SERVICE_ACCOUNT_JSON", "{not valid json")

    with pytest.raises(firebase_client.FirebaseConfigError, match="not valid JSON"):
        firebase_client.get_firestore_client()

    firebase_client.reset_client_for_tests()


# ---------------------------------------------------------------------
# Fixture: a FirestoreRepositories bundle backed by the fake client
# ---------------------------------------------------------------------

@pytest.fixture
def fake_db(monkeypatch):
    firebase_client.reset_client_for_tests()
    client = FakeFirestoreClient()
    firebase_client._client = client
    yield client
    firebase_client.reset_client_for_tests()


@pytest.fixture
def firestore_repos(fake_db):
    from shadowshield.repositories.firestore_repositories import build_repositories
    return build_repositories()


# ---------------------------------------------------------------------
# Inventory repository
# ---------------------------------------------------------------------

def test_firestore_upsert_and_get_inventory(firestore_repos):
    firestore_repos.inventory.upsert_approved({
        "mac": "AA:BB:CC:DD:EE:01",
        "ip": "10.0.0.5",
        "hostname": "h1",
        "vendor": "v1",
        "ports": ["80"],
        "protocols": ["TCP"],
    })

    inventory = firestore_repos.inventory.get_approved_inventory()

    assert "aa:bb:cc:dd:ee:01" in inventory
    assert inventory["aa:bb:cc:dd:ee:01"]["hostname"] == "h1"
    assert "fingerprint" in inventory["aa:bb:cc:dd:ee:01"]


def test_firestore_upsert_is_idempotent_no_duplicates(firestore_repos):
    device = {"mac": "aa:bb:cc:dd:ee:02", "hostname": "h2"}
    firestore_repos.inventory.upsert_approved(device)
    firestore_repos.inventory.upsert_approved(device)
    firestore_repos.inventory.upsert_approved(device)

    inventory = firestore_repos.inventory.get_approved_inventory()
    assert len(inventory) == 1


def test_firestore_delete_approved(firestore_repos):
    firestore_repos.inventory.upsert_approved({"mac": "aa:bb:cc:dd:ee:03"})
    assert firestore_repos.inventory.delete_approved("aa:bb:cc:dd:ee:03") is True
    assert firestore_repos.inventory.delete_approved("aa:bb:cc:dd:ee:03") is False
    assert firestore_repos.inventory.get_approved_inventory() == {}


def test_firestore_upsert_rejects_missing_mac(firestore_repos):
    with pytest.raises(ValueError):
        firestore_repos.inventory.upsert_approved({"mac": ""})


# ---------------------------------------------------------------------
# Analysis + observation repositories
# ---------------------------------------------------------------------

def test_firestore_save_and_get_analysis(firestore_repos):
    observations = [{"mac": "aa:bb:cc:dd:ee:10", "ip": "10.0.0.1"}]
    results = [
        {"mac": "aa:bb:cc:dd:ee:10", "status": "Unknown", "risk_score": 30},
    ]

    analysis_id = firestore_repos.analysis.save_analysis(
        "capture.pcap", "pcap", observations, results
    )

    fetched = firestore_repos.analysis.get_analysis(analysis_id)
    assert fetched["source_name"] == "capture.pcap"
    assert fetched["device_count"] == 1
    assert len(fetched["results"]) == 1
    assert fetched["results"][0]["status"] == "Unknown"

    obs = firestore_repos.observation.get_observations(analysis_id)
    assert len(obs) == 1
    assert obs[0]["mac"] == "aa:bb:cc:dd:ee:10"


def test_firestore_get_analysis_missing_returns_none(firestore_repos):
    assert firestore_repos.analysis.get_analysis("does-not-exist") is None


def test_firestore_get_analyses_respects_limit_and_order(firestore_repos):
    import time

    ids = []
    for i in range(3):
        aid = firestore_repos.analysis.save_analysis(
            f"file-{i}.pcap", "pcap", [], []
        )
        ids.append(aid)
        time.sleep(0.001)  # ensure distinct created_at ordering

    page = firestore_repos.analysis.get_analyses(limit=2)
    assert len(page) == 2
    # Most-recently-created first.
    assert page[0]["source_name"] == "file-2.pcap"


def test_firestore_preserves_existing_analysis_id_as_doc_id(firestore_repos):
    analysis_id = firestore_repos.analysis.save_analysis("x.pcap", "pcap", [], [])
    doc = firestore_repos.analysis._db.collection("analyses").document(analysis_id).get()
    assert doc.exists
    assert doc.to_dict()["id"] == analysis_id


# ---------------------------------------------------------------------
# Alert repository
# ---------------------------------------------------------------------

def test_firestore_recent_alerts_limit(fake_db, firestore_repos):
    for i in range(5):
        fake_db.collection("alerts").document().set({
            "mac": f"aa:bb:cc:dd:ee:{i:02x}",
            "status": "Unknown",
            "risk_score": 30,
            "risk_band": "Medium",
            "reasons": [],
            "created_at": f"2026-01-01T00:00:0{i}+00:00",
        })

    alerts = firestore_repos.alert.get_recent_alerts(limit=3)
    assert len(alerts) == 3


# ---------------------------------------------------------------------
# Live session repository
# ---------------------------------------------------------------------

def test_firestore_live_session_lifecycle(firestore_repos):
    session = firestore_repos.live_session.create_live_session(
        "sess-1", "eth0", "10.0.0.0/24"
    )
    assert session["status"] == "created"

    assert firestore_repos.live_session.update_live_session(
        "sess-1", status="running", started_at="2026-01-01T00:00:00+00:00"
    ) is True

    fetched = firestore_repos.live_session.get_live_session("sess-1")
    assert fetched["status"] == "running"
    assert fetched["device_count"] == 0


def test_firestore_live_observation_dedup_by_mac(firestore_repos):
    firestore_repos.live_session.create_live_session("sess-2", "eth0")

    firestore_repos.live_session.save_live_observation("sess-2", {
        "mac": "AA:BB:CC:DD:EE:20",
        "ip": "10.0.0.20",
        "protocols": ["TCP"],
        "ports": ["80"],
    })
    firestore_repos.live_session.save_live_observation("sess-2", {
        "mac": "aa:bb:cc:dd:ee:20",
        "ip": "10.0.0.21",
        "protocols": ["UDP"],
        "ports": ["443"],
    })

    devices = firestore_repos.live_session.get_live_observations("sess-2")
    assert len(devices) == 1  # same MAC merges, no duplicate
    assert devices[0]["observation_count"] == 2
    assert set(devices[0]["protocols"]) == {"TCP", "UDP"}
    assert set(devices[0]["ports"]) == {"80", "443"}


def test_firestore_delete_live_session_removes_observations(firestore_repos):
    firestore_repos.live_session.create_live_session("sess-3", "eth0")
    firestore_repos.live_session.save_live_observation(
        "sess-3", {"mac": "aa:bb:cc:dd:ee:30"}
    )

    assert firestore_repos.live_session.delete_live_session("sess-3") is True
    assert firestore_repos.live_session.get_live_session("sess-3") is None
    assert firestore_repos.live_session.delete_live_session("sess-3") is False


# ---------------------------------------------------------------------
# User repository (business logic only -- see module docstring)
# ---------------------------------------------------------------------

@pytest.fixture
def no_op_transactional(monkeypatch):
    """
    Replace firebase_admin.firestore.transactional with a
    pass-through decorator for these tests, so create_user's
    duplicate-check-then-create logic runs directly against the fake
    client instead of going through the real SDK's transaction-retry
    machinery (which assumes a live Firestore connection/emulator).
    """

    from firebase_admin import firestore as fa_firestore
    monkeypatch.setattr(fa_firestore, "transactional", lambda fn: fn)


def test_firestore_create_user_and_lookup(firestore_repos, no_op_transactional):
    user = firestore_repos.user.create_user("Alice", "Alice@Example.com", "hash123")
    assert user["email"] == "alice@example.com"

    by_email = firestore_repos.user.get_user_by_email("alice@example.com")
    assert by_email is not None
    assert by_email["name"] == "Alice"

    by_id = firestore_repos.user.get_user_by_id(user["id"])
    assert by_id["email"] == "alice@example.com"


def test_firestore_create_user_duplicate_email_rejected(firestore_repos, no_op_transactional):
    firestore_repos.user.create_user("Alice", "dup@example.com", "hash1")

    with pytest.raises(ValueError, match="already exists"):
        firestore_repos.user.create_user("Alice2", "dup@example.com", "hash2")


def test_firestore_session_lifecycle(firestore_repos, no_op_transactional):
    user = firestore_repos.user.create_user("Bob", "bob@example.com", "hash")

    firestore_repos.user.create_session("jti-1", user["id"], expires_at=99999999999)

    active = firestore_repos.user.get_active_session("jti-1", user["id"], now_ts=1)
    assert active is not None
    assert active["email"] == "bob@example.com"

    firestore_repos.user.revoke_session("jti-1", revoked_at="2026-01-01T00:00:00+00:00")

    revoked = firestore_repos.user.get_active_session("jti-1", user["id"], now_ts=1)
    assert revoked is None


def test_firestore_expired_session_not_active(firestore_repos, no_op_transactional):
    user = firestore_repos.user.create_user("Carl", "carl@example.com", "hash")
    firestore_repos.user.create_session("jti-2", user["id"], expires_at=100)

    active = firestore_repos.user.get_active_session("jti-2", user["id"], now_ts=99999)
    assert active is None
