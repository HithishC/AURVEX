"""
Lazy, single-initialization Firebase Admin SDK / Firestore client.

Only used when DB_BACKEND=firestore. Importing this module never
touches Firebase -- initialization happens on first call to
get_firestore_client(), and only once (module-level cache), so a
process running with DB_BACKEND=sqlite never needs Firebase
credentials at all.
"""

from __future__ import annotations

import json
import os
import threading

_client = None
_client_lock = threading.Lock()


class FirebaseConfigError(RuntimeError):
    """Raised when Firestore is selected but not configured correctly."""


def _load_credentials_dict() -> dict:
    raw = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "")

    if not raw.strip():
        raise FirebaseConfigError(
            "DB_BACKEND=firestore requires FIREBASE_SERVICE_ACCOUNT_JSON "
            "to be set to the service account's JSON credentials "
            "(as a single-line JSON string, e.g. from Render's "
            "environment variable editor). It is not set."
        )

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # Never echo the raw value back -- it may contain a private key.
        raise FirebaseConfigError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is set but is not valid JSON. "
            "Check that the full service-account JSON was pasted without "
            "being truncated or re-escaped."
        ) from exc


def get_firestore_client():
    """
    Return the process-wide Firestore client, initializing the
    Firebase Admin SDK on first call only.
    """

    global _client

    if _client is not None:
        return _client

    with _client_lock:
        if _client is not None:
            return _client

        project_id = os.getenv("FIREBASE_PROJECT_ID", "").strip()

        if not project_id:
            raise FirebaseConfigError(
                "DB_BACKEND=firestore requires FIREBASE_PROJECT_ID to be "
                "set. It is not set."
            )

        credentials_dict = _load_credentials_dict()

        import firebase_admin
        from firebase_admin import credentials, firestore

        if not firebase_admin._apps:
            cred = credentials.Certificate(credentials_dict)
            firebase_admin.initialize_app(
                cred, {"projectId": project_id}
            )

        _client = firestore.client()
        return _client


def reset_client_for_tests() -> None:
    """Test-only: clear the cached client so tests can re-initialize
    against a fresh mock/emulator between cases."""

    global _client
    with _client_lock:
        _client = None
