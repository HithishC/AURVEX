"""
Database abstraction layer.

Detection logic (shadowshield.detection, shadowshield.risk,
shadowshield.fingerprint, shadowshield.oui) never imports anything from
this package or from storage.py/auth.py directly -- it only ever
receives plain dicts. That independence is what makes swapping the
storage backend here safe: it cannot change detection behavior.

`get_repositories()` is the single factory used by the rest of the
app to obtain repository instances. The backend is selected with the
`DB_BACKEND` environment variable:

    DB_BACKEND=sqlite    (default) -- wraps the existing storage.py /
                          auth.py SQLite functions. Zero behavior
                          change from the pre-migration app.
    DB_BACKEND=firestore -- uses Firebase Cloud Firestore via the
                          Admin SDK. Requires FIREBASE_PROJECT_ID and
                          FIREBASE_SERVICE_ACCOUNT_JSON to be set.

IMPORTANT (deliberate scope boundary for this migration pass):
`backend/api.py` and `backend/shadowshield/auth.py` are NOT yet wired
to call through this factory -- they still call storage.py/sqlite3
directly, so the live, deployed application's behavior is completely
unchanged by this package's existence. This repository layer is built,
tested (against a Firestore emulator / mocked client, not production
credentials), and ready to be wired in, but that cutover is
intentionally deferred until Firestore has been verified against real
credentials and a verified SQLite backup import has been run. See
backend/docs/FIRESTORE_MIGRATION.md for the cutover steps.
"""

from __future__ import annotations

import os


def get_backend_name() -> str:
    return os.getenv("DB_BACKEND", "sqlite").strip().lower()


def get_repositories():
    """
    Return a namespace object exposing one repository instance per
    domain: .inventory, .analysis, .observation, .alert, .live_session,
    .user -- all implementing the interfaces in
    shadowshield.repositories.interfaces.
    """

    backend = get_backend_name()

    if backend == "sqlite":
        from . import sqlite_repositories as impl
    elif backend == "firestore":
        from . import firestore_repositories as impl
    else:
        raise RuntimeError(
            f"Unknown DB_BACKEND '{backend}'. Expected 'sqlite' or "
            "'firestore'."
        )

    return impl.build_repositories()
