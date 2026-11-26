"""
SQLite repository implementations.

These are thin wrappers around the existing, already-tested functions
in shadowshield/storage.py and shadowshield/auth.py. They introduce no
new SQL and no behavior change -- their only job is to satisfy the
Repositories interface so call sites written against that interface
work identically to call sites written against the raw module
functions.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from config import DB_PATH
from . import interfaces
from .. import storage


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteInventoryRepository(interfaces.InventoryRepository):
    def upsert_approved(self, device: dict) -> None:
        storage.upsert_approved(device)

    def delete_approved(self, mac: str) -> bool:
        return storage.delete_approved(mac)

    def get_approved_inventory(self) -> dict:
        return storage.get_approved_inventory()


class SqliteAnalysisRepository(interfaces.AnalysisRepository):
    def save_analysis(
        self,
        source_name: str,
        source_type: str,
        observations: list[dict],
        results: list[dict],
    ) -> str:
        return storage.save_analysis(
            source_name, source_type, observations, results
        )

    def get_analyses(self, limit: int = 50) -> list[dict]:
        return storage.get_analyses(limit)

    def get_analysis(self, analysis_id: str) -> dict | None:
        return storage.get_analysis(analysis_id)


class SqliteObservationRepository(interfaces.ObservationRepository):
    def get_observations(self, analysis_id: str) -> list[dict]:
        return storage.get_observations(analysis_id)


class SqliteAlertRepository(interfaces.AlertRepository):
    def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        return storage.get_recent_alerts(limit)


class SqliteLiveSessionRepository(interfaces.LiveSessionRepository):
    def create_live_session(
        self,
        session_id: str,
        interface: str,
        subnet: str | None = None,
    ) -> dict:
        return storage.create_live_session(session_id, interface, subnet)

    def update_live_session(
        self,
        session_id: str,
        status: str | None = None,
        started_at: str | None = None,
        stopped_at: str | None = None,
    ) -> bool:
        return storage.update_live_session(
            session_id, status, started_at, stopped_at
        )

    def save_live_observation(self, session_id: str, observation: dict) -> bool:
        return storage.save_live_observation(session_id, observation)

    def get_live_observations(self, session_id: str) -> list[dict]:
        return storage.get_live_observations(session_id)

    def get_live_session(self, session_id: str) -> dict | None:
        return storage.get_live_session(session_id)

    def get_live_sessions(self, limit: int = 50) -> list[dict]:
        return storage.get_live_sessions(limit)

    def delete_live_session(self, session_id: str) -> bool:
        return storage.delete_live_session(session_id)


class SqliteUserRepository(interfaces.UserRepository):
    """
    Wraps the users/auth_sessions tables that shadowshield/auth.py
    creates and queries directly today. This repository does not yet
    replace auth.py's own sqlite3 calls (see package docstring) --
    it exists so a Firestore UserRepository can be verified against
    the identical contract before that cutover happens.
    """

    def _connect(self):
        conn = sqlite3.connect(DB_PATH, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn

    def create_user(self, name: str, email: str, password_hash: str) -> dict:
        now = _now_iso()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users (name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (name, email, password_hash, now),
            )
            row = conn.execute(
                "SELECT id, name, email FROM users WHERE email = ?",
                (email,),
            ).fetchone()

        return dict(row)

    def get_user_by_email(self, email: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,),
            ).fetchone()

        return dict(row) if row else None

    def get_user_by_id(self, user_id) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, email FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

        return dict(row) if row else None

    def create_session(self, jti: str, user_id, expires_at: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (jti, user_id, expires_at)
                VALUES (?, ?, ?)
                """,
                (jti, user_id, expires_at),
            )

    def get_active_session(self, jti: str, user_id, now_ts: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.id, u.name, u.email, s.jti
                FROM auth_sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.jti = ?
                  AND s.user_id = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                """,
                (jti, user_id, now_ts),
            ).fetchone()

        return dict(row) if row else None

    def revoke_session(self, jti: str, revoked_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at = ? WHERE jti = ?",
                (revoked_at, jti),
            )


def build_repositories() -> interfaces.Repositories:
    return interfaces.Repositories(
        inventory=SqliteInventoryRepository(),
        analysis=SqliteAnalysisRepository(),
        observation=SqliteObservationRepository(),
        alert=SqliteAlertRepository(),
        live_session=SqliteLiveSessionRepository(),
        user=SqliteUserRepository(),
    )
