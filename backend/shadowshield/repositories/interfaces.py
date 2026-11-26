"""
Repository interfaces (abstract base classes).

Every method signature here mirrors an existing function in
shadowshield/storage.py or shadowshield/auth.py exactly -- same
parameter names, same return shape (plain dicts/lists) -- so that
either implementation (SQLite or Firestore) is a drop-in replacement
for the other, and for the original module-level functions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class InventoryRepository(ABC):
    @abstractmethod
    def upsert_approved(self, device: dict) -> None: ...

    @abstractmethod
    def delete_approved(self, mac: str) -> bool: ...

    @abstractmethod
    def get_approved_inventory(self) -> dict: ...


class AnalysisRepository(ABC):
    @abstractmethod
    def save_analysis(
        self,
        source_name: str,
        source_type: str,
        observations: list[dict],
        results: list[dict],
    ) -> str: ...

    @abstractmethod
    def get_analyses(self, limit: int = 50) -> list[dict]: ...

    @abstractmethod
    def get_analysis(self, analysis_id: str) -> dict | None: ...


class ObservationRepository(ABC):
    """
    Observations are written as part of save_analysis() (one analysis
    owns many observation rows) rather than through a standalone
    write method, matching the existing SQLite schema. This interface
    exists so observation *reads* have a stable, swappable home even
    though writes stay bundled with AnalysisRepository.save_analysis().
    """

    @abstractmethod
    def get_observations(self, analysis_id: str) -> list[dict]: ...


class AlertRepository(ABC):
    @abstractmethod
    def get_recent_alerts(self, limit: int = 100) -> list[dict]: ...


class LiveSessionRepository(ABC):
    @abstractmethod
    def create_live_session(
        self,
        session_id: str,
        interface: str,
        subnet: str | None = None,
    ) -> dict: ...

    @abstractmethod
    def update_live_session(
        self,
        session_id: str,
        status: str | None = None,
        started_at: str | None = None,
        stopped_at: str | None = None,
    ) -> bool: ...

    @abstractmethod
    def save_live_observation(
        self,
        session_id: str,
        observation: dict,
    ) -> bool: ...

    @abstractmethod
    def get_live_observations(self, session_id: str) -> list[dict]: ...

    @abstractmethod
    def get_live_session(self, session_id: str) -> dict | None: ...

    @abstractmethod
    def get_live_sessions(self, limit: int = 50) -> list[dict]: ...

    @abstractmethod
    def delete_live_session(self, session_id: str) -> bool: ...


class UserRepository(ABC):
    @abstractmethod
    def create_user(self, name: str, email: str, password_hash: str) -> dict: ...

    @abstractmethod
    def get_user_by_email(self, email: str) -> dict | None: ...

    @abstractmethod
    def get_user_by_id(self, user_id) -> dict | None: ...

    @abstractmethod
    def create_session(self, jti: str, user_id, expires_at: int) -> None: ...

    @abstractmethod
    def get_active_session(self, jti: str, user_id, now_ts: int) -> dict | None: ...

    @abstractmethod
    def revoke_session(self, jti: str, revoked_at: str) -> None: ...


class Repositories:
    """Simple namespace bundling one repository instance per domain."""

    def __init__(
        self,
        inventory: InventoryRepository,
        analysis: AnalysisRepository,
        observation: ObservationRepository,
        alert: AlertRepository,
        live_session: LiveSessionRepository,
        user: UserRepository,
    ):
        self.inventory = inventory
        self.analysis = analysis
        self.observation = observation
        self.alert = alert
        self.live_session = live_session
        self.user = user
