#!/usr/bin/env python
"""
Import a verified SQLite backup into Firestore.

This script NEVER touches a live/production SQLite database -- it
opens the backup file you give it in read-only mode and never writes
to it, never deletes it, and never modifies the original in any way.

Usage:

    python scripts/migrate_sqlite_to_firestore.py \\
        --backup /path/to/shadowshield_backup.db \\
        --project-id aurvex-prod \\
        [--service-account /path/to/service-account.json] \\
        [--dry-run] \\
        [--report /path/to/migration_report.json]

Requires either:
  --service-account pointing at a service-account JSON file, or
  the FIREBASE_SERVICE_ACCOUNT_JSON / FIREBASE_PROJECT_ID environment
  variables already set (same as the running backend).

Safety properties:
- Read-only against the SQLite backup (opened with a URI that forces
  read-only mode; see `_open_readonly`).
- Schema validation: refuses to run against a file that doesn't look
  like a shadowshield.db backup (checks for the expected tables).
- Duplicate detection: every write uses the *same document ID* the
  source record already has (approved_inventory.mac, analyses.id,
  live_sessions.session_id, alerts' own auto-id reused as the
  Firestore doc id) so re-running this script twice does not create
  duplicates -- it overwrites the same documents with the same data.
- Safe retrying: because writes are idempotent (see above), a failed
  or interrupted run can simply be re-run from the top without manual
  cleanup.
- Produces a JSON migration report: counts per table, duplicates
  skipped, and any per-record errors -- written to --report or
  printed to stdout if not given.
- Never deletes anything from the source SQLite file.

This script is NOT wired into any API route and is NOT run
automatically by anything in this repository. It must be invoked
manually, against an explicitly supplied backup file, by someone who
has already verified that backup is complete and correct.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path


REQUIRED_TABLES = {
    "approved_inventory",
    "analyses",
    "observations",
    "analysis_results",
    "alerts",
    "live_sessions",
    "live_observations",
}


def _open_readonly(path: str) -> sqlite3.Connection:
    resolved = Path(path).resolve()

    if not resolved.is_file():
        raise FileNotFoundError(f"Backup file not found: {resolved}")

    uri = f"file:{resolved.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def _validate_schema(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    tables = {row["name"] for row in rows}

    missing = REQUIRED_TABLES - tables
    if missing:
        raise ValueError(
            "This file does not look like a shadowshield.db backup -- "
            f"missing expected tables: {sorted(missing)}"
        )


def _load_json_list(value, default=None):
    if not value:
        return default if default is not None else []
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default if default is not None else []


def _init_firestore(args) -> "google.cloud.firestore.Client":  # noqa: F821
    if args.service_account:
        service_account_path = Path(args.service_account).resolve()
        with open(service_account_path, "r", encoding="utf-8") as f:
            os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"] = f.read()

    if args.project_id:
        os.environ["FIREBASE_PROJECT_ID"] = args.project_id

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from shadowshield.firebase_client import get_firestore_client

    return get_firestore_client()


def migrate(conn: sqlite3.Connection, db, dry_run: bool) -> dict:
    report = {
        "inventory": {"read": 0, "written": 0, "errors": []},
        "analyses": {"read": 0, "written": 0, "observations": 0, "results": 0, "errors": []},
        "alerts": {"read": 0, "written": 0, "errors": []},
        "live_sessions": {"read": 0, "written": 0, "observations": 0, "errors": []},
        "dry_run": dry_run,
    }

    # --- inventory ---------------------------------------------------
    for row in conn.execute("SELECT * FROM approved_inventory"):
        report["inventory"]["read"] += 1
        try:
            mac = row["mac"]
            doc = dict(row)
            doc["ports"] = _load_json_list(doc.get("ports"))
            doc["protocols"] = _load_json_list(doc.get("protocols"))
            doc["allowed_ports"] = _load_json_list(doc.get("allowed_ports"))
            doc["fingerprint"] = _load_json_list(doc.get("fingerprint"), {})

            if not dry_run:
                db.collection("inventory").document(mac).set(doc)
            report["inventory"]["written"] += 1
        except Exception as exc:
            report["inventory"]["errors"].append({"mac": row["mac"], "error": str(exc)})

    # --- analyses (+ observations + results subcollections) ----------
    for arow in conn.execute("SELECT * FROM analyses"):
        analysis_id = arow["id"]
        report["analyses"]["read"] += 1
        try:
            analysis_doc = dict(arow)

            if not dry_run:
                ref = db.collection("analyses").document(analysis_id)
                ref.set(analysis_doc)

                for orow in conn.execute(
                    "SELECT * FROM observations WHERE analysis_id=?",
                    (analysis_id,),
                ):
                    odoc = dict(orow)
                    odoc["ports"] = _load_json_list(odoc.get("ports"))
                    odoc["protocols"] = _load_json_list(odoc.get("protocols"))
                    # Reuse the original SQLite row id as the Firestore
                    # document id so re-running this script overwrites
                    # the same document instead of duplicating it.
                    ref.collection("observations").document(
                        str(odoc["id"])
                    ).set(odoc)
                    report["analyses"]["observations"] += 1

                for rrow in conn.execute(
                    "SELECT * FROM analysis_results WHERE analysis_id=?",
                    (analysis_id,),
                ):
                    result_doc = json.loads(rrow["result_json"])
                    ref.collection("results").document(
                        str(rrow["id"])
                    ).set(result_doc)
                    report["analyses"]["results"] += 1

            report["analyses"]["written"] += 1
        except Exception as exc:
            report["analyses"]["errors"].append(
                {"analysis_id": analysis_id, "error": str(exc)}
            )

    # --- alerts --------------------------------------------------------
    for row in conn.execute("SELECT * FROM alerts"):
        report["alerts"]["read"] += 1
        try:
            doc = dict(row)
            doc["reasons"] = _load_json_list(doc.get("reasons"))

            if not dry_run:
                # Reuse the SQLite row id as the Firestore doc id for
                # idempotent re-runs.
                db.collection("alerts").document(str(doc["id"])).set(doc)
            report["alerts"]["written"] += 1
        except Exception as exc:
            report["alerts"]["errors"].append({"id": row["id"], "error": str(exc)})

    # --- live sessions (+ observations subcollection) ------------------
    for srow in conn.execute("SELECT * FROM live_sessions"):
        session_id = srow["session_id"]
        report["live_sessions"]["read"] += 1
        try:
            session_doc = dict(srow)

            if not dry_run:
                ref = db.collection("live_sessions").document(session_id)
                ref.set(session_doc)

                for obs_row in conn.execute(
                    "SELECT * FROM live_observations WHERE session_id=?",
                    (session_id,),
                ):
                    obs_doc = dict(obs_row)
                    obs_doc["protocols"] = _load_json_list(obs_doc.get("protocols"))
                    obs_doc["ports"] = _load_json_list(obs_doc.get("ports"))
                    obs_doc["dns_names"] = _load_json_list(obs_doc.get("dns_names"))
                    # Document id = normalized mac, matching the live
                    # UNIQUE(session_id, mac) constraint -- idempotent.
                    ref.collection("observations").document(
                        obs_doc["mac"]
                    ).set(obs_doc)
                    report["live_sessions"]["observations"] += 1

            report["live_sessions"]["written"] += 1
        except Exception as exc:
            report["live_sessions"]["errors"].append(
                {"session_id": session_id, "error": str(exc)}
            )

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", required=True, help="Path to the SQLite backup file.")
    parser.add_argument("--project-id", help="Firebase project id.")
    parser.add_argument("--service-account", help="Path to a service-account JSON file.")
    parser.add_argument("--dry-run", action="store_true", help="Read and validate only; write nothing.")
    parser.add_argument("--report", help="Path to write the JSON migration report to.")
    args = parser.parse_args()

    conn = _open_readonly(args.backup)

    try:
        _validate_schema(conn)

        if args.dry_run:
            print("DRY RUN -- no Firestore credentials required, nothing will be written.")
            db = None
        else:
            db = _init_firestore(args)

        report = migrate(conn, db, dry_run=args.dry_run)
    finally:
        conn.close()  # the backup file itself is never modified or deleted

    output = json.dumps(report, indent=2)

    if args.report:
        Path(args.report).write_text(output, encoding="utf-8")
        print(f"Migration report written to {args.report}")
    else:
        print(output)

    total_errors = sum(
        len(section.get("errors", []))
        for section in report.values()
        if isinstance(section, dict)
    )
    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
