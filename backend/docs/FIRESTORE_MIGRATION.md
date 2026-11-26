# Firestore migration

## Status: built, tested against mocks/emulated client, **not yet activated**

`backend/api.py` and `backend/shadowshield/auth.py` still call
`storage.py`/raw `sqlite3` directly. This migration added a parallel,
fully-tested repository abstraction (`backend/shadowshield/repositories/`)
and a Firestore implementation of it, but **did not cut the live app
over to it**. The running application's behavior is unchanged until
someone explicitly wires `api.py`/`auth.py` to call through
`shadowshield.repositories.get_repositories()` instead, which should
only happen after the steps below are complete.

Why deferred: cutting over without (a) real Firebase credentials to
test against and (b) a verified backup of whatever currently lives in
production risked exactly the kind of silent, unverifiable data loss
this task was explicitly scoped to avoid.

## Architecture

```
backend/shadowshield/
  repositories/
    __init__.py          -- get_repositories() factory, DB_BACKEND env var
    interfaces.py         -- abstract base classes (one per domain)
    sqlite_repositories.py    -- wraps existing storage.py / direct sqlite3
    firestore_repositories.py -- Firebase Admin SDK / Firestore implementation
  firebase_client.py      -- lazy singleton Firestore client, clear startup errors
backend/scripts/
  migrate_sqlite_to_firestore.py  -- one-off backup importer (see below)
backend/tests/
  fake_firestore.py                 -- in-memory fake of the Firestore client surface used
  test_repositories.py              -- repository layer tests (22 tests)
  test_migrate_sqlite_to_firestore.py -- migration script tests (6 tests)
```

Detection logic (`detection.py`, `risk.py`, `fingerprint.py`, `oui.py`)
imports nothing from this package and never will -- it only receives
and returns plain dicts, so switching storage backends cannot change
detection behavior.

## Firestore collection layout

| Collection | Document ID | Notes |
|---|---|---|
| `inventory` | normalized MAC | one doc per approved device; upsert is idempotent |
| `analyses` | existing `analysis_id` UUID | metadata only (source_name, source_type, device_count, created_at) |
| `analyses/{id}/observations` | auto | subcollection; not fetched when just listing analyses |
| `analyses/{id}/results` | auto | subcollection; per-device detection results |
| `alerts` | auto (or source SQLite row id, via the migration script) | ordered by `created_at` |
| `live_sessions` | existing `session_id` UUID | session metadata |
| `live_sessions/{id}/observations` | normalized MAC | mirrors the `UNIQUE(session_id, mac)` SQLite constraint; repeat observations merge into the same doc |
| `users` | generated UUID4 | SQLite's auto-increment integer id has no Firestore equivalent -- see **Known gap** below |
| `sessions` | JWT `jti` | mirrors `auth_sessions` |

## Known gap: JWT `sub` claim type

`shadowshield/auth.py` currently does `user_id = int(payload["sub"])`
when verifying a token, because SQLite's `users.id` is an integer.
Firestore's `FirestoreUserRepository` generates a string UUID4 user id
instead (Firestore has no auto-increment primary key). **This means
`auth.py` cannot be switched to `DB_BACKEND=firestore` as-is** -- that
`int(...)` cast needs to become a plain string pass-through first.
This is intentionally left undone in this pass rather than silently
changed, since `auth.py` is live, working, authentication-critical
code that was out of scope to touch without very deliberate testing.

## Setting up Firebase

1. In the Firebase console, create (or reuse) project **AURVEX**.
2. Enable **Cloud Firestore** (Native mode) for that project.
3. Project Settings → Service Accounts → **Generate new private key**.
   This downloads a JSON file -- treat it as a secret. Never commit it.
4. Decide composite indexes once real query patterns are known. The
   queries this migration uses (`order_by("created_at")` with no
   additional `where`, and single-field `where("email", "==", ...)`)
   do **not** require a composite index under Firestore's automatic
   single-field indexing. If a future query combines a `where` and an
   `order_by` on different fields, Firestore will return an error
   with a direct link to create the needed composite index -- follow
   that link rather than guessing one in advance.

## Environment variables (Render)

Set these in Render's dashboard under the backend service's
**Environment** tab -- never commit them:

| Variable | Value |
|---|---|
| `DB_BACKEND` | `firestore` (only once verified; leave as `sqlite` or unset until then) |
| `FIREBASE_PROJECT_ID` | your Firebase project id |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | the full contents of the downloaded service-account JSON, pasted as one line |

`JWT_SECRET` is **not** changed by this migration -- leave it exactly
as currently configured.

## Local development

```bash
cp backend/.env.example backend/.env
# fill in FIREBASE_PROJECT_ID / FIREBASE_SERVICE_ACCOUNT_JSON only if
# you intend to actually exercise DB_BACKEND=firestore locally against
# a real (ideally non-production) Firebase project.
pip install -r backend/requirements.txt
```

To run the app against SQLite (current, default behavior): don't set
`DB_BACKEND` at all, or set it to `sqlite`. Nothing else changes.

## Testing

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/ -v
```

All Firestore-related tests run against `tests/fake_firestore.py`, an
in-memory fake of the Firestore client surface this code actually
uses -- **no real Firebase project or credentials are required to run
the test suite**, satisfying that requirement directly. There is one
documented gap: `create_user`'s Firestore transaction decorator
(`firebase_admin.firestore.transactional`) is monkeypatched to a
pass-through in tests, so the *duplicate-email business logic* is
tested, but the real SDK's transaction-retry behavior is not --
verifying that fully would need a live Firestore emulator (the `gcloud
emulators firestore start` Java-based emulator), which wasn't run in
this environment.

## SQLite backup import procedure

**Never run this against production without a verified backup file in
hand first.**

1. Obtain a verified SQLite backup (e.g. via Render's shell: a file
   produced by SQLite's own `.backup` command against the live
   `shadowshield.db`, downloaded off the instance).
2. Dry run first (no credentials needed, nothing written):
   ```bash
   python backend/scripts/migrate_sqlite_to_firestore.py \
     --backup /path/to/shadowshield_backup.db \
     --dry-run
   ```
   Review the printed counts. If `errors` is non-empty for any table,
   stop and investigate before proceeding.
3. Real import, with the report saved:
   ```bash
   python backend/scripts/migrate_sqlite_to_firestore.py \
     --backup /path/to/shadowshield_backup.db \
     --project-id <your-project-id> \
     --service-account /path/to/service-account.json \
     --report migration_report.json
   ```
4. The script is idempotent -- every write reuses the source record's
   own identifier as the Firestore document id (MAC for inventory,
   existing UUID for analyses/live sessions, MAC for live
   observations, original SQLite row id for alerts/observations/
   results). Re-running it after a failure overwrites the same
   documents with the same data rather than duplicating them.
5. The script never deletes, modifies, or writes to the source SQLite
   file -- it is opened in SQLite's read-only URI mode
   (`file:...?mode=ro`).
6. Only after the report shows zero errors and a spot-check in the
   Firebase console confirms the data looks right should `DB_BACKEND`
   be switched to `firestore` on Render -- and only after `api.py`/
   `auth.py` have actually been wired to the repository factory (see
   **Known gap** above and the "not yet activated" note at the top of
   this document).

## Rollback

Because this pass never changed `api.py`/`auth.py`'s live code path,
"rollback" for everything done so far is simply: do nothing further.
If a future PR wires the app to the repository layer and sets
`DB_BACKEND=firestore` on Render, rollback is:

1. On Render, set `DB_BACKEND` back to `sqlite` (or remove it) and
   redeploy.
2. Confirm `backend/shadowshield.db` (or whatever
   `SHADOWSHIELD_DB_PATH` points at) still has the pre-cutover data --
   this is exactly why step 6 above (backup + verified import, not a
   destructive cutover) matters.
