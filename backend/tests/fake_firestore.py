"""
A minimal, in-memory fake of the pieces of the google-cloud-firestore
client API that shadowshield/repositories/firestore_repositories.py
actually uses. This is not a full Firestore emulator -- it exists so
the repository logic (collection/document layout, upsert semantics,
ordering, limits, batching, transactional duplicate-checking) can be
unit-tested without real Firebase credentials or a running emulator,
per the "mocked Firebase services or emulator" test requirement.

Supports: collection().document(id?), .set/.get/.update/.delete,
collection-level .stream(), .where(field, "==", value), .order_by(
field, direction=...) including the special "__name__" (document id)
field, .limit(n), .start_after(...) (accepted but not semantically
validated -- no test here exercises real pagination cursors), plus
.batch() and a best-effort .transaction()/transactional() pairing.
"""

from __future__ import annotations

import uuid


class FakeDocSnapshot:
    def __init__(self, doc_id, data, exists, reference=None):
        self.id = doc_id
        self._data = data
        self.exists = exists
        self.reference = reference

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class FakeDocRef:
    def __init__(self, store, path):
        self._store = store
        self.path = path
        self.id = path.rsplit("/", 1)[-1]

    def set(self, data, merge=False):
        if merge and self.path in self._store:
            self._store[self.path].update(data)
        else:
            self._store[self.path] = dict(data)

    def get(self):
        data = self._store.get(self.path)
        return FakeDocSnapshot(self.id, data, data is not None, reference=self)

    def update(self, updates):
        if self.path not in self._store:
            raise KeyError(f"No document to update at {self.path}")
        self._store[self.path].update(updates)

    def delete(self):
        self._store.pop(self.path, None)

    def collection(self, name):
        return FakeCollection(self._store, f"{self.path}/{name}")


class FakeQuery:
    def __init__(self, store, path, filters=None, order=None, limit=None):
        self._store = store
        self.path = path
        self._filters = filters or []
        self._order = order
        self._limit_n = limit

    def where(self, field, op, value):
        assert op == "==", "fake firestore only supports '==' filters"
        return FakeQuery(
            self._store, self.path, self._filters + [(field, value)],
            self._order, self._limit_n,
        )

    def order_by(self, field, direction="ASCENDING"):
        return FakeQuery(
            self._store, self.path, self._filters, (field, direction),
            self._limit_n,
        )

    def limit(self, n):
        return FakeQuery(self._store, self.path, self._filters, self._order, n)

    def start_after(self, _marker):
        # Accepted for interface compatibility; not implemented for
        # these unit tests, which only check single-page results.
        return self

    def _matching_docs(self):
        prefix = self.path + "/"
        docs = []
        for key, data in self._store.items():
            if not key.startswith(prefix):
                continue
            rest = key[len(prefix):]
            if "/" in rest:
                continue  # belongs to a deeper subcollection
            doc_id = rest
            if all(data.get(f) == v for f, v in self._filters):
                docs.append((doc_id, data))
        return docs

    def stream(self, transaction=None):
        docs = self._matching_docs()

        if self._order:
            field, direction = self._order
            if field == "__name__":
                docs.sort(key=lambda d: d[0])
            else:
                docs.sort(key=lambda d: d[1].get(field))
            if direction == "DESCENDING":
                docs.reverse()

        if self._limit_n is not None:
            docs = docs[: self._limit_n]

        return [
            FakeDocSnapshot(
                doc_id, data, True,
                reference=FakeDocRef(self._store, f"{self.path}/{doc_id}"),
            )
            for doc_id, data in docs
        ]


class FakeCollection(FakeQuery):
    def __init__(self, store, path):
        super().__init__(store, path)

    def document(self, doc_id=None):
        if doc_id is None:
            doc_id = str(uuid.uuid4())
        return FakeDocRef(self._store, f"{self.path}/{doc_id}")


class FakeBatch:
    def __init__(self, store):
        self._store = store
        self._ops = []

    def set(self, ref, data):
        self._ops.append(("set", ref, dict(data)))

    def commit(self):
        for op, ref, data in self._ops:
            ref.set(data)
        self._ops = []


class FakeTransaction:
    """Supports the subset of the Transaction API this codebase uses:
    passing to .stream(transaction=...) (ignored) and .set(ref, data)
    for writes staged during the transaction."""

    def set(self, ref, data):
        ref.set(data)


class FakeFirestoreClient:
    def __init__(self):
        self._store: dict[str, dict] = {}

    def collection(self, name):
        return FakeCollection(self._store, name)

    def batch(self):
        return FakeBatch(self._store)

    def transaction(self):
        return FakeTransaction()
