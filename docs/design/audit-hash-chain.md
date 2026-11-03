# Design: tamper-evident audit log

Status: implemented in 0.6.0 (approved 2026-11-03). Threat model R3 describes
what it covers.

## Problem

`audit.db` is a SQLite file, `0600`, opened without following symlinks. That
stops other users and symlink tricks, but anything running as the user, the
agent included, can open it with `sqlite3` and rewrite or delete rows. Nothing
would notice.

A hash chain makes edits visible. Two things make it harder than "hash each
row with the previous hash":

- **Rows change after they are written.** `record_pending` inserts a row when a
  call arrives; `record_decision`, `record_windowed` and `record_outcome`
  update it later, sometimes minutes later while a prompt is open. A chain over
  mutable rows breaks on every legitimate update.
- **Several processes write the same file.** Every MCP client session runs its
  own `mcp-warden mcp`, and the CLI writes too (`lock`, `unlock`, `run`,
  `preset confirm`, `doctor --deep`). Two writers must never fork the chain.

And one thing a chain alone cannot do: an attacker who can edit the file can
also recompute every hash. Something outside SQLite has to remember where the
chain was.

## Records

`events` stays exactly as it is: the CLI, the web UI and `query()` keep reading
it. Next to it, a new append-only table:

```sql
CREATE TABLE chain (
    seq      INTEGER PRIMARY KEY,   -- 1, 2, 3, … with no gaps
    event_id INTEGER NOT NULL,      -- events.id this record is about (0 for genesis)
    record   TEXT NOT NULL,         -- canonical JSON, see below
    hash     TEXT NOT NULL          -- lowercase hex SHA-256
);
CREATE INDEX idx_chain_event ON chain(event_id);
```

Every `record_*` call appends one record, in the same transaction as its change
to `events`:

| Call | Record |
|---|---|
| `record_pending` | `{"kind":"pending","event":7,"at":"…","preset":"…","action":"…","summary":"…","client":"…","session":"…"}` |
| `record_decision` | `{"kind":"decision","event":7,"decision":"approved"}` |
| `record_windowed` | `{"kind":"windowed","event":7,"via_event":3}` |
| `record_outcome` | `{"kind":"outcome","event":7,"outcome_kind":"ok","outcome_data":"…"}` |
| migration | `{"kind":"genesis","v":1,"chain_id":"…","legacy_through":41,"legacy_rows":41,"legacy_digest":"…","at":"…"}` |

The JSON is serialised from fixed Rust structs, so the field order is fixed.
The values are the exact strings stored in `events`, not values re-read from
it: `row_to_event` is lossy (an unknown decision reads as `Timeout`, a bad
timestamp as now).

```
hash(seq) = SHA-256("mcp-warden-audit-v1\n" ‖ hash(seq-1) ‖ "\n" ‖ seq ‖ "\n" ‖ record)
```

`hash(0)` is 64 zeros. The domain prefix and the `seq` inside the hash stop a
record from being moved to another position.

### Writing

Each `record_*` call runs one transaction:

1. `BEGIN IMMEDIATE` (takes the write lock up front; `busy_timeout` 5 s lets a
   second writer wait instead of failing);
2. the `INSERT` or `UPDATE` on `events`; an `UPDATE` that changes no row is an
   error;
3. read the tip: `SELECT seq, hash FROM chain ORDER BY seq DESC LIMIT 1`;
4. insert `seq + 1` with the new hash;
5. `COMMIT`.

Writers queue on SQLite's lock, `seq` is the primary key, and the tip is read
inside the transaction, so two processes cannot append the same `seq` and the
chain stays linear.

Triggers refuse `UPDATE` and `DELETE` on `chain` and `DELETE` on `events`:

```sql
CREATE TRIGGER chain_no_update BEFORE UPDATE ON chain BEGIN SELECT RAISE(ABORT, 'audit chain is append-only'); END;
CREATE TRIGGER chain_no_delete BEFORE DELETE ON chain BEGIN SELECT RAISE(ABORT, 'audit chain is append-only'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
```

They catch our own bugs. An attacker with `sqlite3` can drop them, and the
chain then shows what they changed.

The `AuditSink` trait stays append-only (invariant 7). The new methods only
read: `chain_tip()`, `chain_hash_at(seq)`, `verify_chain()`.

## Migration

On open, inside `BEGIN IMMEDIATE`, and only if `chain` is empty, a database
created before 0.6.0 gets its genesis record:

- `legacy_through` is `MAX(events.id)` (0 for a new database);
- `legacy_rows` is the number of those rows;
- `legacy_digest` is a SHA-256 over their raw columns in id order;
- `chain_id` is 16 random bytes in hex;
- `PRAGMA user_version = 1`.

Running it twice, or in two processes at once, still writes one genesis: the
second writer sees a non-empty chain.

Rows up to `legacy_through` are reported as "before 0.6.0, not chained". The
digest tells whether they changed after the upgrade.

Known limits, stated in the CHANGELOG:

- MCP clients must be restarted after upgrading. A 0.5.x server still running
  writes rows without chain records, and `verify` reports them as unchained.
- A 0.5.x prompt still open during the upgrade updates a legacy row, and the
  legacy digest no longer matches.
- Downgrading to 0.5.x breaks the chain the same way.

## Verify

`mcp-warden audit verify [--format json]` only reads, in two streaming passes,
with constant memory:

1. **The chain.** Walk `chain` by `seq`. `seq` must have no gaps, the first
   record must be genesis, every record must parse, and every recomputed hash
   must match. Stop at the first failure: "chain broken at record N (event M)".
2. **The table against the chain.** For each `events` row in id order, fold its
   chain records and compare the raw columns:
   - a field differs → "event M changed after it was recorded (decision: chain
     says approved, table says auto)";
   - a row after `legacy_through` has no `pending` record → "event M is not in
     the chain";
   - a `pending` record whose row is missing → "event M was deleted";
   - the legacy digest differs → "rows written before 0.6.0 changed".

Exit code 0 if everything holds, 1 otherwise.

Without the anchor below, removing records from the end of the chain is not
detectable. A test pins that, so nobody mistakes the chain for more than it is.

## Anchor

A keychain entry outside SQLite remembers how far the chain reached:

```
name:  audit/anchor/<first 16 hex chars of SHA-256(canonical path of audit.db)>
value: v1 seq=<n> hash=<hex> chain=<chain_id> at=<rfc3339>
```

- **Keyed by the path, not the chain id.** Otherwise deleting the database and
  starting a new chain would also start a new anchor, and look like "never
  anchored".
- **A plain value, not an HMAC.** Writing the keychain directly is out of scope
  (threat model N2). Anyone who can do that can forge an HMAC key read from the
  same keychain too.
- **`audit/` is reserved** like `stamp/`. `secret add`, `secret remove`,
  `secret list`, `doctor`, and every config field that names a keychain entry
  refuse or hide it, so it cannot be overwritten through the CLI or revealed
  through `get_secret_for_env`.

### When it moves

Never once per tool call: keychain writes are slow and may prompt. Instead:

- a background task in the MCP server, every 60 seconds, only if the tip moved
  since this process last anchored it (`spawn_blocking`, never on a prompt
  path);
- once when the MCP server shuts down;
- on `mcp-warden lock` and `unlock`, best effort, after the lock file is
  written;
- after `audit verify` finds the log intact.

### How it moves

Under an exclusive lock on `<config dir>/locks/audit-anchor.lock`
(`try_lock`; if busy, skip this round):

1. read the anchor A;
2. require that chain record `A.seq` still has hash `A.hash`, and that the tip
   is at or after `A.seq`;
3. recompute the links from `A.seq` to the tip;
4. write the tip as the new anchor.

If step 2 or 3 fails, the anchor **does not move**: `tracing::error!` goes to
stderr, and `audit verify`, `doctor` and the web UI report the log as rewritten.
Nothing else changes: the kill switch is not latched (owner decision,
2026-11-03).

This closes the obvious laundering path: rewrite `audit.db`, recompute the
whole chain, then run `mcp-warden lock` so the anchor follows the forgery. The
anchored record's hash no longer matches, so the anchor stays where it was and
`verify` names the break.

The lock file keeps the anchor monotonic when several processes try at once. A
process that loses the race skips; the next round picks up the newer tip.

### What verify adds with the anchor

Only the CLI reads the anchor; the web UI never touches the keychain
(docs/web-ui.md) and shows "chain intact, not checked against the anchor".

- Anchored record matches → "anchored through record N; K later records are
  covered by the chain only".
- The anchor names a record after the tip, or the database is missing or empty
  while an anchor exists → "records after N were removed, or the log was
  replaced".
- The anchored record's hash differs → "the log was rewritten before record N".
- No anchor → "not anchored yet" (a new install, or Linux keyutils lost it on
  reboot).

## What this protects, honestly

- **The chain alone** catches corruption and naive edits made with `sqlite3`.
  Anyone who can write the file can still recompute it.
- **The anchor** protects history up to the last time it moved: at most about
  60 seconds behind while a server runs, or up to the end of the last session.
  Records after the anchor can still be rewritten or cut off.
- **Out of scope:** root, and anything that writes the keychain directly (N2).
- **Linux:** keyutils entries may not survive a reboot (as with secrets), and
  `verify` then reports "not anchored yet".

## Tests

- One chain record per `record_*` call, and the links verify.
- Two `LocalSqlite` instances writing from two threads produce one linear chain.
- The triggers refuse `UPDATE` and `DELETE`.
- Migration of a 0.5.4-shaped fixture database: genesis written once, reopening
  is a no-op, two concurrent opens write one genesis.
- One test per kind of tampering: an edited event field, an edited chain
  record, a deleted event, a deleted chain record, an inserted unchained row,
  corrupt record JSON (reported, no panic), an edited legacy row; and a test
  that pins "a cut tail is invisible without the anchor".
- Anchor: it advances; a laundering attempt is refused and the anchor stays
  unchanged; rolling back to an older copy of the database and deleting it are
  both detected; two threads racing never move the anchor backwards.
- The MCP server writes at most one anchor per interval, and none while the tip
  stays still.
