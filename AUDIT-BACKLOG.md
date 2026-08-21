# Audit backlog — clustered and prioritised

Two audit rounds against a real database produced **213 candidates**; **107**
survived adversarial verification. As of **0.40.0**, 24 are fixed and **83
remain**, grouped below by the *root cause they share* rather than by guard,
because most of them are one mistake made in several places.

The clusters are ordered by damage, not by count.

| | Cluster | Open | Why it ranks here |
|---|---|---|---|
| **P0** | [A. False assurance](#a-false-assurance) | 4 | The tool says "proven" about a probe that never ran |
| **P0** | [B. Fires on correct code](#b-fires-on-correct-code) | 12 | Teaches people to loosen security to silence it |
| **P1** | [C. Fix text that breaks the app](#c-fix-text-that-breaks-the-app) | 9 | The 0.26.0 class: advice applied blind |
| **P1** | [D. Fix text that silently does nothing](#d-fix-text-that-silently-does-nothing) | 7 | User applies it, guard keeps failing, trust goes |
| **P1** | [E. Emitted SQL that will not run](#e-emitted-sql-that-will-not-run) | 5 | Copy-paste, get a syntax or type error |
| **P2** | [F. Parsing: comments and quoted bodies](#f-parsing-comments-and-quoted-bodies) | 6 | Both directions — misses and false positives |
| **P2** | [G. Probe coverage gaps](#g-probe-coverage-gaps) | 14 | Real leaks the guard's own scope should reach |
| **P2** | [H. Privilege resolution](#h-privilege-resolution) | 8 | PUBLIC, role membership, column grants |
| **P3** | [I. Shared-helper drift](#i-shared-helper-drift) | 6 | Three copies of "which column is the tenant" |
| **P3** | [J. Cosmetic, perf, packaging](#j-cosmetic-perf-packaging) | 12 | Real but low-consequence |

---

## A. False assurance

*The guard reports a green verdict about something it did not test.* Worst
class: a missed leak is a gap, this is an untrue statement, and it is the one
thing a user cannot check for themselves.

**Fixed in 0.40.0** — column-exposure role precheck; column-exposure alias
truncation at 63 bytes; trigger-visibility on an empty table; storage-isolation
own-read control arm; realtime-isolation asserting a denial that cannot apply.

**Open (4):**

- `schema-tenancy` probes only the **alphabetically first** table of each tenant
  schema. A role denied that one table but granted another in the same foreign
  schema reports "proven scoped to one tenant" while reading the other tenant's
  rows.
- `schema-tenancy` infers tenant schemas by **exact table-set equality** and
  probes only the largest matching group. One extra table in one schema makes it
  report "not a schema-per-tenant database".
- `default-privileges` only ever creates its probe table **as the connecting
  role**, so `ALTER DEFAULT PRIVILEGES FOR ROLE <migration role>` — the usual
  shape — is never exercised.
- `cross-tenant-fk` treats an UPDATE that matched **zero rows** as "blocked" and
  emits that as a silent pass.

---

## B. Fires on correct code

*The most damaging outcome for a linter.* A guard that fails a build over a
configuration that is already right teaches people to loosen their security to
silence it — which is how the 0.26.0 outage happened, from the other direction.

**Fixed in 0.38.0** — the standard Supabase `REVOKE … ON ALL TABLES IN SCHEMA`
lockdown; `identity-trust` firing on its own recommended fix.

**Open (12), most user-visible first:**

- `route-org-scoping` fails the build on `.eq('user_id', user.id)` — a route
  scoped by the session user's own id. **This is the same complaint the
  MonkeyTravel report made (§4) and it is still open.**
- `constraint-oracles` fails on globally-UNIQUE **bearer-secret** columns —
  invite `token`, `api_keys.key`. A unique index there is correct design.
- `trigger-visibility` fails on a textbook **append-only audit trigger**
  (AFTER INSERT, writes to an RLS-locked table, `RETURN NULL`).
- `identity-trust` fires on the **canonical correct Supabase tenant table**.
- `role-capabilities` fails on `auth.users` access decided from
  `has_table_privilege` alone.
- `migration-collisions`' only build-failing condition fires on correct
  migrations when the later file of a same-prefix pair references the earlier.
- `migration-collisions` scans dollar-quoted plpgsql bodies as if they were
  top-level SQL.
- `migration-collisions` orders tied prefixes with ICU collation
  (`localeCompare`) instead of Postgres' code-unit ordering.
- `column-exposure` `classifyColumn` matches any column whose name merely
  *starts* with a sensitive token.
- `pooler-bleed` scans raw file text without stripping comments.
- `mfa-enforcement` never compares policy **roles** when deciding whether
  another permissive policy grants the same rows.
- `constraint-oracles`' unguessable-type exemption is gated on
  `columns.length === 1`, so an all-uuid composite UNIQUE is reported.

---

## C. Fix text that breaks the app

*Applied literally, the remediation takes something down.* Same class as the
`view-isolation` `security_invoker` fix corrected in 0.38.0.

**Open (9):**

- `shadow-tables`' fix makes every INSERT into the **protected source table**
  fail with 42501.
- `storage-isolation` / `realtime-isolation` print `CREATE POLICY …` with no
  `ENABLE ROW LEVEL SECURITY`, so applied verbatim the policy does nothing.
- `schema-tenancy` hands out a point-in-time `GRANT … ON ALL TABLES IN SCHEMA`,
  so the per-tenant role it tells you to create silently misses later tables.
- `schema-tenancy` revokes only from the role it told you to create one line
  earlier.
- `cross-tenant-fk`'s replacement FK is emitted **with no referential action**,
  so applying it silently drops `ON DELETE CASCADE`.
- `trigger-visibility` emits `ALTER FUNCTION <table_schema>.<function>()` —
  the function's schema is never selected, so the statement names the wrong one.
- `column-exposure`'s "expose only the public part" recipe revokes the base-table
  SELECT and then hands out something that cannot work.
- `pooler-bleed`'s leading branch (flip `set_config`'s third argument to `true`)
  needs an explicit transaction, and only the `SET LOCAL` branch says so.
- `role-capabilities` claims `urlencode` is an egress function.

---

## D. Fix text that silently does nothing

*The user applies it, nothing changes, the guard keeps failing.*

**Fixed in 0.38.0** — `anon-writes` `REVOKE … FROM anon` against a PUBLIC grant;
`ALTER DEFAULT PRIVILEGES` with no `FOR ROLE`; `rls-proof` "add a FOR ALL policy".

**Open (7):** `column-exposure` REVOKE against a PUBLIC-sourced grant;
`role-capabilities` REVOKE without PUBLIC; `role-capabilities` transitive
privileges via role membership; `create-grants` REVOKE against inherited CREATE;
`constraint-oracles` `ALTER TABLE … DROP CONSTRAINT` for an index with no backing
`pg_constraint`; `constraint-oracles` enumerating from `pg_index` but always
emitting the constraint form; `mfa-enforcement` templating the fix from the
config role instead of the offending policy's.

---

## E. Emitted SQL that will not run

**Fixed in 0.38.0** — `rls-proof`'s policy against a `uuid` tenant column (42883).

**Open (5):** `shadow-tables` ×2 (no cast, one-argument `current_setting`);
`identity-trust` `USER_METADATA_FIX` (one string used as both column name and
claim key, no cast); `storage-isolation` / `realtime-isolation` hardcoding a path
separator instead of using the configured one.

The fix already exists — `tenantComparison()` in `rls-proof.mjs`, added in
0.38.0. These are call sites that have not adopted it.

---

## F. Parsing: comments and quoted bodies

Both directions, which is what makes it worth doing once properly.

- `pooler-bleed`: a comment reading *"our pgbouncer does NOT issue DISCARD ALL"*
  **globally downgrades the guard's only build-failing verdict to a note.** One
  boolean, ORed across every scanned file. This one is close to P0.
- `shadow-tables`: a table named only inside a comment is treated as a write
  target.
- `trigger-visibility`: `tablesRead()` matches anywhere in `prosrc`, so a trigger
  that performs no read is reported.
- `migration-collisions`: dollar-quoted bodies scanned as top-level SQL.
- Plus 2 smaller ones.

---

## G. Probe coverage gaps

Real leaks inside each guard's own stated scope. Highest first:

- `pooler-bleed` skips entirely — with the affirmative message *"no policy
  authorizes from a custom GUC — nothing that can outlive a request"* — when the
  policy reads its GUC **through a helper function**. Reproduced live.
- `constraint-oracles` is blind to a unique index on an expression, and to one
  other constraint shape that is exactly the oracle it exists to catch.
- `cross-tenant-fk` drops **every self-referencing FK**, so `parent_id` →
  same-table `ON DELETE CASCADE` is never examined.
- `shadow-tables` returns 'safe' for any RLS-enabled destination.
- `shadow-tables`' `writeTargets()` only matches `UPDATE <table> SET`, missing
  `UPDATE <table> <alias> SET`.
- `identity-trust` reads authority-table write access with `has_table_privilege`
  (the column-grant blind spot fixed elsewhere in 0.37.0).
- `mfa-enforcement`'s `referencesAal` misses a gate written through an
  aal-named helper.
- `route-org-scoping` searches the tenant signal anywhere in the statement, so
  naming the tenant column in the SELECT list satisfies it.
- Plus 6 more.

---

## H. Privilege resolution

`has_table_privilege` and friends do not answer the question the guards are
asking. Partly fixed in 0.37.0 (column grants in `anon-reads` / `anon-writes`);
8 call sites remain, overlapping clusters D and G.

---

## I. Shared-helper drift

- "Which column is the tenant" exists in **three copies**, and only
  `constraint-oracles` orders by config priority.
- `cross-tenant-fk` and `default-privileges` are the only two guard files with
  no `pg_catalog` schema qualification.
- Plus 4 smaller divergences.

Worth one consolidation pass rather than six patches.

---

## J. Cosmetic, perf, packaging

12 items: N+1 query patterns, the ~300s test suite, `bin/tenant-guard.mjs`
listing drift, `package.json` / `CHANGELOG.md` inconsistencies, stale doc
comments. Real, low consequence.

---

## Suggested order

1. **Finish A** (4). Never assert what was not tested.
2. **B, starting with `route-org-scoping`** — it is the one complaint a real
   user has now made twice.
3. **F's `pooler-bleed` comment bug** — a comment disabling a guard belongs with
   the P0s despite sitting in a P2 cluster.
4. **C and D together**, per guard: both are "what happens when someone applies
   this", and the same guards recur in both.
5. **E** by adopting `tenantComparison()` at the remaining call sites.
6. **G**, largest first.
7. **H and I** as one consolidation pass.
8. **J** last, or never.

## Method note

Both rounds were run the same way: fan out over guards, have each agent build the
scenario against embedded Postgres, then have a second agent try to **refute**
each finding. The refutation stage is not optional — it rejected 19 of 126
verified claims, including one where the guard was behaving correctly and the
"fix" would have introduced a mass false positive. Anything reported here without
a reproduction should be re-verified before it is acted on.
