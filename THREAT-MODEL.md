# Threat model — how multi-tenant isolation actually breaks

This is the map tenant-guard is built against: an enumeration of the ways tenant
isolation fails in Postgres/Supabase, each tagged with whether tenant-guard covers
it **today**, whether it is *coverable at all* by this tool's method, and where it
is deliberately out of scope.

It exists because a security tool that grows one reported bug at a time is always
one reviewer behind. Community feedback has been excellent — several checks here
came from it, and they're credited in [`CHANGELOG.md`](CHANGELOG.md) — but the
coverage target is *the whole failure surface*, derived up front, not the subset
someone happened to hit.

**Legend**
- ✅ **covered** — a guard proves or flags this today
- 🟡 **partial** — detected in the common case; a named limitation remains
- 🔜 **planned** — coverable by this method, not built yet
- ⛔ **out of scope** — *not* provable by "run SQL as the app role"; needs a
  different instrument. Listed anyway, because a security tool that hides its
  blind spots is worse than one that names them.

---

## 0. The method, and what it can and cannot see

tenant-guard's runtime guards work one way: **connect privileged, seed or find two
tenants, drop to your real app role, and run real SQL inside a transaction that is
rolled back.** Everything below is judged against that.

Two consequences worth stating plainly:

1. **It proves the database boundary (RLS), not the application boundary.** A
   server route that uses a service-role/admin connection and forgets
   `.eq('organization_id', …)` is a real cross-tenant bug that the database will
   happily serve — correctly, because that role is *meant* to bypass RLS. No
   SQL-as-role probe can see it. That class is covered statically by
   `route-org-scoping`, and imperfectly (it's a heuristic on source text).
2. **A probe you can't falsify is worthless.** Every runtime guard first asserts
   its own identity is actually subject to RLS (§1); if it isn't, the run **fails**
   rather than reporting a vacuous pass.

---

## 1. Identity & probe integrity — "is this test even valid?"

If the probing role isn't subject to RLS, every "isolated" result is meaningless.
These are checked *before* any isolation claim.

| # | Failure | Status | How |
|---|---|---|---|
| 1.1 | Probe role is a **superuser** | ✅ | deny-all canary: role must NOT read it → abort the run |
| 1.2 | Probe role has **BYPASSRLS** (e.g. `service_role`) | ✅ | same canary → abort |
| 1.3 | Probe role in **`pg_read_all_data`** | ✅ | same canary → abort |
| 1.4 | `SET ROLE` silently didn't take effect | ✅ | same canary → abort |
| 1.5 | Probe role **owns the table**, `FORCE ROW LEVEL SECURITY` off → owner bypasses RLS *for that table only* | ✅ | per-table owner check; the canary **cannot** catch this (it isn't owned by the app role), so it's checked from `pg_class.relowner`/`relforcerowsecurity` and reported as **not proven** with the exact `ALTER TABLE … FORCE ROW LEVEL SECURITY` fix |
| 1.6 | RLS on, **zero policies** → deny-all that *looks* isolated | ✅ | reported as `no policy`, never as a pass |
| 1.7 | Table sees none of its own rows (misconfigured `becomeTenant`/claim) | ✅ | reported as `over-restrictive` — "not proven", never a pass |
| 1.8 | Claim GUC set in a shape the app's `auth.uid()` doesn't read | 🟡 | surfaces as 1.7 (not a false pass), but the diagnosis could name the mismatch explicitly |

## 2. Read path

| # | Failure | Status | How |
|---|---|---|---|
| 2.1 | RLS never enabled on a tenant table | ✅ | `rls-proof` (cross-tenant read) + `anon-reads` (structural: RLS off + grant) |
| 2.2 | `USING (true)` / predicate omits the tenant | ✅ | `rls-proof` cross-tenant read |
| 2.3 | Any logged-in user reads another tenant (`authenticated` leak) | ✅ | `rls-proof` — the core probe |
| 2.4 | **`anon` can read tenant data** (CVE-2025-48757 class) | ✅ | `anon-reads`, probed as `anon` |
| 2.5 | Safe idiom `TO public USING (auth.uid() = …)` **false-flagged** | ✅ | probed, not guessed → proven safe (0 rows as anon). A catalog-only linter cries wolf here |
| 2.6 | RLS enabled early, **disabled/policy dropped later** | ✅ | runtime reflects live state; `rls-drift` also flags catalog-vs-migrations divergence |
| 2.7 | A second **permissive** policy widens access (policies OR together) | ✅ | behavioural — the leak shows up in the probe regardless of which policy caused it |
| 2.8 | Policy trusts a **client-settable GUC** (`current_setting('app.tenant')`) — the client just sets it | 🔜 | probe: as tenant A, `SET` the GUC to tenant B and re-read. High value, small build |
| 2.9 | Policy trusts a **user-writable JWT claim** (`user_metadata`) rather than `app_metadata` | 🔜 | probe: forge the claim in `becomeTenant`, re-read |
| 2.10 | Policy subquery reads a **user-writable membership table** → self-grant into another tenant | 🔜 | two-step probe: insert own membership row for tenant B, then re-read B |
| 2.11 | Existence oracles: global `UNIQUE` key, single-column FK, `ON CONFLICT DO NOTHING` reveal another tenant's hidden rows | 🔜 | probe returns `23505`/FK error where a row is invisible → enumeration leak |
| 2.12 | `pg_stat_activity` exposes other tenants' live query text (all users share one DB role) | 🔜 | read it as the app role |
| 2.13 | Planner/statistics side channels (`pg_stats`, non-`LEAKPROOF` functions) | ⛔ | needs adversarial query construction; low yield, high noise |

## 3. Write path

RLS is **per-command**, and `USING` (which rows you may touch) is separate from
`WITH CHECK` (what the row may become). Most write leaks live in that gap.

| # | Failure | Status | How |
|---|---|---|---|
| 3.1 | `UPDATE`/`DELETE` another tenant's rows while reads look correct | ✅ | whole-table probes, affected-count compared (a `WHERE` would be masked by a correct SELECT policy) |
| 3.2 | **Tenant-hop** — move your own row *into* another tenant (`SET org = <other>`) | ✅ | explicit move probe; `USING` passes, missing `WITH CHECK` doesn't stop it |
| 3.3 | **`INSERT`** a row belonging to another tenant | ✅ | insert probe; no `RETURNING` (it re-applies the SELECT policy and masks the leak), landing read from the row-count delta |
| 3.4 | **Omitted tenant** — `INSERT` with tenant `NULL` → a row nobody owns that everybody reads | ✅ | null-tenant probe + read-back |
| 3.5 | `anon` can INSERT/UPDATE/DELETE (cache poisoning) | ✅ | `anon-writes` (hybrid catalog + probe) |
| 3.6 | Tenant column has a `DEFAULT` but no `WITH CHECK` — the default is overridable | ✅ | 3.3 catches it (explicit foreign tenant on insert) |
| 3.7 | **UPSERT** (`ON CONFLICT DO UPDATE`) — the conflict path needs the *UPDATE* policy; an INSERT-only policy set lets it update another tenant's row | 🔜 | probe an upsert colliding with tenant B's key |
| 3.8 | Self-row `UPDATE` lets a user set their own `role`/`org_id` → escalation | 🔜 | probe updating an authorization column on your own row |
| 3.9 | **`TRUNCATE` ignores RLS entirely** — gated only by table privilege (`GRANT ALL` includes it) | 🔜 | probe `TRUNCATE` in a savepoint; success = cross-tenant destruction capability |
| 3.10 | `MERGE` (PG15+) per-arm policy gaps | 🔜 | exercise each arm |
| 3.11 | Cross-tenant FK reference / cascade reaching another tenant's rows | 🔜 | insert a child pointing at tenant B's parent |
| 3.12 | `anon` INSERT-only surface under RLS | 🟡 | `anon-writes` probes UPDATE/DELETE; pure-INSERT anon surfaces not probed yet |

## 4. Objects that aren't base tables

The highest-severity blind spot of any table-only scanner.

| # | Failure | Status | How |
|---|---|---|---|
| 4.1 | **View without `security_invoker`** — runs as its owner, so base-table RLS is evaluated as the owner and returns every tenant | ✅ | `view-isolation` probes every tenant-column view as the app role; the catalog (owner, `security_invoker`, kind) is used only to explain *why* and pick the right fix |
| 4.2 | **Materialized view** — RLS *never* applies; it's an RLS-free snapshot of every tenant | ✅ | `view-isolation` (cross-tenant) and `anon-reads` (unauthenticated). The fix text never suggests `security_invoker` here — no policy can scope a matview |
| 4.3 | `SECURITY DEFINER` **function** that doesn't re-filter by tenant, or trusts a tenant argument | 🟡 | `definer-grants` flags mutating definer functions not revoked from `PUBLIC`/`anon` (static). Calling them to prove a data leak is 🔜 — and gated, since an unknown definer body can have side effects a rollback won't undo |
| 4.4 | Definer function with **mutable `search_path`** → object-shadowing escalation | 🔜 | catalog: `prosecdef` + no pinned `search_path`, plus `CREATE` on `public` |
| 4.5 | Definer **helper used inside a policy** (the recursion-avoidance idiom) inherits any flaw | 🔜 | shows up behaviourally once 4.1/4.3 probes exist |
| 4.6 | View/function over `auth.users` exposing every tenant's email | 🟡 | a *view* over `auth.users` is covered by 4.1 **if it exposes a tenant column**; one keyed only by user id isn't yet |
| 4.7 | **Partitions**: RLS on the parent, but a partition queried directly uses *its own* (often unset) RLS; newly attached partitions miss `ENABLE`/`FORCE` | 🔜 | enumerate `pg_inherits`, probe each partition directly |
| 4.8 | Legacy `INHERITS` children don't inherit parent policies | 🔜 | same enumeration |
| 4.9 | Triggers/rules writing tenant rows into an un-RLS'd audit/outbox table | 🟡 | the audit table is itself scanned *if* it has a tenant column; without one it's invisible → 🔜 |

## 5. Supabase surfaces

| # | Failure | Status | How |
|---|---|---|---|
| 5.1 | `storage.objects` — tenancy lives in the **object path** or `owner`, not a column | 🔜 | the metadata table *is* RLS-guarded and probeable; needs tenant-**expression** support (path segment), not just a tenant column. Named as an honest limit in the README today |
| 5.2 | `storage.buckets.public = true` — CDN serves objects with no auth and no RLS | 🟡→🔜 | the flag is a catalog read; the actual public GET is HTTP behaviour, outside SQL |
| 5.3 | Realtime `postgres_changes` streams rows to subscribers | 🟡 | delivery is gated by the **SELECT policy**, which §2 already proves; naming it explicitly (publication membership + permissive policy) is 🔜 |
| 5.4 | Realtime broadcast/presence authorization (`realtime.messages` RLS) | 🔜 | it's an RLS-guarded table — same probe shape |
| 5.5 | Tables exposed in **non-`public` schemas** (PostgREST `db-schemas`) | 🟡 | `schemas` is configurable, but defaults to `public` — a `public`-only run under-reports |
| 5.6 | `service_role` key shipped to the client | ⛔ | not a database fact — needs a bundle/env/git secret scan |
| 5.7 | JWT secret weak/leaked → forged `role: service_role` | ⛔ | key management, not RLS |

## 6. Connection pooling & session state

| # | Failure | Status | How |
|---|---|---|---|
| 6.1 | Tenant GUC set with session `SET` (not `SET LOCAL`) **bleeds to the next request** on a transaction-mode pooler — the next tenant inherits the previous tenant's identity | ⛔ runtime / 🔜 static | structurally invisible to a single-connection probe: it is an *inter-transaction* property of the app's pooled connections. Detectable statically (RLS keyed on a custom `app.*` GUC + app code using bare `SET`/`set_config(…, false)`), and partially via a two-transaction persistence check |
| 6.2 | Other session state (temp tables, `SET ROLE` not reset, prepared plans) bleeding across pooled clients | ⛔ | same reason |

## 7. Privileges & grants

| # | Failure | Status | How |
|---|---|---|---|
| 7.1 | Over-broad `GRANT ALL` / `TO PUBLIC` amplifying any RLS gap | 🟡 | the *effect* is proven by the probes; the grant itself is a catalog read (and `GRANT ALL` is what makes 3.9 possible) |
| 7.2 | `ALTER DEFAULT PRIVILEGES` auto-granting every *future* table | 🔜 | catalog: `pg_default_acl` |
| 7.3 | `CREATE` on `public` granted to `anon`/`authenticated` (feeds 4.4) | 🔜 | catalog or probe |
| 7.4 | Mutating `SECURITY DEFINER` function not revoked from `PUBLIC`/`anon` | ✅ | `definer-grants`, judged on the **net state** of migration history |

## 8. Structurally out of scope (documented so the coverage claim stays honest)

These are real ways tenants leak that this tool's method **cannot** prove. They are
listed so nobody reads a green run as more than it is.

- **App-layer IDOR with an admin/service-role connection** — the DB answers
  correctly; the missing tenant filter is in application code. (`route-org-scoping`
  catches the common shape statically.)
- **Secrets in the client bundle** (service-role key, JWT secret).
- **Public storage buckets served over CDN** (HTTP behaviour, not an RLS decision).
- **Pooler session-state bleed** (§6) — an inter-connection property.
- **Backups, `pg_dump`, logical replication** — run as owner/superuser by design.
- Anything reachable only through a web app's own auth logic.

---

## What this means for the roadmap

Ordered by (severity × prevalence in real AI-generated apps) ÷ build cost, the
next builds are: **2.8/2.9 (forgeable identity — a policy trusting a client-settable
GUC or a user-writable `user_metadata` claim)**; **3.7/3.9 (upsert conflict path,
`TRUNCATE`)**; then **4.7 (partitions queried directly)** and **5.1 (storage object
paths)**.

*Done: 4.1/4.2 (views & materialized views) shipped in 0.9.0 — they were the
highest-severity open item and invisible to every table-only checker.*

If you know a failure mode that isn't in this table, that's the most useful bug
report this project can get — open an issue.
