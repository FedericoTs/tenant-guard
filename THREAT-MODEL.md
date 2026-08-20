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
| 2.8 | Policy trusts a **client-settable GUC** (`current_setting('app.tenant')`) — the client just sets it | 🟡 | `identity-trust`. The *concrete* form is a hard failure: a callable `SECURITY DEFINER` function that sets that GUC from an **argument** (a "become any tenant" primitive). Bare dependence on a settable GUC is a **note, never a build failure** — whether it is exploitable depends on architecture SQL cannot see, and it is also how this tool impersonates. That note is **upgraded to a failure by `pooler-bleed` (§6.1)** when the source is found writing the same GUC with connection scope |
| 2.9 | Policy trusts a **user-writable JWT claim** (`user_metadata`) rather than `app_metadata` | ✅ | `identity-trust` detects it in the policy text (conclusive on its own) and then **proves** it: forge `user_metadata.<key>` as the victim and re-read. A control arm forging a nonexistent tenant keeps an already-open table from being blamed on the claim |
| 2.10 | Policy subquery reads a **user-writable membership table** → self-grant into another tenant | ✅ | `identity-trust`. Dependencies come from `pg_depend` (exact, not a regex over policy text). Fails when the authority table has RLS off with a write grant, or an INSERT/UPDATE policy whose check never constrains its **tenant column** — the `WITH CHECK (user_id = auth.uid())` near-miss that pins WHO you are and leaves WHICH TENANT open. No tenant column on the authority table → a note, never a silent pass |
| 2.11 | Existence oracles: global `UNIQUE` key, single-column FK, `ON CONFLICT DO NOTHING` reveal another tenant's hidden rows | ✅ | `constraint-oracles`, catalog-only. **UNIQUE omitting the tenant column → fails** (conclusive: the constraint either carries the tenant or it doesn't). Skips primary keys and single-UUID columns — unguessable values answer nothing. Expression indexes are skipped rather than guessed at. **Single-column FKs between tenant tables → an aggregated note**, since composite tenant FKs are rare and exploiting one needs a guessable parent id *and* an insert that passes `WITH CHECK` |
| 2.12 | `pg_stat_activity` exposes other tenants' live query text (all users share one DB role) | 🔜 | read it as the app role |
| 2.13 | Planner/statistics side channels (`pg_stats`, non-`LEAKPROOF` functions) | ⛔ | needs adversarial query construction; low yield, high noise |
| 2.14 | **Schema-per-tenant**: one role reaches more than one tenant schema | ✅ | `schema-tenancy`. A different architecture entirely — the boundary is GRANTs, not policies, and `search_path` is not a control. Was a verified blind spot: `rls-proof` reported "1/1 proven isolated" on a database where the app role read both tenant schemas |

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
| 3.8 | Self-row `UPDATE` lets a user set their own `role`/`org_id` → escalation | ✅ | `identity-trust`. **RLS is row-level and cannot restrict columns**, so the textbook-correct `USING (id = auth.uid()) WITH CHECK (id = auth.uid())` still lets you rewrite every field of your own row. Read from `has_column_privilege` per column — the only real control is a column-level GRANT, which is also the fix given. Scoped to columns a dependent policy actually reads, plus tenant columns (re-parenting) |
| 3.9 | **`TRUNCATE` ignores RLS entirely** — gated only by table privilege (`GRANT ALL` includes it) | 🟡 | `rls-proof` reads the privilege from the catalog and reports one aggregated **note**. Deliberately **not probed**: `TRUNCATE` takes an `ACCESS EXCLUSIVE` lock and is the one statement you must not fire at a database by surprise. Latent (PostgREST exposes no TRUNCATE) rather than directly exploitable, so it is not a build failure |
| 3.10 | `MERGE` (PG15+) per-arm policy gaps | 🔜 | exercise each arm |
| 3.11 | Cross-tenant FK reference / cascade reaching another tenant's rows | 🔜 | insert a child pointing at tenant B's parent |
| 3.12 | `anon` INSERT-only surface under RLS | 🟡 | `anon-writes` probes UPDATE/DELETE; pure-INSERT anon surfaces not probed yet |

## 4. Objects that aren't base tables

The highest-severity blind spot of any table-only scanner.

| # | Failure | Status | How |
|---|---|---|---|
| 4.1 | **View without `security_invoker`** — runs as its owner, so base-table RLS is evaluated as the owner and returns every tenant | ✅ | `view-isolation` probes every tenant-column view as the app role; the catalog (owner, `security_invoker`, kind) is used only to explain *why* and pick the right fix |
| 4.2 | **Materialized view** — RLS *never* applies; it's an RLS-free snapshot of every tenant | ✅ | `view-isolation` (cross-tenant) and `anon-reads` (unauthenticated). The fix text never suggests `security_invoker` here — no policy can scope a matview |
| 4.3 | `SECURITY DEFINER` **function** that doesn't re-filter by tenant, or trusts a tenant argument | ✅ | `definer-rpc` **calls them and measures the leak**. The safety objection that kept this unbuilt has a catalog answer: Postgres enforces that a non-`VOLATILE` function cannot write (*"INSERT is not allowed in a non-volatile function"*), so `STABLE`/`IMMUTABLE` definer functions are safe to invoke and are probed; `VOLATILE` ones are **never called** and are reported from their body as an explicitly-unproven note. Zero-arg and single-tenant-arg functions are probed; anything else is skipped rather than guessed at. `definer-grants` still covers the static grant side |
| 4.4 | Definer function with **mutable `search_path`** → object-shadowing escalation | ✅ | `definer-rpc`. **Fails only when the precondition holds** — the app role must be able to CREATE somewhere to plant a shadowing object; without that it is a note, because you cannot exploit what you cannot create |
| 4.10 | **SQL injection inside a `SECURITY DEFINER` function** — dynamic SQL built by concatenating a caller-supplied parameter | ✅ | `definer-rpc`, from the body (so it works on `VOLATILE` functions the probe cannot call). Injected SQL executes as the function's **owner**, so it bypasses RLS wholesale — a verified example returns every tenant's rows through a table whose policy is perfect. Narrow by design: `||`-concatenation and `format()`'s `%s` are flagged; `USING`, `quote_literal`, `quote_ident`, `%L` and `%I` are not, and anything it cannot read confidently produces no finding |
| 4.5 | Definer **helper used inside a policy** (the recursion-avoidance idiom) inherits any flaw | ✅ | shows up behaviourally: the helper is a definer function (4.3) *and* the policy that calls it is proven by `rls-proof`, so a flaw surfaces from either side |
| 4.6 | View/function over `auth.users` exposing every tenant's email | 🟡 | a *view* over `auth.users` is covered by 4.1 **if it exposes a tenant column**; one keyed only by user id isn't yet |
| 4.7 | **Partitions**: RLS on the parent, but a partition queried directly uses *its own* (often unset) RLS; newly attached partitions miss `ENABLE`/`FORCE` | ✅ | `rls-proof`. This was a **false negative in the flagship guard**: partitioned parents are `relkind='p'` (previously skipped entirely) and every partition holds exactly one tenant by construction, so the two-tenant probe never fired and a leaking database reported green. Fixed by scanning parents and adding a **foreign-tenant probe** |
| 4.8 | Legacy `INHERITS` children don't inherit parent policies | 🔜 | same enumeration |
| 4.9 | Triggers/rules writing tenant rows into an un-RLS'd audit/outbox table | ✅ | `shadow-tables` follows triggers on tenant tables to their write targets. Detection reads the function **body**, because plpgsql records no `pg_depend` for what it writes — so a dynamically-assembled target isn't followed, and unresolvable ones are listed rather than dropped |

## 5. Supabase surfaces

| # | Failure | Status | How |
|---|---|---|---|
| 5.1 | `storage.objects` — tenancy lives in the **object path** or `owner`, not a column | ✅ | `storage-isolation`. Tenant-**expression** support (`split_part(name,'/',N)` — deliberately not Supabase's `storage.foldername()`, so the same SQL runs on vanilla Postgres). Probes cross-tenant reads AND the **upload path-hop**: the client picks the object name on upload, so an unpinned INSERT policy lets a user write into another tenant's folder. The upload probe has a control arm — it first uploads into its OWN folder, so a refusal elsewhere is never miscredited to tenant scoping |
| 5.2 | `storage.buckets.public = true` — CDN serves objects with no auth and no RLS | ✅ | `storage-isolation` fails a public bucket that holds objects under **two or more tenant folders**. The flag is a catalog read and the message says so — the public GET is HTTP behaviour in the Storage service, so it is reported as a catalog fact, not claimed as probed. A single-folder public bucket (logos, assets) is not flagged |
| 5.3 | Realtime `postgres_changes` streams rows to subscribers | ✅ | delivery is gated by the **SELECT policy**, which §2 already proves — so `realtime-isolation` does not re-litigate it and instead **names which tenant tables are actually in the `supabase_realtime` publication** (and which of those have RLS off). On a streaming table a permissive policy is a live firehose rather than one request at a time, and people rarely know the list |
| 5.4 | Realtime broadcast/presence authorization (`realtime.messages` RLS) | ✅ | `realtime-isolation`. The tenant lives in the **topic** (`org_A:notifications`), so it uses a tenant expression like storage: `split_part(topic, ':', 1)` — which also covers a bare `org_A` topic, since split_part returns the whole string when the separator is absent. Probes cross-tenant channel reads AND **publishing into another tenant's channel** (joining is a write), with the same control arm as storage |
| 5.5 | Tables exposed in **non-`public` schemas** (PostgREST `db-schemas`) | 🟡 | `schemas` is configurable, but defaults to `public` — a `public`-only run under-reports |
| 5.6 | `service_role` key shipped to the client | ⛔ | not a database fact — needs a bundle/env/git secret scan |
| 5.7 | JWT secret weak/leaked → forged `role: service_role` | ⛔ | key management, not RLS |

## 6. Connection pooling & session state

| # | Failure | Status | How |
|---|---|---|---|
| 6.1 | Tenant GUC set with session `SET` (not `SET LOCAL`) **bleeds to the next request** on a transaction-mode pooler — the next tenant inherits the previous tenant's identity | ✅ | `pooler-bleed`, the only guard that reads **both halves of the repository**, which is exactly why it went uncovered: the *database* says which custom GUCs your policies authorize from, the *source* says whether you write them with `is_local = false` or a bare `SET`. Either half alone is a note (that is §2.8); together the finding is conclusive and names the policy and the line. **Verified**: with a session-scoped write, a later request that sets *nothing* reads the previous tenant's rows through a policy working exactly as written — and `rls-proof` calls that same database fully isolated. The inter-connection property itself is still not probed (that would need the app's own pooler and its own concurrency); what *is* probed is the mechanism — a session-scoped setting survives into later transactions while a transaction-scoped one does not, the second being the control arm. `DISCARD ALL` on release is detected and downgrades the finding |
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

Every failure mode above that is **both** coverable by this tool's method **and**
worth the noise it would add now has a guard behind it. Seven rows are still
🔜, and they are listed here rather than summarised away, ordered by
(severity × prevalence) ÷ build cost:

| # | Why it hasn't been built |
|---|---|
| 7.2 `ALTER DEFAULT PRIVILEGES` | The best of the remaining set — a **time bomb**: today's green becomes tomorrow's leak when the next table auto-inherits the grant. Catalog read of `pg_default_acl`; cheap |
| 3.11 cross-tenant FK / cascade | Real, moderate cost: insert a child pointing at another tenant's parent and see whether the reference is allowed |
| 7.3 `CREATE` on `public` granted to `anon`/`authenticated` | Already checked *as a precondition* inside `definer-rpc` (§4.4); standalone it is a small catalog read |
| 3.10 `MERGE` per-arm policies | PG15+, and rare in the app shapes this targets |
| 4.8 legacy `INHERITS` children | Same enumeration as partitions, far rarer |
| 3.7 UPSERT conflict path | Its permissive-`UPDATE`-policy case is already caught by the existing write probes, so a dedicated check would mostly re-report an existing finding |
| 2.12 `pg_stat_activity` query text | Small; worth doing when someone hits it |

Also open, and smaller: **1.8** (naming a claim-shape mismatch explicitly rather
than surfacing it as 1.7) and **5.5** (a `public`-only run under-reports when
PostgREST exposes other schemas).

Everything marked ⛔ is out of scope **by construction** — leaked service keys,
pooler session-state bleed *at runtime* (§6.2), app-layer IDOR through a
service-role connection. Those need a different instrument, and they stay listed
rather than quietly dropped, because the honest statement of what a tool cannot
see is part of what makes the rest of it trustworthy.

The most useful contribution now is a failure mode that **isn't in this table at
all**. If you know one, that's the best bug report this project can get.

*Done: 4.1/4.2 views & materialized views (0.9.0); 2.9 user-writable claims, 2.8
callable GUC-setting definer functions, 4.7 partitions, 3.9 TRUNCATE (0.10.0);
2.10 user-writable policy authority (0.11.0); 3.8 self-row escalation (0.12.0);
5.1/5.2 storage paths + public buckets (0.13.0); 2.11 constraint oracles (0.14.0);
5.3/5.4 Realtime channels (0.15.0); 4.3/4.4/4.10 definer RPCs and SQL injection
inside them (0.16.0–0.17.0); 4.9 shadow tables, 7.1 role capabilities (0.18.0);
2.14 schema-per-tenant (0.19.0); 6.1 session-scoped tenant GUCs (0.21.0).*

*Three of these are worth learning from. **4.7** was a false NEGATIVE in the
flagship guard, found by writing the failure surface down rather than by waiting
for a bug report. **2.10 and 3.8** are the pair where the policy is correct and
the thing it TRUSTS is writable, which no amount of per-policy review would
surface. And **6.1** is the one no single-request test can see at all: run one
request and isolation is perfect — the leak exists only between requests, which
is why it needed the database and the source read together.*

If you know a failure mode that isn't in this table, that's the most useful bug
report this project can get — open an issue.
