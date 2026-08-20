# Changelog

## 0.17.0

Still in 4.3's neighbourhood, and the answer to "should this do SQL-injection
checks too?" — which is **yes, for exactly one shape, and no for the rest**.

- **feat(definer-rpc): SQL injection inside a `SECURITY DEFINER` function.**
  Generic injection scanning belongs in semgrep/CodeQL, and bolting it on here
  would produce precisely the alert fatigue this project argues against. But in
  *this* shape injection isn't a generic bug — it is a **tenant-isolation
  failure**, because the injected SQL executes as the function's **owner** and so
  bypasses RLS wholesale. Verified before building: a table with a flawless policy
  returns 1 row to its tenant, while `search_notes` with a payload of
  `%' or true --` returns every tenant's rows. Both existing guards reported green.
  - Read from the **body**, so unlike the call-probe it also covers `VOLATILE`
    functions — which matters, because plpgsql defaults to VOLATILE and that is
    exactly where dynamic SQL lives.
  - Deliberately narrow, so a finding is never a guess: `||`-concatenation of a
    parameter into `EXECUTE`, and `format()`'s **`%s`** (which escapes nothing).
    `EXECUTE … USING`, `quote_literal`, `quote_ident`, `%L` and `%I` are correct
    and produce nothing. Anything it cannot read confidently produces nothing
    either — silence beats a guess.
- **feat(definer-rpc): unpinned `search_path` (threat-model 4.4).** Unqualified
  names inside a definer function resolve through the **caller's** `search_path`,
  so a caller who can create objects can make the function operate on theirs —
  executing as the owner. Fails **only when that precondition holds**: the role
  must hold `CREATE` somewhere to plant the shadowing object. Otherwise it is a
  note, because you cannot exploit what you cannot create.
- Threat model **4.4 covered**, and **4.10 added** — the first row the map gained
  from someone asking a question it had no entry for.
- 303 tests (was 292).

## 0.16.0

A Reddit reviewer asked for "RPCs where SECURITY DEFINER + grants can quietly
undermine otherwise-correct RLS". Checking rather than assuming turned up a real
**false negative**, and a catalog fact that unblocked the check that had been
parked as too dangerous to build.

- **feat: new guard `definer-rpc`** (`tenant-guard rpc`). A `SECURITY DEFINER`
  function runs as its **owner**, so it bypasses RLS on everything it touches, and
  PostgREST exposes it at `/rest/v1/rpc/<name>`. This:

      create function get_invoices(org text) returns setof invoices
        language sql security definer stable
        as $$ select * from invoices where organization_id = org $$;
      grant execute on function get_invoices(text) to authenticated;

  hands out every tenant's invoices while `invoices` itself has flawless RLS —
  and before this release **every guard here reported green on it**. There is a
  test asserting exactly that: `rls-proof` passes while `definer-rpc` fails, on
  the same database.
- **The safety objection had a catalog answer.** Calling an arbitrary definer
  function is genuinely unsafe — an unknown body can commit autonomously and
  outlive the rollback that makes every other guard harmless, which is why the
  threat model had this parked as "gated". But Postgres *enforces* that a
  non-`VOLATILE` function cannot write (*"INSERT is not allowed in a non-volatile
  function"*). So `STABLE`/`IMMUTABLE` definer functions are **called and
  measured**, and `VOLATILE` ones are **never invoked** — reported from a read of
  their body, as a note that says plainly it is not proven and why.
- Distinguishes **trusts-argument** (called with another tenant's id, returned
  their rows) from **no-filter** (returns rows even for a tenant id that cannot
  exist) using a control arm, because the fix differs. Probes zero-arg and
  single-tenant-arg functions; anything else is skipped rather than guessed at,
  and says so.
- Threat model **4.3 and 4.5 → covered**.
- 292 tests (was 270), 13 guards.

## 0.15.0

**The map is closed.** Threat-model 5.4 was the last planned item; everything
still open is out of scope by construction and says so.

- **feat: new guard `realtime-isolation`** (`tenant-guard realtime`). Realtime is a
  second way out of the database, and easy to forget once the REST surface looks
  locked down.
  - **Broadcast and Presence authorize channels through RLS on
    `realtime.messages`.** With no policy there, any client joins any tenant's
    channel: reads every payload flowing through it and — because joining is a
    write — **publishes into it**. Injecting fabricated events into another
    tenant's live channel is the realtime analogue of writing into their storage
    folder, and a correct read policy does not prevent it.
  - The tenant lives in the **topic**, not a column, so it uses a tenant
    expression like storage: `split_part(topic, ':', 1)`. That one expression
    covers both conventions — with no separator present `split_part` returns the
    whole topic, so a bare `org_A` channel resolves correctly too.
  - Same control arm as the storage upload probe: it publishes into its **own**
    channel first, so a refusal elsewhere is never miscredited to tenant scoping.
  - RLS on with **no policy** is reported as a note, not a leak — broadcast is
    switched off rather than secured, which is almost certainly unintended but is
    not a leak.
  - For **`postgres_changes`** (5.3) it deliberately does *not* re-litigate the
    SELECT policy `rls-proof` already proves; it names **which tenant tables are
    actually in the `supabase_realtime` publication**, because on a streaming
    table a permissive policy is a live firehose rather than one request at a
    time, and people rarely know that list.
- **feat: `tenant-guard all`** — runs every guard in order. With a dozen of them,
  "how do I check everything?" needed a one-command answer. Runtime guards with no
  database skip, and a skip is still never a pass.
- 270 tests (was 251).

## 0.14.0

Threat-model **2.11**, and the last planned read-path item: **RLS hides rows, not
constraints** — and constraints are enforced *below* it.

- **feat: new guard `constraint-oracles`** (`tenant-guard oracles`). Catalog-only,
  no probing, no transaction.
  - **A globally UNIQUE natural key on a tenant-scoped table fails the build.**
    `users.email UNIQUE` means inserting `victim@corp.com` raises `duplicate key
    value violates unique constraint` **even though RLS hides the row that caused
    it** — so anyone who can attempt an insert can test whether a value exists in
    another tenant, and `ON CONFLICT DO NOTHING` asks the same question silently,
    with no error at all. Nothing about the policies is wrong here; the schema is
    the leak. Fix: `UNIQUE (organization_id, email)`.
  - Deliberately quiet where it should be: **primary keys** are skipped (globally
    unique by design), **single-UUID** unique columns are skipped (you cannot
    enumerate random UUIDs, so the answer is worthless), **expression indexes** are
    skipped rather than guessed at, and tables with no tenant column are ignored
    entirely.
  - **Single-column foreign keys between tenant tables are an aggregated note, not
    a failure.** Referential-integrity checks run with RLS not applied, so a child
    row can confirm a parent in another tenant — but composite tenant FKs are rare
    enough that failing on them would flag nearly every schema, and exploiting one
    needs both a guessable parent id and an insert that passes `WITH CHECK`.
  - An integration test **proves the premise** rather than asserting it: as tenant
    A, `SELECT` returns 0 rows while the duplicate insert still raises `23505`.
- 251 tests (was 231).

## 0.13.0

The last surface on the threat model this tool could not reach: **Supabase
Storage** (5.1/5.2). It needed a genuinely new capability rather than a reuse of
existing machinery — storage has **no tenant column**.

- **feat: new guard `storage-isolation`** (`tenant-guard storage`). Tenancy in
  storage lives in the object **path** (`org_A/invoices/q1.pdf`), so the tenant is
  an *expression* over `name` rather than a column. That single difference is why
  every other guard here was blind to it.
  - **Tenant-expression support**, via `split_part(name, '/', N)` — deliberately
    *not* Supabase's `storage.foldername()`, so the same SQL also runs on vanilla
    Postgres and the guard is testable without a Supabase instance. The segment is
    validated as a bounded integer, never interpolated as a string.
  - **The upload path-hop.** The client supplies the object name on upload, so an
    INSERT policy that doesn't pin the tenant segment lets a user write straight
    into another tenant's folder — overwriting or planting files — no matter how
    correct the read policy is. The probe has a **control arm**: it first uploads
    into its *own* folder, so a refusal elsewhere is never miscredited to tenant
    scoping when the session simply can't upload at all.
  - **Public buckets.** `storage.buckets.public = true` serves
    `/storage/v1/object/public/…` with no auth and **no RLS evaluated at all**;
    "the path is unguessable" is not a boundary. Flagged when the bucket holds
    objects under two or more tenant folders — a single-folder asset bucket
    (logos, marketing) is not. Stated as a **catalog fact**, not claimed as probed:
    the CDN behaviour lives in the Storage service, not in Postgres.
  - Also flags RLS disabled outright on `storage.objects`, and **skips cleanly on
    non-Supabase databases** so nobody is punished for a surface they don't have.
- 231 tests (was 210).

## 0.12.0

Threat-model **3.8**, and it rhymes with 0.11.0: the policy is right, the thing it
trusts is writable. This time the write is to your **own row**.

- **feat(identity-trust): self-row escalation.** `CREATE POLICY self ON profiles
  FOR UPDATE USING (id = auth.uid()) WITH CHECK (id = auth.uid())` is exactly
  right, and exactly the bug — because **RLS is ROW-level and cannot restrict
  columns.** It decides *which rows* you may touch and says nothing about *which
  fields*, so it happily lets a user rewrite every column of their own row:
  the `role` another policy reads to grant admin, or the `organization_id` that
  decides which tenant they are in.
  - Read from **`has_column_privilege` per column**, not inferred from the policy,
    because a **column-level GRANT is the only thing that actually stops it** — and
    that is what the fix says (`REVOKE UPDATE … ; GRANT UPDATE (safe_cols) …`),
    not a policy change.
  - Scoped so it doesn't cry wolf: a writable column counts only when a policy
    that depends on the table actually **reads** it — plus tenant columns, which
    always count, since re-parenting your own row is escalation by definition.
- 210 tests (was 199).

## 0.11.0

Threat-model **2.10**: the policy is flawless and still bypassable, because the
thing it *derives authority from* is soft.

- **feat(identity-trust): user-writable policy authority.** The textbook
  multi-tenant policy —
  `USING (org_id IN (SELECT org_id FROM memberships WHERE user_id = auth.uid()))`
  — is completely bypassable if the caller can write `memberships`: insert
  yourself a row for someone else's org and every policy that trusts that table
  now returns their data, **legitimately**. Nothing is "leaking"; the authority was
  soft. Per-table checking can never find this, because the flaw is one table away
  from the table you're checking.
  - Dependencies are read from **`pg_depend`**, which records every relation a
    policy's subqueries touch — exact, where a regex over `pg_policies.qual` would
    be a guess.
  - Fails when the authority table has **RLS off with a write grant**, or an
    INSERT/UPDATE policy whose check **never constrains its tenant column**. That
    second case is the one worth naming: `WITH CHECK (user_id = auth.uid())` looks
    careful and is the most common real-world shape — it pins WHO you are and
    leaves WHICH TENANT wide open.
  - Covers the UPDATE shape too (re-point your own membership row at another
    tenant), and reports **unknown → a note** when the authority table has no
    recognisable tenant column, rather than guessing either way.
- 199 tests (was 184).

## 0.10.0

Built down the [threat model](THREAT-MODEL.md), not down a bug queue — and the
most important thing in this release is a **false negative it found in the
flagship guard**.

- **fix(rls-proof): partitioned tables reported GREEN while leaking.** Two
  compounding causes. A partitioned parent is `relkind = 'p'` and the
  introspection only looked at `'r'`, so the parent was never scanned. And
  list-partitioning by tenant means every partition holds exactly ONE tenant *by
  construction*, so the two-tenant probe could never fire — each partition was
  written off as "only 1 tenant, cannot prove". Net effect: `ok: true` on a
  database where any authenticated user reads every other tenant by naming the
  partition directly (PostgREST exposes each partition as its own endpoint).
  Fixed by scanning parents **and** adding a **foreign-tenant probe**: impersonate
  a tenant that exists elsewhere and check whether this table's rows are visible
  to them. That also upgrades ordinary **single-tenant tables** from "cannot
  prove" to a real verdict.
- **feat: new guard `identity-trust`** (`tenant-guard identity`). Asks the question
  every other guard assumes away: can the caller **forge the identity** your
  policies authorize from?
  - **`user_metadata` used for authorization → FAIL.** It is writable by the user
    (`supabase.auth.updateUser({ data })`) while `app_metadata` is not. Detected
    in the policy text (conclusive on its own) and then *proven* by forging that
    exact claim and re-reading the victim's rows — with a **control arm** forging a
    nonexistent tenant, so a table that is simply open to everyone is never
    misattributed to the claim.
  - **A callable `SECURITY DEFINER` function that sets your tenant GUC from an
    ARGUMENT → FAIL.** That is a "become any tenant" primitive. A function that
    derives the tenant from the verified session instead is only a note.
  - **Bare dependence on a client-settable GUC → NOTE, never a build failure.**
    Whether that is exploitable depends on architecture SQL cannot see (and it is
    how this tool itself impersonates). Failing on it would be exactly the
    unfalsifiable finding this project exists to avoid.
- **feat(rls-proof): `TRUNCATE` capability surfaced.** `TRUNCATE` ignores RLS
  completely — no policy can stop it — and `GRANT ALL` includes it. Read from the
  catalog and reported as **one aggregated note**, deliberately **never probed**: a
  `TRUNCATE` probe takes an `ACCESS EXCLUSIVE` lock and is the one statement you
  must not fire at a database by surprise.
- **fix(rls-proof): "not proven" count was counting notes, not tables** — advisory
  notes inflated it.
- 184 tests (was 155).

## 0.9.0

Closes the highest-severity item on the [threat model](THREAT-MODEL.md): the
objects that **aren't base tables**. Every table-only checker — including this
tool's own `rls-proof` until now — is blind to these.

- **feat: new guard `view-isolation`** (`tenant-guard views`). Proves a tenant's
  session can't read another tenant's rows through a **view** or **materialized
  view**. Two different Postgres mechanisms, and the guard distinguishes them
  because *the fix is different*:
  - A **view runs with its OWNER's privileges** unless created `WITH
    (security_invoker = true)` — which is **off by default**. So a convenience
    view over a perfectly-RLS'd table evaluates that RLS *as the owner* and hands
    back every tenant. Fix: `ALTER VIEW … SET (security_invoker = true)` (and the
    guard says so only when your Postgres is 15+; older servers get the honest
    alternative).
  - A **materialized view ignores RLS entirely** — it's a stored snapshot owned by
    whoever refreshes it, and *no policy can scope it per caller*. The fix text
    never suggests `security_invoker` here, because it would not work.
  - A view that **already** sets `security_invoker` and still leaks is reported as
    the *base table's* bug, pointing at `tenant-guard prove` — precise blame
    instead of a generic finding.
  - Scoped to views exposing a tenant column, so public/reference views aren't
    flagged; identity (`role`/`becomeTenant`/`claim`) is inherited from `rlsProof`
    so you configure it once.
- **feat(anon-reads): also covers views and materialized views.** An
  anon-readable matview of every tenant — auto-granted and auto-exposed in
  Supabase — is the CVE-2025-48757 class at its worst, and a base-table-only scan
  never sees it. Important asymmetry, deliberately encoded: for a base table
  "RLS off + grant" is a structural leak, but views *always* report
  `relrowsecurity = false`, so applying that rule to them would false-flag every
  safe `security_invoker` view. **Views are therefore always judged by the probe.**
- **refactor:** the `claim` shortcut moved to a shared `applyClaimShortcut()` so
  every impersonating guard uses one implementation.
- 155 tests (was 128).

## 0.8.0

Stop growing one reported bug at a time. This release derives the **whole failure
surface** up front, publishes it, and closes the biggest gaps it exposed.

- **docs: [`THREAT-MODEL.md`](THREAT-MODEL.md).** An enumeration of how
  multi-tenant isolation breaks in Postgres/Supabase — identity/probe integrity,
  read path, write path, non-table objects (views, matviews, definer functions,
  partitions), Supabase surfaces, pooling, privileges — each tagged **covered /
  partial / planned / out-of-scope**, with *why* for the out-of-scope ones. A
  security tool that hides its blind spots is worse than one that names them, so
  the app-layer IDOR, leaked-service-key, public-bucket-CDN and pooler-bleed
  classes are listed explicitly as **not** provable by this method.
- **feat: new guard `anon-reads`.** Proves the anonymous role cannot `SELECT`
  tenant tables — the CVE-2025-48757 class (303 endpoints across 170 Lovable
  projects readable with the public anon key) that this README has cited from day
  one while nothing actually checked it by default. Scoped to tables **with a
  tenant column**, so public content isn't flagged. Hybrid: RLS-off + grant is
  structural (true even when the table is empty); RLS-on is **probed as `anon`**,
  which proves the safe `TO public USING (auth.uid() = …)` idiom is safe instead
  of crying wolf the way a catalog-only linter does. Empty table → *not proven*,
  never a silent pass. New `anon-reads` command + `anonReads` config/init/exports.
- **fix(rls-proof): the owner-bypass false pass.** A table's **owner** is exempt
  from its own RLS unless `FORCE ROW LEVEL SECURITY` is set. If the probe role
  owns the table, RLS is silently inert there — and the deny-all canary could not
  catch it, because the canary isn't owned by the probe role. Such tables are now
  reported as **not proven**, naming the exact `ALTER TABLE … FORCE ROW LEVEL
  SECURITY` fix, instead of producing a vacuous pass or blaming the wrong policy.
- 128 tests (was 109).

## 0.7.0

Another sharp one from the same reviewer: alongside the wrong-tenant INSERT, probe
the **omitted tenant**.

- **feat(rls-proof): the omitted-tenant / orphan-row probe.** As each tenant, the
  proof now also inserts a row with the tenant column **NULL** (the client simply
  doesn't claim a tenant). A strict `tenant = current` policy rejects it cleanly —
  `NULL = 'org_A'` is not true — but where the column is **nullable** and the read
  policy treats NULL as global (`… OR tenant IS NULL`), you get a row **owned by
  nobody and readable by every tenant**. A wrong-tenant probe walks straight past
  it, because it never omits the tenant. Detected by whether the acting session can
  then *read* the row it created (its visible-row count grows). A `NOT NULL` tenant
  column makes such orphans schema-impossible — reported as a safe block, not a
  leak; a `NOT NULL` on some *other* column is inconclusive (a note).
- 109 tests (was 104).

## 0.6.0

Closes the last write path the runtime proof was missing — **INSERT isolation** —
the second half of a reviewer's ask (the first, the `claim` shortcut, shipped in
0.5.0).

- **feat(rls-proof): prove INSERT isolation.** As each tenant, the proof now tries
  to `INSERT` a row belonging to the *other* tenant. INSERT is governed only by a
  `WITH CHECK` clause, so a table can scope `SELECT`/`UPDATE` correctly yet let any
  session create rows in any tenant — a real per-command gap the read/update
  probes couldn't see. Three honest outcomes:
  - **leak** — the row was accepted into the other tenant (fails the build);
  - **blocked** — `WITH CHECK` rejected it, or a `BEFORE` trigger rewrote the
    tenant column back to the acting tenant, or the role has no INSERT grant;
  - **inconclusive** — a `NOT NULL`/FK/sequence error meant we couldn't build a
    valid row, so nothing is proven. Reported as a **note**, never a silent pass.
  - The probe deliberately uses **no `RETURNING`**: `RETURNING` re-applies the
    SELECT policy, and a row `WITH CHECK` accepted but SELECT hides then raises the
    *same* error a `WITH CHECK` block raises — which would mask the leak. Instead
    it reads where the row landed from the acting tenant's own-row count, so it's
    driver-agnostic and trigger-aware.
- 104 tests (was 98).

## 0.5.0

More from Reddit.

- **feat(rls-proof): catch the tenant-HOP.** The write probe now also tries to set
  the tenant column to the *other* tenant (`SET org = <B>`), moving a session's
  OWN row INTO another tenant. A correct read policy passes it — the row is yours
  on the way in — and with no `WITH CHECK` on the destination, nothing validates
  where it lands (especially when the policy is scoped by `created_by`/owner
  rather than the tenant column). This is a distinct cross-tenant write from the
  steal/delete cases, and it was previously missed. A correct `FOR ALL … WITH
  CHECK (tenant = current)` policy still passes cleanly (no false positive).
- **feat(rls-proof): `claim` shortcut.** `rlsProof.claim: "org_id"` (or
  `"team_id"` / `"account_id"`, or `{ key, role }`) builds the
  `request.jwt.claims` `becomeTenant` for you and sets `role` to `authenticated`
  — impersonation via `set_config`, so CI never needs the JWT secret. An explicit
  `becomeTenant` still wins (use it as the SQL hook for membership-table apps).
- 98 tests (was 96).

## 0.4.0

New guard: **`anon-writes`** — the unauthenticated write surface.

This closes the one class a real review found in the wild that no guard caught:
a table with no tenant column that the `anon` role can write. It's how a shared
cache gets poisoned — the public key ships in every browser bundle, so if `anon`
can write the table, anyone can rewrite what every user reads.

- **feat(anon-writes):** `tenant-guard anon-writes` flags tables the anonymous
  role can INSERT/UPDATE/DELETE. Reliability was the hard part: well-secured
  Supabase apps write policies `TO public USING (auth.uid() = …)`, which a
  catalog-only check can't evaluate and would false-positive on. So it's a
  hybrid — the unambiguous **RLS-off + grant** case from the catalog, and for
  **RLS-on** tables it drops to `anon` and actually attempts UPDATE/DELETE (each
  in a rolled-back savepoint), which evaluates the real `USING`/`WITH CHECK`. Same
  identity negative-control as `rls-proof` (aborts if `anon` bypasses RLS).
  Allowlist for intentionally-public tables. Honest limit: pure INSERT-only anon
  surfaces under RLS aren't probed yet (roadmap).
- New `anon-writes` command + `anonWrites` config/init/exports/subpath. 96 tests
  (was 85).

## 0.3.0

Both items in this release came straight from Reddit feedback.

- **feat(rls-proof): seeding mode.** `rlsProof.seed` makes the proof
  **manufacture two synthetic tenants** inside the rolled-back transaction
  instead of requiring two tenants to already have data. This closes two gaps:
  it works on an **empty / CI database**, and it handles **membership-table
  policies** (`org_id IN (SELECT … WHERE user_id = auth.uid())`) — your
  `seed.setup` creates the membership rows the impersonated identity needs, which
  a bare claim can't. Tenant ids default to two UUIDs (pass `seed.tenants` for
  other types); a broken seed statement fails with a clear message. Nothing
  persists.
- **fix(definer-grants): judge the FINAL state of history, not each file.** A
  function that ships unsafe and is fixed by a `REVOKE` (or by dropping
  `SECURITY DEFINER`) in a *later* repair migration is no longer flagged — it
  used to be, because the guard only looked for a same-file revoke. Now it takes
  the latest definition of each function across all migrations and whether it's
  ever revoked, matching an ArchUnit-style "assert on the final definition" test.
  Genuinely-unsafe functions introduced late are still caught.
- 85 tests (was 79).

## 0.2.1

Two improvements to `rls-proof`, both from sharp reviewer feedback.

- **feat(rls-proof): a built-in negative control.** Before trusting any pass, the
  proof drops to your app role and asserts it **cannot** read a deliberately
  deny-all RLS table (RLS on + `FORCE`, no policy). If it can, RLS isn't being
  enforced for that role — a superuser, a `BYPASSRLS` role, a table owner, or a
  `SET ROLE` that didn't take effect — so every "isolated" result would be a
  *vacuous pass*. The guard now fails with a clear message instead of reporting
  one. (Runs inside the same rolled-back transaction; the canary is a temp table.)
- **docs: membership-table policies.** Policies that read a membership/junction
  table (`org_id IN (SELECT … WHERE user_id = auth.uid())`) need a *seeded
  membership row* for the impersonated identity, not just a claim — otherwise the
  table reports as "not proven." Documented in the rls-proof example, and the
  over-restrictive note now points at it. 79 tests (was 77).

## 0.2.0

New guard: **`rls-drift`** — prove your RLS is in version control.

Motivated by a real review: running the tool against a Supabase app surfaced a
permissive policy that let `anon` write a shared table — and the reason it had
hidden was that the policy existed **only in production**, applied by hand and
never captured in a migration. Its security posture was invisible to code review.

- **feat(rls-drift):** `tenant-guard drift` reads every `ENABLE ROW LEVEL
  SECURITY` / `CREATE POLICY` in your migrations (net of `DROP`/`DISABLE`) and
  diffs it against the live catalog (`pg_policies` + `pg_class.relrowsecurity`).
  Anything present in the database but declared in **no** migration fails the
  build; declared-but-absent is a note (migrations may be unapplied). The diff is
  name/flag-presence, not policy-expression parsing — reliable, no false drift.
  Read-only (two catalog queries, no transaction). Skips cleanly with no DB;
  `rlsDrift.allowlist` for policies intentionally managed outside migrations.
- New CLI command `drift`; `rlsDrift` config block + init stub; `drift`/`runDrift`
  exported; `./guards/rls-drift` subpath. 77 tests (was 61).

## 0.1.4

Docs only. Validated end-to-end against two real, independently-built Supabase
codebases (a ~500k-line org-multi-tenant app and a ~per-user travel app); the
guards behaved correctly on both, so no code changed.

- **docs: per-user apps.** The run surfaced a common adoption case worth naming:
  when the tenant is a *user*, add `user_id` to `routeOrgScoping.tenantSignals`
  and `rlsProof.tenantColumns`. It's intentionally **not** a default — in a B2B
  app `user_id` is often just the creator, and treating it as the boundary would
  hide real org leaks. Also: allowlist genuinely shared tables/routes (a
  places-cache, a reference table) with a reason instead of scoping global data.

## 0.1.3

The runtime proof (`rls-proof`) now tests the **write path**, not just reads —
prompted by sharp reviewer feedback that the leaks that actually bite are on
`UPDATE`.

- **feat(rls-proof): write-path proving.** As each tenant, the proof now probes
  `UPDATE`/`DELETE` of other tenants' rows and reports a **write leak** when they
  succeed — a distinct violation from a read leak. RLS is per-command, so a
  correct `SELECT` policy can leave `UPDATE`/`DELETE` wide open; this catches it.
  Each write probe runs in a `SAVEPOINT` that is rolled back inside the
  already-rolled-back transaction, so it stays non-destructive. Toggle with
  `probeWrites` (default `true`).
  - The probe deliberately uses whole-table `UPDATE`/`DELETE` with **no `WHERE`**
    and compares the affected-row count to the tenant's own: a `WHERE tenant =
    'other'` probe is *masked* by a correct read policy (you can't target rows
    you can't see), which would hide the very leak we're hunting.
- **feat(rls-proof): name the RLS-on-no-policy trap.** A table with RLS enabled
  and **no policy** denies every row — which looks exactly like isolation but is
  really an unfinished table. It's now detected from `pg_policy` and reported
  explicitly (`no policy`) instead of passing silently or as a vague note.
- **docs:** README, METHODOLOGY, and the rls-proof example updated; the demo gains
  a third scenario — reads correctly scoped, `UPDATE` wide open — the exact case
  a SELECT-only test misses.
- 61 tests (was 48).

## 0.1.2

Docs only — no code changes since 0.1.1.

- README: animated demo GIF, CI / npm / license / zero-dependency badges, and a
  "How it fits your project" section clarifying that tenant-guard runs **in your
  repo** against files on disk (plus an optional test-database connection for the
  runtime proof) — it is not a scanner you point at a URL.
- Corrected the CVE-2025-48757 reference to the primary-sourced figure: 303
  endpoints across 170 Lovable projects, readable by unauthenticated requests via
  the public anon key.

## 0.1.1

Everything here came out of trying to *prove* the flexibility claims rather than
assert them — see `test/flexibility.test.mjs`.

- **fix(rls-proof):** a misconfigured `becomeTenant` now degrades to a clear,
  actionable note (`could not probe — … cast the placeholder, e.g. $1::text`)
  instead of crashing the entire proof with a cryptic driver stack.
- **fix(docs):** the Supabase JWT-claim `becomeTenant` example now casts the
  placeholder (`$1::text`). Without it Postgres can't infer the type inside
  `json_build_object` and the proof errored (SQLSTATE 42P18).
- **feat(route-org-scoping):** the default bare-id detector now also catches
  **Drizzle** (`eq(table.id, …)`), alongside Supabase (`.eq('id')`) and Prisma
  (`where: { id }`). Re-validated false-positive-free against a real
  493k-line codebase. Raw SQL (`where id = …`) stays out of the default and is
  configurable via `idFilterPattern`.
- **test:** add `test/flexibility.test.mjs` — proofs for Supabase JWT-claim
  policies, non-Supabase session-GUC apps, Prisma/Drizzle routes, custom tenant
  columns, robustness, and the documented boundaries. 48 tests total; the test
  suite now ships in the package.

## 0.1.0

Initial release: three zero-dependency static guards (`route-org-scoping`,
`definer-grants`, `migration-collisions`) plus the runtime `rls-proof`, the CLI
(`run` / `prove` / `init` / `list`), config, and runnable examples.
