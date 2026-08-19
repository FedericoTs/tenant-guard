# Changelog

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
