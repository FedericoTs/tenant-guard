# Changelog

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
