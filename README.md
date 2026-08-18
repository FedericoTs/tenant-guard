# tenant-guard

**Guard tests that fail your CI when multi-tenant code can leak across tenants.**

<p align="center">
  <img src="https://raw.githubusercontent.com/FedericoTs/tenant-guard/main/assets/demo.gif" alt="tenant-guard failing CI on two cross-tenant leaks: a SECURITY DEFINER function callable by anon, and an API route that filters by bare id with no tenant scope" width="760">
</p>

Not a scanner you run and then ignore. These are checks that live in your repo,
run in `npm test` and your CI, and **block the merge** — so the cross-tenant
leak never ships. The static guards have **zero dependencies** and run in CI
without `npm ci`; the runtime proof adds a real Postgres check when you opt in.

```bash
npx tenant-guard init     # detects your migrations + API routes, writes a config
npx tenant-guard run      # static guards — exit 1 if anything can leak
npx tenant-guard prove    # runtime proof — exit 1 if a tenant can read another tenant
```

---

## The problem

AI code generators — and tired humans — ship the same multi-tenant bugs over
and over:

- an authenticated route loads a row by **bare id** with no tenant filter, so
  any user of tenant A can read tenant B's data by guessing an id;
- a new `SECURITY DEFINER` Postgres function is left **callable by `anon`**
  because Postgres grants EXECUTE to `PUBLIC` by default;
- two migrations collide on a number and apply in the wrong order.

These aren't exotic. [170 of 1,645 Lovable showcase apps (10.3%) shipped with
missing row-level security](https://nvd.nist.gov/vuln/detail/CVE-2025-48757),
exposing 303 endpoints. [Wiz found an SSO-bypass in Base44](https://www.wiz.io/blog/wiz-research-uncovers-critical-vulnerability-in-base44)
that reached into any private enterprise app. [Veracode's 2025 study](https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/)
found 45% of LLM-generated code introduces an OWASP Top 10 flaw — and larger,
newer models were **not** safer.

## What it catches (run against a typical vibe-coded app)

```
tenant-guard  — guard tests for multi-tenant isolation

✓ migration-collisions — 2 migrations scanned; 0 grandfathered duplicate(s) ignored
✗ definer-grants — 1 unsafe function(s)
    • 200_add_reset_helper.sql
      function "reset_workspace" is SECURITY DEFINER + mutates but EXECUTE is not revoked from PUBLIC/anon
      → In the SAME migration add:  REVOKE EXECUTE ON FUNCTION public.reset_workspace(<args>) FROM PUBLIC, anon;
✗ route-org-scoping — 1 route(s) can leak across tenants
    • src/app/api/invoices/[id]/route.ts
      authenticated + filters by bare id + never scopes by a tenant column
      → Add the tenant column to every query, e.g. .eq('organization_id', auth.organizationId).

✗ 2 guard(s) failed
```

(That output is real — it's `examples/leaky-demo/`. Reproduce it:
`cd examples/leaky-demo && node ../../bin/tenant-guard.mjs run`.)

## The guards

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `route-org-scoping` | an authenticated route filters by a bare `id` and never mentions a tenant column | catches the *shape* of the IDOR (auth + bare-id + no-tenant), and it lives in your CI so it blocks the merge instead of adding one more report |
| `definer-grants` | a new mutating `SECURITY DEFINER` function isn't revoked from `PUBLIC`/`anon` | requires knowing Postgres default grants + PostgREST exposure interact — *revoking from `anon` alone is a no-op* |
| `migration-collisions` | two migrations share a numeric prefix | a project-specific CI invariant (your numbering scheme), not a code smell |
| `rls-proof` *(runtime)* | a tenant's session can actually read another tenant's rows | it isn't reading source at all — it runs a real query as your app role and measures the leak; nothing static can prove isolation *holds* |

`npx tenant-guard list` describes each.

## Prove it at runtime — the part no scanner can do

The three guards above read source text: they catch the obvious leak cheaply,
but they can't *prove* isolation holds. `tenant-guard prove` can. Against a
seeded test database it:

1. finds every table with a tenant column, noting whether RLS is even on;
2. as the privileged role (which bypasses RLS, like Supabase `service_role`)
   picks two real tenant ids that already have data;
3. drops to your **non-superuser app role** (e.g. `authenticated`), assumes
   tenant A's identity, and asserts A's session sees **zero** of tenant B's
   rows — then checks the other direction.

If RLS is off, or a policy is `USING (true)`, or a policy forgot the tenant
predicate, tenant A sees tenant B's rows and the proof **fails your build**.

See it catch a real leak with zero infrastructure:

```bash
npm i @electric-sql/pglite        # embedded Postgres — no Docker
node examples/rls-proof/demo.mjs  # passes a good policy, fails a leaky one
```

Against your own database (a **test/staging** one, never production):

```bash
npm i -D pg
export TENANT_GUARD_DATABASE_URL="postgres://…/your_test_db"
npx tenant-guard prove
```

It only ever runs `SELECT`s, inside a transaction it rolls back — non-destructive
by construction. A skip (no database, or `pg` not installed) is **not** a pass,
and the CLI says so. Full setup — including the Supabase JWT-claim config — is in
[`examples/rls-proof/`](examples/rls-proof/README.md).

## Why not just a SAST scanner?

There is a good static scanner for this space —
[`mcp-tenant-isolation`](https://www.npmjs.com/package/mcp-tenant-isolation)
(57 rules, SARIF). If you want a report of findings, use it; the two compose.

tenant-guard is a **different tool for a different failure mode**. A scanner
produces a list of findings that a busy team learns to ignore (alert fatigue).
tenant-guard's checks are **tests in your own suite** — red in `npm test`, the
PR can't merge, and they carry a per-project **allowlist**: when you adopt it on
a legacy repo you allowlist the debt you can't fix today, the build goes green,
and *it can only get better from there*. It's the
[ArchUnit](https://www.archunit.org/) philosophy — architecture rules as
executable tests — pointed at tenant isolation, which nobody had done.

## Adopt it

```bash
npx tenant-guard init          # writes tenant-guard.config.json
npx tenant-guard run           # allowlist any legacy finding you can't fix yet
```

Then wire it into CI (GitHub Actions example ships in
`examples/ci-github-actions.yml`) — one job, no install:

```yaml
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npx tenant-guard run
```

Or import the guards into your existing vitest/jest suite:

```js
import { runAll } from 'tenant-guard';
test('no cross-tenant leaks (static)', () => {
  const failed = runAll().filter(r => !r.ok && !r.skipped);
  expect(failed).toEqual([]);
});
```

The runtime proof drops straight into your suite too — hand it any Postgres
client whose `query(text, values)` returns `{ rows }` (node-postgres, or an
embedded pglite in tests):

```js
import { prove } from 'tenant-guard';
test('RLS actually isolates tenants', async () => {
  const res = await prove({ query: (t, v) => pool.query(t, v) });
  expect(res.violations).toEqual([]);
});
```

## Config

`tenant-guard.config.json` (see `examples/tenant-guard.config.json` for the
annotated version). Every guard is opt-in and autodetects its paths; a guard
that doesn't apply to your stack **skips**, it never fails you.

```json
{
  "migrations":     { "dir": "supabase/migrations", "grandfather": ["031", "101"] },
  "definerGrants":  { "baseline": 189, "allowlist": ["validate_public_token"] },
  "routeOrgScoping":{ "routesDir": "src/app/api", "allowlist": [] },
  "rlsProof":       { "role": "authenticated", "tenantColumns": ["organization_id"], "grandfather": ["shared_lookup"] }
}
```

`rlsProof` runs only when `TENANT_GUARD_DATABASE_URL` (or `DATABASE_URL`) is set,
so it stays skipped until you opt in. `becomeTenant` (how a session assumes a
tenant identity) defaults to the canonical Postgres GUC pattern; override it for
Supabase JWT policies — see [`examples/rls-proof/`](examples/rls-proof/README.md).

Defaults target Next.js App Router + Supabase/Postgres, but every signal
(auth helpers, tenant column names, route glob) is configurable, so it works on
any stack that has API routes and SQL migrations. The bare-id detector ships
with patterns for **Supabase** (`.eq('id')`), **Prisma** (`where: { id }`), and
**Drizzle** (`eq(table.id, …)`) out of the box; raw SQL (`where id = …`) is left
out of the default to avoid false positives on self-loads — widen
`idFilterPattern` in config if you want it. These claims are backed by tests in
[`test/flexibility.test.mjs`](test/flexibility.test.mjs), which also prove
`rls-proof` against Supabase JWT-claim policies and non-Supabase session-GUC
apps.

## Honest limits

The three static guards are **heuristics on source text**, deliberately
conservative — they catch a bug *shape*, not every instance. The real defence
for tenant isolation is **row-level security enforced in the database**, which is
exactly why `rls-proof` exists: it doesn't guess from source, it runs a query as
your app role and measures whether the isolation actually holds.

`rls-proof` has honest limits of its own. It proves isolation for the tables it
can reach with the tenant identity you configure; it can only test tables that
already hold two tenants' data (it reports the rest as *not proven*, never as
passing); and it's only as good as the `becomeTenant` config matching how your
app assumes a tenant — a mismatch shows up as "sees none of its own rows either",
not a false pass. It is a strong proof on every commit, not a substitute for a
pen test.

## Background

These guards were extracted from a production multi-tenant EU SaaS (now retired)
where they ran green on every push. The interesting finding from that codebase
is written up in [`METHODOLOGY.md`](METHODOLOGY.md): **the descriptive docs
written for the AI agent all rotted, while every executable guard survived.**

## Licence

MIT — see [`LICENSE`](LICENSE). By Federico Sciuca.
