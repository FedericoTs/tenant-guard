# Runtime RLS proof — runnable demo

This is the guard that does what a scanner can't: it connects to a real Postgres,
assumes one tenant's identity, and **proves** that session cannot read another
tenant's rows.

## Run it with zero infrastructure

```bash
npm i @electric-sql/pglite     # embedded Postgres — no Docker, no server
node examples/rls-proof/demo.mjs
```

You'll see the proof **pass** a correctly scoped policy, then **fail** the same
schema after the tenant predicate is dropped — exiting non-zero, exactly as it
would in CI on a real leak.

## Run it against your own database

`prove` talks to Postgres over the `pg` driver. Point it at a **seeded test or
staging** database (never production) that has data for at least two tenants:

```bash
npm i -D pg
export TENANT_GUARD_DATABASE_URL="postgres://user:pass@host:5432/db_test"
npx tenant-guard prove
```

By default the proof assumes a tenant with the canonical Postgres pattern
(`current_setting('app.current_tenant')`). If your policies key off a JWT claim
(Supabase), tell it how to assume an identity in `tenant-guard.config.json`:

```json
{
  "rlsProof": {
    "role": "authenticated",
    "becomeTenant": [
      "select set_config('request.jwt.claims', json_build_object('org_id', $1::text)::text, true)"
    ],
    "tenantColumns": ["organization_id", "tenant_id"],
    "grandfather": ["shared_reference_table"]
  }
}
```

`$1` is bound to a tenant id the proof discovered in your data. **Cast it
(`$1::text`)** — `json_build_object` gives Postgres no way to infer the
placeholder's type otherwise, and the proof will report a clear "could not
probe — cast the placeholder, e.g. `$1::text`" note. If your RLS resolves the
tenant from `auth.uid()` via a users table, set `sub` to a real user id of that
tenant instead (the `becomeTenant` SQL can look it up: `... 'sub', (select id
from users where organization_id = $1::text limit 1) ...`).

## What it reports

- **isolated** — the session saw its own rows and **zero** of the other tenant's. ✓
- **leak** — it saw the other tenant's rows. Either a policy is permissive
  (`USING (true)` / missing the tenant predicate) or **RLS is off entirely**.
  This fails the build. ✗
- **not proven** (a note, not a failure) — the table has only one tenant's data,
  or the `becomeTenant`/`role` config doesn't match your policies, so isolation
  couldn't be demonstrated. Seed a second tenant, or fix the config.

Everything runs inside a transaction that is rolled back, and the proof only
ever issues `SELECT`s — it never writes to your database.
