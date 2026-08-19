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
(Supabase), the shortest way to say so is `claim` — it builds the
`request.jwt.claims` impersonation for you, so **CI never needs the JWT secret**:

```json
{
  "rlsProof": {
    "claim": "org_id",
    "tenantColumns": ["organization_id", "tenant_id"],
    "grandfather": ["shared_reference_table"]
  }
}
```

`claim: "org_id"` (or `"team_id"` / `"account_id"`, or `{ "key": "org_id", "role":
"member" }`) expands to a `set_config('request.jwt.claims', …)` `becomeTenant` and
sets `role` to `authenticated`. Prefer the explicit `becomeTenant` below when your
policies resolve the tenant some other way (a `users`/memberships lookup) — an
explicit `becomeTenant` always wins over `claim`:

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

**Membership-table policies.** The thing that varies most between apps isn't the
claim shape — it's policies that read a **membership/junction table** rather than
a claim, e.g. `organization_id IN (SELECT organization_id FROM memberships WHERE
user_id = auth.uid())`. For those, setting a claim isn't enough: the impersonated
identity needs a **seeded membership row** linking that user to the tenant, or the
session resolves to "no orgs," sees nothing, and the table reports as *not proven*
(over-restrictive) rather than isolated. Impersonate a user who is already a
member of the discovered tenant, and make sure your test database has the
membership rows — or use **seeding mode** (below), which creates them for you.

## Seeding mode — prove on an empty database

By default the proof samples two tenants that already have data. On a fresh / CI
database, or for policies that read a membership table, there's nothing to
sample. `seed` fixes that: it **manufactures two synthetic tenants inside the
rolled-back transaction**, so nothing is ever committed.

```json
{
  "rlsProof": {
    "becomeTenant": ["select set_config('app.uid', (select user_id from memberships where organization_id = $1::text limit 1)::text, true)"],
    "seed": {
      "setup": [
        "insert into memberships (user_id, organization_id) values (gen_random_uuid(), $1::text)",
        "insert into invoices (organization_id, amount) values ($1::text, 100)"
      ]
    }
  }
}
```

Each `setup` statement runs once per synthetic tenant with `$1` = the tenant id,
**privileged**, in dependency order (parents before children). Tenant ids default
to two generated UUIDs; pass `"tenants": ["…", "…"]` if your tenant column isn't a
UUID. A table your seed doesn't populate is reported as "not proven" (add an
INSERT for it), and a broken seed statement fails with the exact SQL error.

## What it reports

- **isolated** — the session could neither read nor write the other tenant's
  rows, and saw its own. ✓
- **read leak** — it *read* another tenant's rows. A policy is permissive
  (`USING (true)` / missing the tenant predicate) or **RLS is off entirely**.
  Fails the build. ✗
- **write leak** — it could *UPDATE/DELETE* another tenant's rows, **or reassign
  its OWN rows into another tenant** (`SET organization_id = <other>` — a
  tenant-hop the read policy passes because the row is yours on the way in, and no
  `WITH CHECK` on the destination stops), even when reads were correctly scoped.
  RLS is **per-command**: a right-looking `SELECT` policy says nothing about
  `UPDATE`/`DELETE`, and `USING` says nothing about where an update *lands* — that
  needs `WITH CHECK` (and `UPSERT` needs its own `UPDATE` policy). Fails the
  build. ✗
- **no policy** (a note) — RLS is enabled but the table has **no policy at all**.
  Postgres then denies every row, which looks *exactly* like isolation but means
  the table is unfinished — the moment someone adds a permissive policy it leaks.
  Named explicitly so it can't masquerade as a pass.
- **not proven** (a note) — only one tenant's data, no read access, or the
  `becomeTenant`/`role` config doesn't match your policies. Seed a second tenant,
  or fix the config.
- **identity self-check failed** — before trusting any pass, the proof drops to
  your app role and checks it *cannot* read a deliberately deny-all RLS table. If
  it can, RLS isn't being enforced for that role (a superuser, a `BYPASSRLS` role,
  a table owner, or a `SET ROLE` that didn't take effect) — so a green result
  would be meaningless. The proof fails instead of reporting a vacuous pass. ✗

Everything runs inside a transaction that is rolled back, and each `UPDATE`/`DELETE`
write probe is additionally wrapped in its own `SAVEPOINT` that is rolled back —
nothing is ever committed. (Triggers still fire inside the rolled-back
transaction; set `"probeWrites": false` to test reads only.)
