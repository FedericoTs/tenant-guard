# Wiring tenant-guard into CI

tenant-guard exists to **block the merge**, so the only installation that counts
is the one in your pipeline. This is the whole guide.

- [30-second version](#30-second-version)
- [GitHub Action](#github-action)
  - [Inputs](#inputs)
  - [Outputs](#outputs)
  - [With a database](#with-a-database-the-runtime-guards)
  - [Adopting on an existing codebase](#adopting-on-an-existing-codebase)
- [Any other CI](#any-other-ci)
- [Troubleshooting](#troubleshooting)

---

## 30-second version

```yaml
# .github/workflows/tenant-guard.yml
name: tenant-guard
on: [pull_request]

jobs:
  guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write     # so findings reach the Security tab
    steps:
      - uses: actions/checkout@v4
      - uses: FedericoTs/tenant-guard@v0
```

That runs the static guards, fails the build on a finding, writes a result table
to the run summary, and uploads SARIF so each finding is annotated on the diff.
No `npm ci`, no config, no database.

Run `npx tenant-guard init` once in your repo to commit a config, or let the
guards autodetect and skip what they can't find. **A skip is never a pass** —
every skipped guard is listed with its reason, in the summary and in the SARIF.

---

## GitHub Action

### Inputs

| Input | Default | What it does |
|---|---|---|
| `command` | `run` | `run` = static guards only. `all` = static + every runtime proof. Or one guard: `prove`, `drift`, `anon-reads`, `anon-writes`, `identity`, `rpc`, `views`, `storage`, `realtime`, `schemas`, `pooler`, `defaults`, `fks`, `creates`, `mfa`, `shadows`, `oracles`, `caps` |
| `database-url` | `''` | Postgres URL for the runtime guards. **Test/staging only** — see the warning below |
| `working-directory` | `.` | Run in a subdirectory (monorepos) |
| `version` | *this action's version* | npm version of the CLI. Pinning the action pins the tool; set `latest` to float |
| `fail-on-error` | `true` | `false` reports findings without blocking — see [adoption](#adopting-on-an-existing-codebase) |
| `upload-sarif` | `true` | Upload to GitHub code scanning. Needs `security-events: write` |
| `job-summary` | `true` | Write the result table to the run summary page |
| `install-pg` | `auto` | Installs the `pg` driver when `database-url` is set. Both it and the CLI go into the action's own prefix under `RUNNER_TEMP` — **your `node_modules` is never touched** |

### Outputs

| Output | Example | |
|---|---|---|
| `result` | `pass` / `fail` | |
| `exit-code` | `0` / `1` / `2` | `2` = bad usage, not a finding |
| `sarif-file` | `/home/runner/work/_temp/tenant-guard.sarif` | |
| `json-file` | `/home/runner/work/_temp/tenant-guard.json` | full results — see [OUTPUT.md](OUTPUT.md) |

```yaml
      - uses: FedericoTs/tenant-guard@v0
        id: guard
        with:
          fail-on-error: false
      - run: echo "verdict is ${{ steps.guard.outputs.result }}"
```

### With a database (the runtime guards)

The static guards read files. The runtime guards **prove** isolation by running
real SQL as your real app role — which means they need a database.

> [!WARNING]
> **Never point `database-url` at production.** The runtime guards perform write
> probes — `INSERT`, `UPDATE`, `DELETE`, and a tenant-hop attempt — inside a
> transaction that is rolled back. Rollback is not a substitute for pointing it
> somewhere disposable. Use a service container, a CI branch database, or a
> staging copy.

```yaml
name: tenant-guard
on: [pull_request]

jobs:
  guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready --health-interval 10s
          --health-timeout 5s --health-retries 5
        ports: ['5432:5432']

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22

      # Build the schema the same way you build it anywhere else. Whatever gets
      # your migrations + a couple of tenants' rows into that database is right.
      - name: Apply migrations
        run: psql "$DB" -f supabase/migrations/*.sql
        env:
          DB: postgres://postgres:postgres@localhost:5432/postgres

      - uses: FedericoTs/tenant-guard@v0
        with:
          command: all
          database-url: postgres://postgres:postgres@localhost:5432/postgres
```

Two tenants' worth of rows have to exist for the comparison to mean anything.
If your CI database starts empty, use the `seed` block in
`tenant-guard.config.json` — it manufactures two synthetic tenants inside the
rolled-back transaction, so nothing is left behind:

```jsonc
"rlsProof": {
  "claim": "org_id",
  "seed": {
    "setup": [
      "insert into organizations (id) values ($1)",
      "insert into memberships (user_id, organization_id) values (gen_random_uuid(), $1)",
      "insert into invoices (organization_id, amount) values ($1, 100)"
    ]
  }
}
```

Each statement runs privileged, once per tenant, with `$1` bound to the tenant
id, in the order you list them.

### Adopting on an existing codebase

A mature repo will light up on the first run. That is normal, and failing the
build on day one is the fastest way to get the tool deleted. Two levers:

**1. Report first, block later.**

```yaml
      - uses: FedericoTs/tenant-guard@v0
        with:
          fail-on-error: false     # findings appear; the build stays green
```

Findings still reach the Security tab and the job summary. Flip it to `true`
once the list is empty.

**2. Allowlist what you can't fix yet, with a reason.**

Every guard takes an `allowlist`, and every finding tells you the exact string
to add. Allowlisting is not cheating — it converts "we have 40 unknown problems"
into "we have 40 known ones and no new ones", and from that point the guard can
only ratchet in your favour.

`definerGrants` also takes a `baseline` migration number, so only migrations
after that number are judged.

---

## Any other CI

The Action is a convenience wrapper. The CLI is the product, and it is one
command with no install step:

```bash
npx tenant-guard run          # exit 1 on a finding
```

**GitLab CI**

```yaml
tenant-guard:
  image: node:22
  script:
    - npx tenant-guard all --json=tenant-guard.json
  variables:
    TENANT_GUARD_DATABASE_URL: $CI_STAGING_DATABASE_URL
  artifacts:
    when: always
    paths: [tenant-guard.json]
```

**As a test, so it runs with everything else**

```json
{
  "scripts": {
    "test": "node --test && tenant-guard run"
  }
}
```

**Pre-commit / lefthook / husky** — the static guards take milliseconds and need
no database, so they are cheap enough to run on commit:

```bash
npx tenant-guard run --quiet
```

Anything that reads SARIF (GitLab, Sonar, DefectDojo, Semgrep AppSec Platform)
takes `--sarif=file` directly. Anything else takes `--json`.

---

## Troubleshooting

**`Resource not accessible by integration` on the upload step**
The job is missing the permission. Add it, or turn the upload off:

```yaml
    permissions:
      security-events: write
```
```yaml
        with:
          upload-sarif: false
```
Code scanning uploads also require GitHub Advanced Security on private
repositories; public repositories have it enabled by default.

**Everything skipped, and the run is green**
That is the tool working — and saying so. `run` skips guards whose paths it
can't find; the runtime guards skip without `database-url`. Run
`npx tenant-guard init` to write a config with the right paths, and read the
skip list in the job summary: it names every guard that did not run and why.

**`Cannot find package 'pg'`**
A runtime guard was asked for without the driver. The Action installs it
automatically when `database-url` is set — into its own prefix, not your
`node_modules`. If you set `install-pg: false`, install `pg` yourself. Running
the CLI directly? `npm i -D pg`.

**A guard fails and I believe it is wrong**
Read the `fix` line — it names the exact allowlist entry. If the finding is a
false positive rather than an accepted risk,
[open an issue](https://github.com/FedericoTs/tenant-guard/issues); a
reproducible false positive is a bug, and the
[threat model](../THREAT-MODEL.md) records what each guard claims to prove.
