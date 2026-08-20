# Output formats

Every command takes the same three flags, and **the exit code is identical in
all of them** — the format changes who can read the result, never the verdict.

| | Exit code |
|---|---|
| every guard that ran passed | `0` |
| at least one guard failed | `1` |
| bad usage — unknown command or option | `2` |

```bash
tenant-guard all --json[=FILE]       # results as data
tenant-guard all --sarif[=FILE]      # GitHub code scanning
tenant-guard all --markdown[=FILE]   # a job summary
```

Omit `=FILE` and the document goes to **stdout**, with the human-readable report
suppressed so the output is parseable. Give it a file and the human report stays
on stdout as usual. Two formats cannot share stdout — that exits `2` rather than
interleaving two documents.

`--json` and `--sarif` overwrite their file. `--markdown` **appends**, because
its destination is usually `$GITHUB_STEP_SUMMARY`, which other steps write to
as well.

---

## `--json`

The stable contract. Add `--json` to any command:

```bash
tenant-guard all --json | jq '.summary'
tenant-guard all --json | jq -r '.guards[] | select(.status=="skip") | .id + " — " + .reason'
```

```jsonc
{
  "$schema": "https://github.com/FedericoTs/tenant-guard/blob/main/docs/OUTPUT.md",
  "schemaVersion": 1,
  "tool": { "name": "tenant-guard", "version": "0.20.0" },
  "command": "all",

  "summary": {
    "guards": 16,        // guards considered
    "ran": 3,            // guards that actually ran — EXCLUDES skips
    "passed": 1,
    "failed": 2,
    "skipped": 13,
    "violations": 2,     // total findings that fail the build
    "notes": 0,          // total informational findings that do not
    "ok": false,
    "exitCode": 1        // the same code the process exits with
  },

  "guards": [
    {
      "id": "route-org-scoping",
      "status": "fail",              // "pass" | "fail" | "skip"
      "summary": "1 route(s) can leak across tenants",
      "scanned": 2,                  // present when the guard counts things
      "violations": [
        {
          "where": "src/app/api/invoices/[id]/route.ts",
          "message": "authenticated + filters by bare id + never scopes by a tenant column",
          "fix": "Add the tenant column to every query in this route, …",
          "kind": "read"             // optional; only some guards classify
        }
      ],
      "notes": []
    },
    {
      "id": "rls-proof",
      "status": "skip",
      "reason": "no database configured — set TENANT_GUARD_DATABASE_URL",
      "summary": "skipped",
      "violations": [],
      "notes": []
    }
  ]
}
```

### The three fields worth knowing

**`status` — a skip is never a pass.** `ran` excludes skips for the same reason,
so `"failed": 0` can never be mistaken for "everything was checked". If you
build a badge or a gate from this, gate on `summary.ran` too.

**`violations` vs `notes`.** A violation fails the build; it is conclusive. A
note does not; it is real but its exploitability depends on something SQL cannot
see (architecture, deployment, whether an attacker can guess a value). Notes are
where this tool refuses to cry wolf — see the
[threat model](../THREAT-MODEL.md) for which findings are deliberately notes.

**`fix`.** Every violation carries one, and it names the exact allowlist entry if
the finding is an accepted risk rather than a bug.

### Stability

- `schemaVersion` is bumped **only** when a field changes meaning or disappears.
  Adding a field is not a breaking change — parse defensively.
- The output is **deterministic**: no timestamps, no durations, no absolute
  paths. Two runs against an unchanged repo and database are byte-identical, so
  you can commit a baseline and diff against it.

```bash
tenant-guard all --json=baseline.json     # commit this
diff <(tenant-guard all --json) baseline.json
```

`tenant-guard list --json` emits the guard catalogue (id, title, why) instead of
a run — enough to generate a docs table from.

---

## `--sarif`

SARIF 2.1.0, for GitHub code scanning and anything else that reads it. The
[Action](CI.md#github-action) produces and uploads this for you; do it by hand
with:

```yaml
      - run: npx tenant-guard all --sarif=tg.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tg.sarif
          category: tenant-guard
```

### How findings map

| tenant-guard | SARIF |
|---|---|
| guard | one `rule`, with the guard's own title and rationale as its description |
| violation | `result` at level `error` |
| note | `result` at level `note` |
| the `fix` text | appended to the result message — the finding is useless without it |
| skipped guard | `invocations[0].toolConfigurationNotifications` |

### Locations, honestly

SARIF wants a file and a line. Most of these guards find things in a **database**,
which has neither. Rather than invent one:

- **Static guards** (`route-org-scoping`, `definer-grants`,
  `migration-collisions`) point at the real file. `migration-collisions` emits
  one location per colliding file.
- **Runtime guards** are anchored at `tenant-guard.config.json` — not a cosmetic
  choice: that is the file you would edit to allowlist the finding, so "go to
  location" lands somewhere useful. The database object is carried in
  `logicalLocations`, which is the field SARIF has for exactly this.
- **No line numbers are claimed.** File-level findings use `startLine: 1`, which
  is the conventional way to say "this file" rather than "this line".
- If a path doesn't exist on disk, the result is emitted with **no location**
  rather than a broken pointer — GitHub silently discards results that point at
  missing files, which would turn a real finding into a green run.

`partialFingerprints.tenantGuardV1` is a hash of guard + object + message, with
no line numbers in it, so GitHub tracks a finding across runs and unrelated
edits don't resurrect it as new.

`executionSuccessful` is `true` even when guards fail — it means "the tool ran",
and setting it false makes GitHub discard the entire run.

---

## `--markdown`

A result table for a GitHub Actions job summary:

```bash
tenant-guard all --markdown=$GITHUB_STEP_SUMMARY
```

The headline verdict, a table of every guard that ran, each finding with its fix
in a fenced block, notes collapsed behind a `<details>` — and the **skip list
never collapsed**, because a summary that quietly omits what it did not check is
how a green badge starts meaning less than the person reading it thinks.

---

## Programmatic use

Every guard is importable, and the serialisers are exported too:

```js
import { runEverything, summarise, toSarifString } from 'tenant-guard';
// or a subpath, if you only want the serialiser: 'tenant-guard/output/json'

const results = await runEverything(process.cwd());
const { failed, skipped } = summarise(results);
if (failed > 0) throw new Error(`${failed} guard(s) failed`);
if (skipped > 0) console.warn(`${skipped} guard(s) never ran`);
```
