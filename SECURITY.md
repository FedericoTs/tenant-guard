# Security policy

## What this tool is for

tenant-guard is a set of CI checks you run **against a database you own or are
authorized to test**. It is not a scanner, it does not discover targets, and it
has no network mode. The runtime guards require a Postgres connection string with
write access, supplied by you.

That last point is worth stating plainly, because it is sometimes misread: **the
tool grants no access it does not already require.** Anyone holding a
`DATABASE_URL` with write privileges can already read and modify the data by
typing `SELECT`. tenant-guard tells you what *your application's* roles can reach
through that connection. It cannot be pointed at a third party's database without
credentials that would make it redundant.

## Rules for running it

- **Only against a database you own or have written authorization to test.**
  Running security probes against systems you do not control is illegal in most
  jurisdictions, regardless of intent or outcome.
- **Never against production.** The runtime guards WRITE — `UPDATE`, `DELETE`,
  `INSERT`, and a temp table for the negative control. Every write is inside a
  transaction that is rolled back, and each probe is additionally wrapped in a
  savepoint, but a rollback is not a guarantee against every failure mode:
  triggers with external side effects still fire, sequences still advance, and a
  connection dropped mid-probe leaves the rollback to the server. Use a
  test/staging database seeded with synthetic data.
- **Do not run it against a shared or multi-customer staging database** you do
  not solely control, for the same reason.
- The static guards (`run`) read files on disk and touch no database at all. If
  you only want the file-level checks, that is the safe default and needs no
  connection string.

## Why the failure modes are published

`THREAT-MODEL.md` and the release notes describe, specifically, how each failure
mode works and how to reproduce it. That is deliberate, and it is the same
trade-off every security checklist makes — OWASP, the CWE list, every CVE
write-up, and Supabase's own advisor documentation.

The reasoning: every behaviour documented here is documented Postgres semantics.
Permissive policies OR. Referential integrity checks bypass RLS. `pg_temp` is
searched before every listed schema. An attacker who is going to use these
already knows them; a developer who needs to defend against them mostly does not,
because none of it is collected anywhere as a checklist. A finding described
vaguely enough to be useless to an attacker is also too vague to fix.

What is **not** published, and will not be: findings from anyone's specific
database. The reports that shaped this project are quoted for their mechanism,
never with an identifiable system, and the guards themselves are built so a
finding never carries the leaked data into a CI log — `column-exposure` probes
with `count()` precisely so the value is never fetched.

## Reporting a vulnerability

**In tenant-guard itself** — including a guard that reports a false green, which
is the failure that matters most here — open an issue at
https://github.com/FedericoTs/tenant-guard/issues. There is no embargo process; a
wrong result in a linter is not an exploitable vulnerability in anyone's running
system, and discussing it in the open is how it gets fixed.

If you believe you have found something in this repository that IS
exploitable — a probe that can be induced to run destructive SQL, an injection
through a config value — please report it privately first via a GitHub security
advisory on the repository rather than a public issue.

**In your own database, found by this tool** — that is between you and your
users. If it is a Supabase platform behaviour rather than your configuration,
Supabase has its own disclosure process.

## Supported versions

The latest published version only. This is a pre-1.0 project on a fast release
cadence; fixes go into the next release rather than being backported.
