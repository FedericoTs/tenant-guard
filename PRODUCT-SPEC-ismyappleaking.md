# ismyappleaking — product & feature spec ($50k/yr platform vision)

> **How to use this file.** It is a build brief you can hand to a coding agent,
> and a product doc a human can read top to bottom. It describes the platform
> that tenant-guard grows into: a leak-diagnosis product that starts as a
> zero-friction one-shot scan and expands into connected deep analysis and
> continuous monitoring. Written from the perspective of a customer paying
> **$50,000/year** — every feature below is something that buyer would expect to
> exist and would churn if it didn't. Grounded in real findings from the
> MonkeyTravel run (2026-08): email exposure, an anon-writable view, definer
> grants, SPF/MX gaps, a 10-month-broken password reset, an account-deletion FK
> bug, i18n key leaks. Those are the receipts that each capability matters.
>
> Non-negotiable principles are in §8 — read them first; they are what separate
> this from every "scanner you run once and ignore."

---

## 0. Positioning & the buyer

- **One line:** "Point us at your app. We prove — with reproductions, not
  guesses — exactly what an attacker or a curious user can read, write, or
  break, and we block it from ever shipping again."
- **The $50k buyer:** a Series A–C startup or a mid-market eng org on
  Supabase/Postgres + Next.js/Vercel (and neighbours: Prisma, Drizzle, Rails,
  Firebase), 5–50 engineers, shipping AI-generated code fast, with real PII and
  no dedicated AppSec team. They buy because one leak is an existential,
  headline-grade event and they have no one whose job is to prevent it.
- **Why now:** AI code generators reproduce the same isolation bugs at scale
  (CVE-2025-48757: 303 endpoints across 170 projects with anon-readable tables).
  The buyer ships faster than they can review.
- **The wedge → land → expand motion:**
  1. **One-shot, anonymous, free** — paste a URL, get a graded report with a few
     *confirmed* leaks in 60 seconds. No signup, no code. This is the demo that
     sells itself.
  2. **Connected** — sign up, connect repo + a safe DB + deploy target; get the
     full static+runtime suite and CI enforcement.
  3. **Continuous + enterprise** — monitoring, trends, compliance evidence,
     SSO/RBAC, custom policy, self-hosted. This is the $50k tier.

---

## 1. Tier / journey structure

| Tier | Access | What it does | Price shape |
|---|---|---|---|
| **Scan** (free) | URL only, no auth, client-safe | One-shot external diagnosis, graded, a few confirmed findings, shareable report | Free / lead-gen |
| **Connect** (team) | GitHub App + read-only DB/branch + Vercel | Full static+runtime guards, CI PR-blocking, full domain coverage, fix PRs | per-repo / per-seat |
| **Continuous** (enterprise, $50k) | + SSO, org, data controls | Monitoring, drift, trends, benchmarks, compliance evidence, custom policy, SLA, self-hosted option | annual contract |

The report *shape* is identical across tiers (same finding model, §6) so the free
scan is a genuine taste of the paid product, not a teaser.

---

## 2. Phase 1 — the one-shot, anonymous, client-side scan (the front door)

**Constraint:** URL only. No code, no credentials, no signup. Everything here is
observable from outside by anyone — which is exactly why it is scary and
persuasive. Runs in seconds; a chunk can run **client-side in the browser** so
the user watches it happen against their own app.

**What it inspects, unauthenticated:**

- **Client-bundle secret scrape.** Fetch and parse the JS bundle
  (`/_next/static/**`, source maps if present). Grep for live credential shapes:
  `service_role` JWTs, `sk_live_`, Google/AWS keys, private tokens. *A
  service-role key in the bundle is game-over and instantly demonstrable.*
- **Supabase/PostgREST live probe (the killer demo).** Extract the public
  `anon` key from the bundle, hit `/rest/v1/` (OpenAPI introspection) to
  enumerate tables and RPCs, then **prove** anon reachability:
  `?select=*&limit=1` per table, `?select=<sensitive-column>` for
  email/token/phone, and **anon write probes on views** (the MonkeyTravel
  `public_profiles` class — auto-updatable view write-through). Report the
  literal request/response: *"with the key in your bundle, this returns 447
  email addresses."*
- **Sensitive-column exposure.** Flag anon-readable columns matching a
  dictionary (`email`, `phone`, `token`, `secret`, `hash`, `password`, `ssn`,
  `stripe_*`, `*_key`, `ip`, `dob`, `address`).
- **Endpoint/asset exposure.** `/.git/`, `/.env`, exposed source maps, backup
  files, admin routes, debug endpoints, directory listings.
- **HTTP posture.** CSP (and CSP bypass smells), HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, permissions-policy, cookie flags
  (Secure/HttpOnly/SameSite), CORS (wildcard-with-credentials).
- **Email spoofability (DNS only).** SPF (and `-all` vs `~all`), DKIM presence,
  DMARC policy + pct, and **MX presence** (MonkeyTravel's `support@` bounced —
  a real trust + deliverability leak).
- **Auth-flow smells, black-box.** Account enumeration on login/reset (different
  responses for known vs unknown email), OAuth redirect handling, password-reset
  link shape (the fragment-trap class), missing rate-limits on auth endpoints.
- **IDOR surface (black-box).** Sequential/guessable IDs in URLs and API
  responses; probe `id±1` on public objects.
- **Third-party & privacy beacons.** Trackers loaded, PII in query strings/URLs,
  data sent to analytics before consent, cookie-consent enforcement.
- **Output:** a **grade (A–F)**, a headline count ("3 confirmed leaks, 6
  hardening gaps"), each confirmed finding with a copy-pasteable reproduction and
  the exact fix, and a **shareable, watermarked report URL**. One click → "fix
  these automatically" → signup wall.

**Why client-side matters:** the user sees the scan run against *their* app in
*their* browser with *their* key — no "trust us, upload your code" friction, and
nothing sensitive leaves their machine for the free tier. It is the trust
on-ramp to the connected tier.

---

## 3. Phase 2 — connected deep analysis (post-signup)

The user connects three surfaces, each optional but each unlocking depth:

- **GitHub App (read-only)** → static guards on the actual migrations + routes +
  source. This is the tenant-guard core: RLS, grants, definers, views,
  cross-tenant FKs, route scoping, migration hygiene, updatable-view
  write-through, column exposure, search_path, default-privilege drift.
- **A safe database (branch or read-only replica)** → **runtime proofs**. Never
  production; the platform provisions/uses a Supabase branch or a
  schema-restored ephemeral DB and runs write-probes **inside rolled-back
  transactions**. This is where the highest-severity, hardest-to-fake findings
  live (the MonkeyTravel view-write hole was only provable at runtime).
- **Deploy target (Vercel/host)** → runtime error correlation, env-var audit
  (secrets not in `NEXT_PUBLIC_*`), header verification on the live deploy,
  preview-deploy scanning.

**Full domain coverage (the 12 domains), each producing typed findings:**

1. Multi-tenant / object-level authz (tenant-guard core).
2. Secrets & config exposure (bundle, git history, env, source maps).
3. Excessive data exposure + mass-assignment (payload > UI; settable
   `is_admin`/balance/tier fields).
4. Auth & session (reset flows, cookie flags, enumeration, OAuth redirects, MFA,
   session lifecycle, auth rate-limits).
5. Email authentication (SPF/DKIM/DMARC/MX, link safety, data-in-email).
6. HTTP posture (headers, CORS, clickjacking).
7. Injection (XSS, SQLi in raw RPCs, **SSRF** in proxies/fetchers, path
   traversal).
8. AI-specific (prompt-injection exfiltration, PII to model providers,
   unvalidated model output, cost-DoS on generation endpoints).
9. Abuse / rate-limiting / cost (anti-automation on paid endpoints, bot
   protection, quota enforcement).
10. PII & GDPR lifecycle (deletion completeness — the FK class, export,
    retention, PII in logs/Sentry/analytics, consent enforcement).
11. Dependencies & supply chain (`audit`, leaked third-party keys, unsigned
    webhooks, SRI).
12. Client-side trust (localStorage secrets, client-only authz, flag exposure).

**Auto-fix, done safely.** For each finding, offer a **fix PR** (the REVOKE, the
column grant, the header, the policy). Fixes must be **safe to apply blind** —
cross-checked against dependencies (the `user_is_trip_owner` lesson: never
recommend a REVOKE that breaks an RLS policy). Every fix PR carries the
reproduction and a rollback note.

---

## 4. Phase 3 — continuous monitoring & advanced analytics ($50k tier)

- **CI enforcement.** Static guards block every PR (SARIF → Security tab + diff
  annotations). Runtime guards run against the PR's branch DB. A merge cannot
  reintroduce a fixed class.
- **Deploy-triggered re-scan.** Every production deploy re-runs the external +
  connected suite; a regression pages the team before users find it.
- **Drift detection.** Schema/policy/grant drift the migrations don't declare
  (someone ran SQL in the dashboard — exactly how the MonkeyTravel `public.users`
  grants drifted). Diff *effective* state vs *declared* state continuously.
- **Posture score over time.** One number, trended. Per-domain sub-scores.
  "Auth: A, Data-exposure: C, trending down since deploy #4412."
- **Benchmarking.** Anonymized percentile vs comparable apps ("your anon
  attack-surface is wider than 82% of Supabase apps your size"). Powerful for
  the exec buyer.
- **Alerting & routing.** Slack/Teams/PagerDuty/email; severity-routed; Jira/
  Linear ticket creation with the reproduction attached; auto-assign by
  CODEOWNERS.
- **Live attack-surface inventory.** A living map: every anon-reachable table,
  RPC, route, bucket, channel — searchable, diffable release-over-release. "What
  can an unauthenticated request touch, right now?"
- **Time-to-remediate analytics.** MTTR per severity, aging findings, who fixed
  what — the metrics an eng leader reports upward.

---

## 5. Cross-cutting: the report & finding model

- **Every finding is a typed object:** id, domain, severity, **confirmed-vs-
  hardening**, affected object, reproduction (literal request/response or SQL,
  rolled-back), exact fix, fix-PR link, first-seen, status, owner, allowlist
  path with required justification.
- **Confirmed vs hardening is a hard split**, never blurred. "Anon deleted a
  user row (confirmed)" and "add HSTS (hardening)" are different universes.
- **Positive confirmation is first-class.** The report shows the **green**: "we
  verified anon cannot read email / cannot write through views / cannot execute
  these RPCs." Buyers renew on the green as much as the red.
- **Silent-failure surfacing.** A dedicated lens: "these are failing *quietly*"
  — RLS→0-rows, embed→null, swallowed errors, emails rendering as raw i18n keys.
  This is the platform's signature insight and nobody else frames it.
- **Machine-everywhere:** `--json`, `--sarif`, API, webhooks; identical exit
  semantics across formats.

---

## 6. Enterprise / trust / compliance — what actually justifies $50k

You are handling the customer's secrets and probing their data. Trust *is* the
product at this tier.

- **Data handling:** read-only everywhere; runtime writes only in rolled-back
  txns against non-prod; **self-hosted / VPC / BYO-runner** option so nothing
  leaves their perimeter; configurable data residency; zero-retention mode;
  every scan artifact encrypted and access-logged.
- **Access:** SSO/SAML, SCIM provisioning, RBAC (who can see findings vs fixes vs
  raw repro), multi-org / multi-project, full audit log of who viewed what.
- **Compliance evidence:** map findings to SOC 2 / ISO 27001 / GDPR / OWASP
  ASVS controls; export auditor-ready reports; "continuous control monitoring"
  framing for the compliance buyer.
- **Custom policy-as-code:** the customer writes their own guards/allowlist
  policy (per-repo tenancy model, sensitive-column dictionary, severity
  overrides) and version-controls it.
- **Service:** onboarding, a named CSM, an SLA on scan latency and support
  response, a human-triage escalation for disputed false positives, priority
  custom-guard development.
- **Integrations breadth:** GitHub/GitLab/Bitbucket, Vercel/Netlify/AWS,
  Supabase/Neon/RDS/PlanetScale, Slack/Teams/PagerDuty, Jira/Linear, SIEM export.

---

## 7. Coverage matrix (domain × how detected × access needed)

| Domain | One-shot (URL) | Static (repo) | Runtime (DB) |
|---|---|---|---|
| Tenant/object authz | anon probes | RLS/grants/policies | rolled-back proofs |
| Secrets exposure | bundle scrape | git history/env | — |
| Excessive exposure / mass-assign | response shape | payload vs schema | write probes |
| Auth & session | black-box smells | flow code | seeded flows |
| Email auth | DNS | template code | send-sandbox |
| HTTP posture | live headers | config | — |
| Injection / SSRF | fuzz surface | sink analysis | payloads (sandbox) |
| AI-specific | prompt probes | data-flow to LLM | injection sandbox |
| Abuse / cost | rate tests | endpoint cost | load probe |
| PII / GDPR | trackers/consent | deletion/export code | deletion proof |
| Dependencies | — | lockfile/audit | — |
| Client trust | storage/flags | client authz | — |

The matrix is the sales asset too: it shows a buyer exactly what each connection
level unlocks, i.e. why they upgrade.

---

## 8. Non-negotiable product principles (from the MonkeyTravel run — read first)

1. **Proof, not possibility.** Every confirmed finding reproduced against the
   real target. Guesses are labelled as guesses. This is the moat.
2. **Fixes safe to apply blind.** Never recommend a change that breaks the app
   (the RLS-predicate REVOKE that caused a 42501 outage). Cross-check
   dependencies before advising.
3. **Never write to production.** Runtime probes are rolled-back and non-prod,
   always, no exceptions, stated loudly.
4. **Confirmed ≠ hardening.** Two separate ladders; never conflated.
5. **Show the green.** Positive confirmation is a deliverable, not an absence.
6. **Make silent failures loud.** The unifying insight; seeded positive AND
   negative controls so both leak *and* over-restriction fail the check.
7. **Own the data trust story** before selling the enterprise tier.

---

## 9. Suggested build sequence

1. Harden the static core (the improvement brief P0/P1: view write-through,
   column exposure, effective-grant drift, RLS-predicate safety, per-user
   tenancy autodetect). *In tenant-guard's existing lane, ships now.*
2. Build the **one-shot anonymous scanner** (Phase 2 here) as the standalone
   growth product — bundle scrape + anon PostgREST probe + headers + DNS. This is
   the demo that acquires.
3. GitHub App + branch-DB runtime orchestration (Phase 3) → CI enforcement.
4. Continuous monitoring, drift, trends, benchmarks.
5. Enterprise: SSO/RBAC, self-hosted, compliance evidence, custom policy.

---

Environment note: distilled from the tenant-guard run against MonkeyTravel
(Supabase + PostgREST + Next.js/Vercel, per-user tenancy), 2026-08.
