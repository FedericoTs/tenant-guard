/**
 * Guard: Supabase Realtime tenant isolation.
 *
 * Realtime is a second, parallel way out of your database, and it is easy to
 * forget it exists once the REST surface looks locked down.
 *
 *   • **Broadcast / Presence** authorize channel access through **RLS on
 *     `realtime.messages`**. If that table has no RLS — or a permissive policy —
 *     any client can join any tenant's channel: read every payload flowing through
 *     it, and, because joining is a write, **publish into it**. Injecting events
 *     into another tenant's live channel is the realtime analogue of writing into
 *     their storage folder.
 *
 *   • **`postgres_changes`** streams row changes over a websocket, gated by the
 *     table's ordinary SELECT policy. That policy is already proven by `rls-proof`,
 *     so this guard does not re-litigate it — it reports which tenant tables are
 *     actually in the `supabase_realtime` publication, because a permissive policy
 *     on a *streaming* table is a live firehose rather than a request-at-a-time
 *     read, and people rarely know the list.
 *
 * The tenant lives in the **topic** (`org_A`, or `org_A:notifications`), not in a
 * column — the same shape as storage paths, so the same tenant-expression
 * approach applies. `split_part(topic, ':', 1)` covers both conventions: with no
 * separator it returns the whole topic.
 *
 * Skips cleanly when there is no `realtime` schema, so non-Supabase projects and
 * older Supabase versions are never punished for a surface they don't have.
 */
import {
  safeRole,
  buildBecomeTenant,
  isPermissionDenied,
  isRlsCheckViolation,
  applyClaimShortcut,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'realtime-isolation',
  title: 'Supabase Realtime tenant isolation (broadcast channels)',
  why: "Realtime is a second way out of the database. Broadcast and Presence authorize channels through RLS on realtime.messages — with no policy there, any client joins any tenant's channel, reads every payload on it, and can publish into it. The tenant lives in the topic, not a column, so a column-based check never sees it.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  claim: null,
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  // How a topic encodes its tenant: "org_A:notifications" -> separator ':'.
  // A topic that is just the tenant id works with the same expression.
  topicSeparator: ':',
  allowlist: [], // topic prefixes that are intentionally global (a status channel)
  sampleLimit: 3,
  probeWrites: true,
};

/** The topic tenant-guard would broadcast into; never committed. */
export const PROBE_EVENT = 'tenant-guard-probe';

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Is Realtime's broadcast table present at all? */
export function realtimePresentSql() {
  return {
    text: `select count(*)::int as n
             from pg_catalog.pg_class c
             join pg_catalog.pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'realtime' and c.relname = 'messages'`,
    values: [],
  };
}

/**
 * The tenant EXPRESSION over a channel topic. Like storage paths, Realtime has no
 * tenant column — the tenant is encoded in `topic`. With no separator present,
 * `split_part` returns the whole topic, so this covers both the `org_A` and
 * `org_A:notifications` conventions with one expression.
 */
export function topicTenantExpr(separator) {
  if (typeof separator !== 'string' || separator.length !== 1 || /['\\]/.test(separator)) {
    throw new Error(`unsafe topic separator: ${JSON.stringify(separator)} (expected a single character, not a quote or backslash)`);
  }
  return `split_part(topic, '${separator}', 1)`;
}

/** RLS status + policy count for realtime.messages (it may be partitioned). */
export function messagesRlsSql() {
  return {
    text: `select c.relrowsecurity as rls_enabled,
                  c.relkind as kind,
                  (select count(*) from pg_catalog.pg_policy p where p.polrelid = c.oid)::int as policy_count
             from pg_catalog.pg_class c
             join pg_catalog.pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'realtime' and c.relname = 'messages'`,
    values: [],
  };
}

/** Distinct tenants seen across channel topics (privileged — sees everything). */
export function distinctTopicTenantsSql(separator, limit) {
  const expr = topicTenantExpr(separator);
  return {
    text: `select distinct ${expr} as t
             from realtime.messages
            where topic is not null and topic <> ''
            order by 1
            limit $1`,
    limit,
  };
}

/** How many messages on a given tenant's channels the CURRENT session can see. */
export function topicMessageCountSql(separator) {
  const expr = topicTenantExpr(separator);
  return { text: `select count(*)::int as n from realtime.messages where ${expr} = $1` };
}

/** Broadcast probe: publish into a channel whose topic the CLIENT chooses. */
export function broadcastProbeSql() {
  return { text: `insert into realtime.messages (topic, extension, event) values ($1, 'broadcast', $2)` };
}

/** Tenant tables that are actually streaming through postgres_changes. */
export function publicationTablesSql(tenantColumns) {
  const text = `
    select pt.schemaname as schema,
           pt.tablename  as table,
           c.relrowsecurity as rls_enabled
    from pg_catalog.pg_publication_tables pt
    join pg_catalog.pg_class c on c.relname = pt.tablename
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace and n.nspname = pt.schemaname
    where pt.pubname = 'supabase_realtime'
      and exists (
        select 1 from pg_catalog.pg_attribute a
         where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
           and a.attname = any($1)
      )
    order by 1, 2`;
  return { text, values: [tenantColumns] };
}

/**
 * The remediation preamble both leak arms share.
 *
 * Measured, not assumed. In pglite (PG 18.3) with
 * `create policy p_all on realtime.messages for select using (true)` already present,
 * this guard's previous advice — a bare `CREATE POLICY ... USING (split_part(...) = ...)`
 * — applied verbatim left check() at ok:false with a byte-identical violation. The
 * statement that flipped it to ok:true was `drop policy p_all`. Same result on the write
 * arm starting from `for insert with check (true)`.
 *
 * The reason is that Postgres OR-combines PERMISSIVE policies: a new permissive policy
 * can only ever ADD access, never remove it. So advice that says nothing but CREATE
 * POLICY is advice that provably does not work on the codebase that triggered the
 * finding — every real project already has the loose policy, which is why the guard
 * fired in the first place.
 *
 * The DROP step is deliberately conditional ("whose <clause> does not pin ...") instead
 * of naming policies. A permissive policy can be correctly scoped through a helper
 * function that never mentions split_part, and telling someone to drop that would take
 * their app down — a strictly worse failure than leaving the leak one more day. The
 * enumeration query puts the real expressions in front of them so they decide.
 *
 * @param {string} cmd        'SELECT' | 'INSERT'
 * @param {string} clause     'USING' | 'WITH CHECK' — the clause that actually governs `cmd`
 * @param {string} topicExpr  the SAME expression the detection probe used
 */
function orCombinePreamble(cmd, clause, topicExpr) {
  return (
    `Adding a policy is NOT enough on its own. Postgres OR-combines permissive policies, so a permissive ${cmd} policy that does not pin the topic keeps granting every channel no matter what you add beside it — verified: with a \`${clause} (true)\` policy present, adding the policy below left exactly the same violation, and dropping the loose one was what fixed it.\n` +
    `  1. Read the policies already on the table, and what they actually allow:\n` +
    `       SELECT polname, polcmd, polpermissive,\n` +
    `              pg_get_expr(polqual, polrelid)      AS using_expr,\n` +
    `              pg_get_expr(polwithcheck, polrelid) AS check_expr\n` +
    `         FROM pg_policy WHERE polrelid = 'realtime.messages'::regclass;\n` +
    `  2. DROP POLICY "<name>" ON realtime.messages;   -- for each PERMISSIVE one covering ${cmd}\n` +
    `                                                  -- whose ${clause} does not pin ${topicExpr}\n` +
    `     Do NOT reach for AS RESTRICTIVE as the whole remedy: a restrictive policy only subtracts,\n` +
    `     so with no permissive grant beside it every client is locked out of every channel.\n` +
    `  3. Then add the scoped policy:`
  );
}

/**
 * Verdict for the broadcast surface.
 *
 * `separator` is threaded in so the RECOMMENDED predicate is built from the same
 * `topicTenantExpr()` the DETECTION probe used, and the two can no longer drift. It was
 * hardcoded to ':' while detection honoured the configured value: measured on
 * `{ topicSeparator: '-' }`, the guard derived tenant `org_A` from topic
 * `org_A-notifications`, then printed a policy whose `split_part(topic, ':', 1)`
 * evaluates to the whole string `org_A-notifications` — equal to no tenant id. Applying
 * it literally gave own-tenant rows visible 0 and other-tenant rows 0, where the correct
 * segment gives 1 and 0. An "isolating" policy that blanks the table is precisely what
 * gets a developer to loosen it again.
 *
 * @returns {{status:'leak'|'isolated'|'insufficient-data'|'no-access'|'no-policy', kind?:string, message?:string, fix?:string}}
 */
export function classifyRealtime({ rlsEnabled, policyCount, tenantCount, crossVisible, broadcastIntoOther, ownBroadcastWorked, noAccess, role = 'authenticated', separator = DEFAULTS.topicSeparator }) {
  // Throws on an unsafe separator exactly as the detection path does. check() validates
  // before any I/O, so by the time we get here this is belt-and-braces.
  const topicExpr = topicTenantExpr(separator);
  if (rlsEnabled === false) {
    return {
      status: 'leak',
      kind: 'read',
      message: `ROW LEVEL SECURITY is not enabled on realtime.messages — Broadcast and Presence authorize channel access through RLS on that table, so with none, any client can join ANY tenant's channel: read every payload flowing through it and publish into it`,
      fix:
        `Enable RLS and scope channel access by the topic's tenant segment:\n` +
        `        ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;\n` +
        `        CREATE POLICY tenant_channels ON realtime.messages FOR SELECT\n` +
        `          USING (${topicExpr} = <the caller's tenant>);\n` +
        `        CREATE POLICY tenant_publish ON realtime.messages FOR INSERT\n` +
        `          WITH CHECK (${topicExpr} = <the caller's tenant>);\n` +
        `      Then look at what ENABLE just switched on. Policies can sit on a table while RLS is\n` +
        `      off and go live the moment you enable it; any permissive one that does not pin\n` +
        `      ${topicExpr} is OR-ed in beside yours and re-opens every channel:\n` +
        `        SELECT polname, polcmd, polpermissive,\n` +
        `               pg_get_expr(polqual, polrelid)      AS using_expr,\n` +
        `               pg_get_expr(polwithcheck, polrelid) AS check_expr\n` +
        `          FROM pg_policy WHERE polrelid = 'realtime.messages'::regclass;`,
    };
  }
  if (policyCount === 0) {
    return { status: 'no-policy', message: `RLS is enabled on realtime.messages but there is NO policy — Postgres then denies everything, so Broadcast and Presence are effectively switched off rather than secured. Not a leak, but almost certainly not what was intended` };
  }
  if (noAccess) return { status: 'no-access', message: `"${role}" cannot read realtime.messages at all — no channel is exposed to it` };
  if (tenantCount < 2) return { status: 'insufficient-data', message: `channel topics reference ${tenantCount} tenant(s) — cannot prove cross-tenant isolation until two exist` };
  if (crossVisible > 0) {
    return {
      status: 'leak',
      kind: 'read',
      message: `a session acting as one tenant read ${crossVisible} message(s) on ANOTHER tenant's channel — the SELECT policy on realtime.messages does not pin the topic's tenant segment, so any client can subscribe to any tenant's broadcast and presence traffic`,
      fix:
        `Scope channel reads by the topic. ${orCombinePreamble('SELECT', 'USING', topicExpr)}\n` +
        `       CREATE POLICY tenant_channels ON realtime.messages FOR SELECT\n` +
        `         USING (${topicExpr} = <the caller's tenant>);`,
    };
  }
  if (broadcastIntoOther) {
    return {
      status: 'leak',
      kind: 'write',
      message: `a session acting as one tenant PUBLISHED into ANOTHER tenant's channel. The client chooses the topic when it joins, so unless the INSERT policy pins the tenant segment, any user can inject events into anyone's live channel — pushing fabricated updates straight into another tenant's running app. Reads being correctly scoped does not prevent this`,
      fix:
        `Pin the topic on publish as well as subscribe — INSERT is governed only by WITH CHECK. ` +
        `${orCombinePreamble('INSERT', 'WITH CHECK', topicExpr)}\n` +
        `       CREATE POLICY tenant_publish ON realtime.messages FOR INSERT\n` +
        `         WITH CHECK (${topicExpr} = <the caller's tenant>);`,
    };
  }
  return { status: 'isolated', ownBroadcastWorked };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);
  const sep = cfg.topicSeparator;
  topicTenantExpr(sep); // validate early, before any I/O

  const present = (await q(realtimePresentSql().text, []))[0];
  if (!present || present.n < 1) {
    return OK({ skipped: true, reason: 'no Supabase Realtime broadcast table (realtime.messages)', summary: 'skipped — no realtime schema' });
  }

  const violations = [];
  const notes = [];

  // postgres_changes: informational, not re-litigating the SELECT policy that
  // rls-proof already proves — just naming which tenant tables actually stream.
  try {
    const pt = publicationTablesSql(cfg.tenantColumns);
    const streaming = await q(pt.text, pt.values);
    if (streaming.length > 0) {
      const offNames = streaming.filter((r) => !(r.rls_enabled === true || r.rls_enabled === 't')).map((r) => `${r.schema}.${r.table}`);
      notes.push({
        where: 'supabase_realtime publication',
        message:
          `${streaming.length} tenant table(s) stream row changes over postgres_changes: ${streaming.slice(0, 4).map((r) => `${r.schema}.${r.table}`).join(', ')}${streaming.length > 4 ? `, +${streaming.length - 4} more` : ''}. ` +
          `Delivery is gated by each table's ordinary SELECT policy, which \`tenant-guard prove\` already proves — but on a streaming table a permissive policy is a live firehose to every subscriber rather than one request at a time, so these are the tables where that policy matters most.` +
          (offNames.length ? ` ${offNames.length} of them have RLS OFF (${offNames.slice(0, 3).join(', ')}) — every row of every tenant is being broadcast to every subscriber.` : ''),
      });
    }
  } catch (err) {
    notes.push({ where: 'supabase_realtime publication', message: `could not read the publication: ${err.message}` });
  }

  const rlsRow = (await q(messagesRlsSql().text, []))[0];
  const rlsEnabled = rlsRow ? (rlsRow.rls_enabled === true || rlsRow.rls_enabled === 't') : null;
  const policyCount = rlsRow ? Number(rlsRow.policy_count || 0) : 0;

  if (rlsEnabled === false) {
    const v = classifyRealtime({ rlsEnabled: false, role, separator: sep });
    violations.push({ where: 'realtime.messages', kind: v.kind, message: v.message, fix: v.fix });
    return { id: meta.id, ok: false, violations, notes, scanned: 1, summary: '1 realtime isolation issue (RLS is off on realtime.messages)' };
  }
  if (policyCount === 0) {
    // "RLS on with no policy denies everything" is true only for a role that is
    // SUBJECT to RLS. Returning here skipped the identity canary below, so a
    // configured role that bypasses RLS — a superuser, BYPASSRLS, or the table
    // owner — got a green verdict asserting a denial that does not apply to it.
    notes.push({ where: 'realtime.messages', message: classifyRealtime({ rlsEnabled: true, policyCount: 0, role, separator: sep }).message });
    notes.push({
      where: `role "${role}"`,
      message: `this verdict is read from the catalog, not probed. It holds only if "${role}" is subject to RLS — a superuser, a BYPASSRLS role, or the owner of realtime.messages reads it regardless of the policy count. Confirm the configured role is the one your clients actually connect as.`,
    });
    return { id: meta.id, ok: true, violations, notes, scanned: 1, summary: 'realtime.messages has RLS but no policy — broadcast is denied, not secured (see notes)' };
  }

  let scanned = 1;
  let proven = 0;

  await query('begin', []);
  try {
    const dt = distinctTopicTenantsSql(sep, cfg.sampleLimit);
    const tenants = (await q(dt.text, [cfg.sampleLimit])).map((r) => r.t).filter((t) => t && !skip.has(t));
    if (tenants.length < 2) {
      notes.push({ where: 'realtime.messages', message: classifyRealtime({ rlsEnabled: true, policyCount, tenantCount: tenants.length, role, separator: sep }).message });
      try { await query('rollback', []); } catch { /* ignore */ }
      return { id: meta.id, ok: true, violations, notes, scanned, summary: 'realtime.messages not proven — fewer than two tenants have channel traffic (see notes)' };
    }
    const [tenantA, tenantB] = tenants;

    // Negative control: the app role must actually be subject to RLS.
    let canaryReady = false;
    try {
      await query('create temp table tg_rt_canary (x int)', []);
      await query('insert into tg_rt_canary values (1)', []);
      await query('alter table tg_rt_canary enable row level security', []);
      await query('alter table tg_rt_canary force row level security', []);
      await query(`grant select on tg_rt_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(self-check)', message: `could not set up the RLS self-check canary (${err.message})` });
    }
    await query(`set local role ${role}`, []);
    if (canaryReady) {
      let seen = null;
      try { seen = (await q('select count(*)::int as n from tg_rt_canary', []))[0].n; } catch { /* denied => enforced */ }
      if (seen !== null && seen > 0) {
        try { await query('rollback', []); } catch { /* ignore */ }
        return {
          id: meta.id, ok: false, notes, scanned,
          violations: [{ where: `role "${role}"`, message: `identity self-check FAILED — "${role}" read a deny-all RLS table, so RLS is NOT enforced for it. Every "isolated" result would be a vacuous pass.`, fix: `Set the role to your non-superuser app role (e.g. "authenticated").` }],
          summary: 'identity switch is not enforcing RLS — refusing to report a vacuous pass',
        };
      }
    }

    let noAccess = false;
    let crossVisible = 0;
    let broadcastIntoOther = false;
    let ownBroadcastWorked = false;
    let probeError = null;
    try {
      for (const s of buildBecomeTenant(cfg.becomeTenant, tenantA)) await query(s.text, s.values);
      const cnt = topicMessageCountSql(sep);
      crossVisible = (await q(cnt.text, [tenantB]))[0].n;

      for (const s of buildBecomeTenant(cfg.becomeTenant, tenantB)) await query(s.text, s.values);
      crossVisible = Math.max(crossVisible, (await q(cnt.text, [tenantA]))[0].n);

      if (cfg.probeWrites !== false) {
        // Control arm first: if this session cannot publish into its OWN channel,
        // a refusal elsewhere proves nothing about tenant scoping.
        const bp = broadcastProbeSql();
        ownBroadcastWorked = await probeBroadcast(query, bp.text, [`${tenantB}${sep}tg`, PROBE_EVENT]);
        if (ownBroadcastWorked) {
          broadcastIntoOther = await probeBroadcast(query, bp.text, [`${tenantA}${sep}tg`, PROBE_EVENT]);
        }
      }
    } catch (err) {
      if (isPermissionDenied(err)) noAccess = true;
      else probeError = err.message;
    }
    await query('reset role', []);

    if (probeError) {
      notes.push({ where: 'realtime.messages', message: `could not probe — check role/becomeTenant: ${probeError}` });
    } else {
      const verdict = classifyRealtime({ rlsEnabled: true, policyCount, tenantCount: tenants.length, crossVisible, broadcastIntoOther, ownBroadcastWorked, noAccess, role, separator: sep });
      if (verdict.status === 'leak') {
        violations.push({ where: 'realtime.messages', kind: verdict.kind, message: verdict.message, fix: verdict.fix, crossVisible });
      } else if (verdict.status === 'isolated') {
        proven++;
        if (cfg.probeWrites !== false && !ownBroadcastWorked) {
          notes.push({ where: 'realtime.messages', message: `channel reads are proven isolated, but the publish probe was inconclusive — this session could not insert a message even on its own topic, so the write path was not exercised.` });
        }
      } else {
        notes.push({ where: 'realtime.messages', message: verdict.message });
      }
    }
  } finally {
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} realtime isolation issue(s)`
        : `${proven}/${scanned} realtime broadcast surface(s) proven isolated`,
  };
}

/** One publish attempt in a rolled-back savepoint. True = the message was created. */
async function probeBroadcast(query, text, values) {
  await query('savepoint tg_rt', []);
  try {
    const res = await query(text, values);
    const affected = res.rowCount ?? res.affectedRows ?? 0;
    await query('rollback to savepoint tg_rt', []);
    await query('release savepoint tg_rt', []);
    return affected > 0;
  } catch (err) {
    try { await query('rollback to savepoint tg_rt', []); await query('release savepoint tg_rt', []); } catch { /* ignore */ }
    if (isRlsCheckViolation(err) || isPermissionDenied(err)) return false;
    return false;
  }
}

/** CLI/programmatic entry: resolve a connection, import `pg`, run the check. */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL)`, summary: 'skipped — no database' });
  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({ skipped: true, reason: 'Postgres driver not installed — run `npm i -D pg`', summary: 'skipped — pg not installed' });
  }
  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    return await check({ query: (text, values) => client.query(text, values), config: cfg });
  } finally {
    await client.end();
  }
}
