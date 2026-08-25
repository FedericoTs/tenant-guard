/**
 * MCP configs: credentials and privilege, read off disk.
 *
 * The calibration tests matter more than the catches. An `env` reference is the
 * CORRECT shape, and every well-configured project uses one — a guard that fires
 * on `"${SUPABASE_TOKEN}"` would hit exactly the people who got it right, which
 * is how a check gets switched off.
 *
 * Scope is deliberately narrow. This reads config. It says nothing about whether
 * an agent will misuse a legitimate tool, and nothing about prompt injection or
 * tool poisoning — a hostile server putting instructions in its tool
 * descriptions is a real risk and a different instrument. Pretending otherwise
 * would be claiming coverage that does not exist.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

import {
  isEnvReference,
  classifySecret,
  adminConnection,
  extractServers,
  supabaseWriteCapable,
  run,
} from '../src/guards/mcp-config.mjs';

function withConfigs(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-mcp-'));
  try {
    for (const [rel, body] of Object.entries(files)) {
      const abs = join(dir, rel);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, typeof body === 'string' ? body : JSON.stringify(body, null, 2));
    }
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A real-shaped service-role JWT: the payload decodes to role=service_role. */
function jwt(role) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.c2lnbmF0dXJl`;
}

// ── the correct shapes must never fire ───────────────────────────────

test('an env reference is the correct shape, in every spelling', () => {
  for (const v of ['${SUPABASE_TOKEN}', '$SUPABASE_TOKEN', 'env:SUPABASE_TOKEN', '${env:TOKEN}', '${input:token}', '']) {
    assert.equal(isEnvReference(v), true, v);
  }
  assert.equal(isEnvReference('sbp_abcdef0123456789abcdef'), false);
});

test('classifySecret returns null for anything referenced', () => {
  assert.equal(classifySecret('${SUPABASE_SERVICE_ROLE_KEY}'), null);
  assert.equal(classifySecret('env:DATABASE_URL'), null);
  assert.equal(classifySecret('postgres://app:${PGPASSWORD}@db.example.com/postgres'), null);
});

test('…and for ordinary config values', () => {
  assert.equal(classifySecret('npx'), null);
  assert.equal(classifySecret('--read-only'), null);
  assert.equal(classifySecret('https://abc.supabase.co'), null);
});

// ── the catches ──────────────────────────────────────────────────────

test('a service-role JWT is identified BY ITS PAYLOAD, not by guesswork', () => {
  const s = classifySecret(jwt('service_role'));
  assert.equal(s.kind, 'service-role-key');
  assert.match(s.what, /bypasses RLS/);
});

test('an anon key is told apart from a service-role key', () => {
  assert.equal(classifySecret(jwt('anon')).kind, 'anon-key');
});

test('a Supabase PAT and secret key are recognised', () => {
  assert.equal(classifySecret('sbp_0123456789abcdef0123456789abcdef').kind, 'supabase-pat');
  assert.equal(classifySecret('sb_secret_0123456789abcdef').kind, 'supabase-secret-key');
});

test('a Postgres URL with an inline password is a credential', () => {
  const s = classifySecret('postgres://app_user:hunter2@db.example.com:5432/app');
  assert.equal(s.kind, 'postgres-url-password');
  assert.match(s.what, /app_user/);
});

test('adminConnection names the account, and ignores a scoped one', () => {
  assert.equal(adminConnection('postgres://postgres:x@db/app').user, 'postgres');
  assert.equal(adminConnection('postgres://supabase_admin:x@db/app').user, 'supabase_admin');
  assert.equal(adminConnection('postgres://mcp_reader:x@db/app'), null);
});

test('extractServers reads every client dialect', () => {
  assert.equal(extractServers({ mcpServers: { a: {} } }).length, 1);
  assert.equal(extractServers({ servers: { b: {} } }).length, 1);
  assert.equal(extractServers({ mcp: { servers: { c: {} } } }).length, 1);
  assert.equal(extractServers({}).length, 0);
});

test('supabaseWriteCapable keys off --read-only, not the server name alone', () => {
  assert.equal(supabaseWriteCapable({ name: 'supabase', cfg: { args: ['-y', '@supabase/mcp-server-supabase'] } }), true);
  assert.equal(supabaseWriteCapable({ name: 'supabase', cfg: { args: ['-y', '@supabase/mcp-server-supabase', '--read-only'] } }), false);
  assert.equal(supabaseWriteCapable({ name: 'filesystem', cfg: { args: ['-y', '@modelcontextprotocol/server-filesystem'] } }), false);
});

// ── end to end ───────────────────────────────────────────────────────

test('a WELL-configured project reports nothing', () => {
  withConfigs({
    '.mcp.json': {
      mcpServers: {
        supabase: {
          command: 'npx',
          args: ['-y', '@supabase/mcp-server-supabase', '--read-only'],
          env: { SUPABASE_ACCESS_TOKEN: '${SUPABASE_ACCESS_TOKEN}' },
        },
      },
    },
  }, (cwd) => {
    const res = run({ cwd });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.equal(res.notes.length, 0, 'a correct config should be silent, not chatty');
  });
});

test('an inline service-role key fails the build', () => {
  withConfigs({
    '.mcp.json': { mcpServers: { supabase: { command: 'npx', env: { SUPABASE_SERVICE_ROLE_KEY: jwt('service_role') } } } },
  }, (cwd) => {
    const res = run({ cwd });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations[0].kind, 'mcp-inline-credential');
    assert.match(res.violations[0].message, /bypasses RLS/);
    assert.match(res.violations[0].fix, /ROTATE/);
  });
});

test('an admin Postgres connection is reported, and points at the proof', () => {
  withConfigs({
    '.cursor/mcp.json': { mcpServers: { pg: { command: 'npx', args: ['-y', 'pg-mcp', 'postgres://postgres:secret@db.example.com/app'] } } },
  }, (cwd) => {
    const res = run({ cwd });
    const v = res.violations.find((x) => x.kind === 'mcp-admin-connection');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /exempt from their RLS/);
    assert.match(v.fix, /tenant-guard prove/);
  });
});

test('a write-capable Supabase server is a NOTE, not a failure', () => {
  // A write-capable server is a legitimate choice for a local branch, and the
  // config cannot tell which project it points at.
  withConfigs({
    '.mcp.json': { mcpServers: { supabase: { command: 'npx', args: ['-y', '@supabase/mcp-server-supabase'], env: { SUPABASE_ACCESS_TOKEN: '${TOKEN}' } } } },
  }, (cwd) => {
    const res = run({ cwd });
    assert.equal(res.ok, true);
    assert.ok(res.notes.some((n) => /--read-only/.test(n.message)));
  });
});

test('an anon key is a note — public by design, still committed', () => {
  withConfigs({ '.mcp.json': { mcpServers: { x: { env: { KEY: jwt('anon') } } } } }, (cwd) => {
    const res = run({ cwd });
    assert.equal(res.ok, true);
    assert.ok(res.notes.some((n) => /anon key/.test(n.message)));
  });
});

test('no MCP config at all is a SKIP, not a pass', () => {
  withConfigs({ 'package.json': { name: 'x' } }, (cwd) => {
    const res = run({ cwd });
    assert.equal(res.skipped, true);
    assert.match(res.reason, /no MCP config/);
  });
});

test('an unparseable config is a note saying it was NOT examined', () => {
  withConfigs({ '.mcp.json': '{ this is not json' }, (cwd) => {
    const res = run({ cwd });
    assert.ok(res.notes.some((n) => /NOT examined/.test(n.message)));
  });
});

test('the allowlist silences a path or a server name', () => {
  const files = { '.mcp.json': { mcpServers: { supabase: { env: { KEY: jwt('service_role') } } } } };
  withConfigs(files, (cwd) => {
    assert.equal(run({ cwd }).ok, false);
    assert.equal(run({ cwd, allowlist: ['supabase'] }).ok, true);
  });
});
