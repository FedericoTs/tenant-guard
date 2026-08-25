import io

# ── config resolver ──────────────────────────────────────────────────
p = 'src/config.mjs'
s = io.open(p, encoding='utf-8').read()
old = "    'route-org-scoping': {"
new = """    'mcp-config': {
      cwd,
      configPaths: config.mcpConfig?.configPaths,
      allowlist: config.mcpConfig?.allowlist ?? [],
    },
    'route-org-scoping': {"""
assert old in s, 'route-org-scoping block not found'
s = s.replace(old, new, 1)
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('config.mjs: mcp-config resolver wired')

# ── index ────────────────────────────────────────────────────────────
p = 'src/index.mjs'
s = io.open(p, encoding='utf-8').read()
s = s.replace("import * as triggerVisibility from './guards/trigger-visibility.mjs';",
              "import * as triggerVisibility from './guards/trigger-visibility.mjs';\nimport * as mcpConfig from './guards/mcp-config.mjs';", 1)
assert 'mcpConfig' in s
s = s.replace("export const GUARDS = [migrationCollisions, definerGrants, routeOrgScoping, updatableViews];",
              "export const GUARDS = [migrationCollisions, definerGrants, routeOrgScoping, updatableViews, mcpConfig];", 1)
assert 'updatableViews, mcpConfig]' in s, 'GUARDS list not updated'
s = s.replace("mfaEnforcement, columnExposure, triggerVisibility };",
              "mfaEnforcement, columnExposure, triggerVisibility, mcpConfig };", 1)
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('index.mjs: mcp-config registered as a static guard')

# ── CLI listing ──────────────────────────────────────────────────────
p = 'bin/tenant-guard.mjs'
s = io.open(p, encoding='utf-8').read()
s = s.replace("  storageIsolation, columnExposure, triggerVisibility,",
              "  storageIsolation, columnExposure, triggerVisibility, mcpConfig,", 1)
if 'mcpConfig,' not in s:
    raise SystemExit('bin: ALL_GUARDS import list not updated')
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('bin: mcp-config in the guard listing')
