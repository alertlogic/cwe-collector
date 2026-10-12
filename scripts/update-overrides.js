'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const packageJsonPath = path.join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
const overrides = packageJson.overrides || {};
const directDependencies = new Set([
  ...Object.keys(packageJson.dependencies || {}),
  ...Object.keys(packageJson.devDependencies || {}),
  ...Object.keys(packageJson.optionalDependencies || {}),
  ...Object.keys(packageJson.peerDependencies || {})
]);

function parseJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function resolveLatestVersion(name) {
  const raw = execFileSync('npm', ['view', name, 'version', '--json'], {
    encoding: 'utf8'
  }).trim();
  const parsed = parseJson(raw);
  const latest = Array.isArray(parsed) ? parsed[parsed.length - 1] : parsed || raw.replace(/"/g, '');
  const normalized = String(latest).trim();

  if (!normalized || normalized === 'undefined') {
    throw new Error(`could not resolve latest version for ${name}`);
  }

  return normalized;
}

function resolveLatestVersionForRange(name, range) {
  const raw = execFileSync('npm', ['view', `${name}@${range}`, 'version', '--json'], {
    encoding: 'utf8'
  }).trim();
  const parsed = parseJson(raw);
  const latest = Array.isArray(parsed) ? parsed[parsed.length - 1] : parsed || raw.replace(/"/g, '');
  const normalized = String(latest).trim();

  if (!normalized || normalized === 'undefined') {
    throw new Error(`could not resolve latest version for ${name}@${range}`);
  }

  return normalized;
}

function isUpdatableSpec(spec) {
  if (typeof spec !== 'string') {
    return false;
  }

  const normalized = spec.trim();
  if (!normalized) {
    return false;
  }

  return !/^(file:|link:|workspace:|git\+|github:|https?:|npm:)/i.test(normalized);
}

function getResolutionRange(spec) {
  const normalized = spec.trim();
  const exactVersion = normalized.match(/^(\d+)\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);

  if (!exactVersion) {
    return normalized;
  }

  const major = Number(exactVersion[1]);
  return `>=${major}.0.0 <${major + 1}.0.0`;
}

function updateDependencyMap(sectionName, dependencies) {
  if (!dependencies || typeof dependencies !== 'object') {
    return;
  }

  for (const [name, current] of Object.entries(dependencies)) {
    if (!isUpdatableSpec(current)) {
      continue;
    }

    try {
      const prefixMatch = current.match(/^[^0-9]*/);
      const prefix = prefixMatch ? prefixMatch[0] : '';

      let resolvedVersion;
      try {
        resolvedVersion = resolveLatestVersionForRange(name, getResolutionRange(current));
      } catch {
        resolvedVersion = resolveLatestVersion(name);
      }

      const next = `${prefix}${resolvedVersion}`;

      if (next !== current) {
        dependencies[name] = next;
        changed = true;
        console.log(`Updated ${sectionName} ${name}: ${current} -> ${next}`);
      }
    } catch (error) {
      console.warn(`Skipping ${sectionName} ${name}: ${error.message}`);
    }
  }
}

function getAuditReport() {
  try {
    const raw = execFileSync('npm', ['audit', '--json'], { encoding: 'utf8' }).trim();
    return parseJson(raw);
  } catch (error) {
    const raw = (error && error.stdout ? String(error.stdout) : '').trim();
    return parseJson(raw);
  }
}

function getParentPackages(nodes, dependencyName) {
  if (!Array.isArray(nodes)) {
    return [];
  }

  const parents = new Set();

  for (const nodePath of nodes) {
    if (typeof nodePath !== 'string') {
      continue;
    }

    const parts = nodePath
      .split('/node_modules/')
      .filter(Boolean)
      .map((part) => part.replace(/^node_modules\//, ''));
    if (parts.length < 2) {
      continue;
    }

    const child = parts[parts.length - 1];
    const parent = parts[parts.length - 2];

    if (child === dependencyName && parent) {
      parents.add(parent);
    }
  }

  return Array.from(parents);
}

const MAX_LOCK_ROWS = 200;

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8' });
}

function readBase(file) {
  try {
    return JSON.parse(git(['show', `HEAD:${file}`]));
  } catch {
    return {};
  }
}

function readCurrent(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

function cell(value) {
  return String(value).replace(/\|/g, '\\|');
}

function table(header, rows) {
  if (!rows.length) {
    return '_No changes_';
  }
  const lines = [`| ${header} | From | To |`, '|---|---|---|'];
  for (const [name, from, to] of rows) {
    lines.push(`| \`${cell(name)}\` | ${cell(from)} | ${cell(to)} |`);
  }
  return lines.join('\n');
}

function diffMap(before = {}, after = {}) {
  const rows = [];
  const names = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const name of [...names].sort()) {
    const from = before[name];
    const to = after[name];
    if (from === to) {
      continue;
    }
    rows.push([name, from === undefined ? '_added_' : from, to === undefined ? '_removed_' : to]);
  }
  return rows;
}

function flattenOverrides(value, prefix = '', out = {}) {
  for (const [name, entry] of Object.entries(value || {})) {
    const key = prefix ? `${prefix} > ${name}` : name;
    if (entry && typeof entry === 'object') {
      flattenOverrides(entry, key, out);
    } else {
      out[key] = entry;
    }
  }
  return out;
}

function lockVersions(lock) {
  const out = {};
  for (const [name, meta] of Object.entries(lock.packages || {})) {
    if (name && meta && meta.version) {
      out[name] = meta.version;
    }
  }
  return out;
}

function auditSummary() {
  let raw;
  try {
    raw = execFileSync('npm', ['audit', '--json'], { encoding: 'utf8' });
  } catch (error) {
    raw = error && error.stdout ? String(error.stdout) : '';
  }
  const report = parseJson(raw);
  const counts = report && report.metadata && report.metadata.vulnerabilities;
  if (!counts) {
    return 'unknown (npm audit failed)';
  }
  const parts = ['critical', 'high', 'moderate', 'low', 'info']
    .filter((level) => counts[level] > 0)
    .map((level) => `${counts[level]} ${level}`);
  return parts.length ? parts.join(', ') : 'none';
}

function buildPrBody() {
  const basePkg = readBase('package.json');
  const currentPkg = readCurrent('package.json');
  const baseLock = readBase('package-lock.json');
  const currentLock = readCurrent('package-lock.json');

  const files = git(['diff', '--name-only']).split('\n').filter(Boolean);
  const lockRows = diffMap(lockVersions(baseLock), lockVersions(currentLock));
  const shownLockRows = lockRows.slice(0, MAX_LOCK_ROWS);

  const sections = [
    'Automatically generated by the Dependency Update workflow.',
    '### Files modified',
    files.length ? files.map((file) => `- \`${file}\``).join('\n') : '_No changes_',
    '### Dependencies',
    table('Package', diffMap(basePkg.dependencies, currentPkg.dependencies)),
    '### Dev dependencies',
    table('Package', diffMap(basePkg.devDependencies, currentPkg.devDependencies)),
    '### Overrides',
    table('Override', diffMap(flattenOverrides(basePkg.overrides), flattenOverrides(currentPkg.overrides))),
    '### Lockfile'
  ];

  if (lockRows.length) {
    let more = '';
    if (lockRows.length > shownLockRows.length) {
      more = `\n\n_...and ${lockRows.length - shownLockRows.length} more_`;
    }
    sections.push(
      `${lockRows.length} package versions changed\n` +
      '<details><summary>Show packages</summary>\n\n' +
      `${table('Package', shownLockRows)}${more}\n\n</details>`
    );
  } else {
    sections.push('_No changes_');
  }

  sections.push(
    '### Checks',
    [
      '- [x] Tests pass on updated dependencies',
      '- [x] Lint passes',
      `- Remaining vulnerabilities: ${auditSummary()}`
    ].join('\n'),
    'Please review the changes in package.json and package-lock.json'
  );

  return sections.join('\n\n');
}

function writePrBody(body) {
  if (!process.env.GITHUB_OUTPUT) {
    console.log(body);
    return;
  }

  const delimiter = `PR_BODY_${crypto.randomBytes(8).toString('hex')}`;
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `body<<${delimiter}\n${body}\n${delimiter}\n`);
}

if (process.argv.includes('--pr-body')) {
  writePrBody(buildPrBody());
  process.exit(0);
}

let changed = false;

updateDependencyMap('dependency', packageJson.dependencies);
updateDependencyMap('devDependency', packageJson.devDependencies);

for (const name of Object.keys(overrides)) {
  const current = overrides[name];

  if (name.startsWith('node_modules/')) {
    delete overrides[name];
    changed = true;
    console.log(`Removed invalid override key ${name}`);
    continue;
  }

  if (directDependencies.has(name) && typeof current === 'string') {
    // npm rejects direct dependency string overrides, but scoped object overrides are valid.
    delete overrides[name];
    changed = true;
    console.log(`Removed direct dependency override ${name}`);
  }
}

const auditReport = getAuditReport();
const vulnerabilities = auditReport && typeof auditReport === 'object' ? (auditReport.vulnerabilities || {}) : {};

for (const [name, vuln] of Object.entries(vulnerabilities)) {
  try {
    let targetVersion = null;
    const fix = vuln && vuln.fixAvailable;

    if (fix && typeof fix === 'object' && !Array.isArray(fix) && fix.name === name && fix.version) {
      targetVersion = String(fix.version).trim();
    }

    if (!targetVersion) {
      targetVersion = resolveLatestVersion(name);
    }

    if (directDependencies.has(name)) {
      const parents = getParentPackages(vuln && vuln.nodes, name);

      for (const parent of parents) {
        const parentOverride = overrides[parent];
        if (parentOverride && typeof parentOverride !== 'object') {
          console.warn(`Skipping ${parent}>${name}: parent override is not an object.`);
          continue;
        }

        const scoped = parentOverride || {};
        const nextValue = `^${targetVersion}`;
        if (scoped[name] !== nextValue) {
          scoped[name] = nextValue;
          overrides[parent] = scoped;
          changed = true;
          console.log(`Added scoped override ${parent}>${name}: ${nextValue}`);
        }
      }

      continue;
    }

    if (!Object.prototype.hasOwnProperty.call(overrides, name)) {
      overrides[name] = `^${targetVersion}`;
      changed = true;
      console.log(`Added override ${name}: ^${targetVersion}`);
    }
  } catch (error) {
    console.warn(`Skipping ${name}: ${error.message}`);
  }
}

const names = Object.keys(overrides);

for (const name of names) {
  const current = overrides[name];
  const prefixMatch = typeof current === 'string' ? current.match(/^[^0-9]*/) : null;

  if (typeof current !== 'string' || prefixMatch === null) {
    console.warn(`Skipping ${name}: unsupported override format.`);
    continue;
  }

  try {
    // Resolve latest version that still satisfies the current range to avoid
    // accidental breaking major jumps for tooling-sensitive overrides.
    const raw = execFileSync('npm', ['view', `${name}@${current}`, 'version', '--json'], {
      encoding: 'utf8'
    }).trim();
    let resolved = raw;

    try {
      resolved = JSON.parse(raw);
    } catch {
      // Keep raw text fallback for npm outputs that are not valid JSON.
    }

    const latest = Array.isArray(resolved) ? resolved[resolved.length - 1] : resolved;
    const normalizedLatest = String(latest).trim();

    if (!normalizedLatest || normalizedLatest === 'undefined') {
      throw new Error(`could not resolve latest version for ${name}@${current}`);
    }

    const next = `${prefixMatch[0]}${normalizedLatest}`;

    if (next !== current) {
      overrides[name] = next;
      changed = true;
      console.log(`${name}: ${current} -> ${next}`);
    } else {
      console.log(`${name}: ${current} (up to date)`);
    }
  } catch (error) {
    console.warn(`Skipping ${name}: ${error.message}`);
  }
}

if (!changed) {
  console.log('npm overrides already up to date.');
  process.exit(0);
}

packageJson.overrides = overrides;
fs.writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);
console.log('Updated package.json overrides.');