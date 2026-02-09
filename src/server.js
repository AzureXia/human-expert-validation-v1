import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { parse } from 'csv-parse/sync';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BUNDLED_DATA_DIR = path.join(__dirname, '..', 'data');
const RUNTIME_DATA_DIR = process.env.RUNTIME_DATA_DIR
  ? path.resolve(process.env.RUNTIME_DATA_DIR)
  : BUNDLED_DATA_DIR;
// If a runtime volume is configured (Railway), default to reading source CSVs from it.
// Local dev still defaults to the bundled ./data folder unless SOURCE_DATA_DIR is explicitly set.
const SOURCE_DATA_DIR = process.env.SOURCE_DATA_DIR
  ? path.resolve(process.env.SOURCE_DATA_DIR)
  : (process.env.RUNTIME_DATA_DIR ? RUNTIME_DATA_DIR : BUNDLED_DATA_DIR);
const RESPONSE_PATH = path.join(RUNTIME_DATA_DIR, 'responses.json');
const SUMMARY_CACHE_PATH = path.join(RUNTIME_DATA_DIR, 'extracted_summaries.json');
const SUMMARY_CACHE_VERSION = 2;
const USERS_PATH = process.env.AUTH_USERS_FILE
  ? path.resolve(process.env.AUTH_USERS_FILE)
  : path.join(RUNTIME_DATA_DIR, 'users.json');

if (!fs.existsSync(RUNTIME_DATA_DIR)) {
  fs.mkdirSync(RUNTIME_DATA_DIR, { recursive: true });
}
if (!fs.existsSync(SOURCE_DATA_DIR)) {
  fs.mkdirSync(SOURCE_DATA_DIR, { recursive: true });
}

const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'hev_session';
const AUTH_SESSION_DAYS = Math.max(parseInt(process.env.AUTH_SESSION_DAYS || '14', 10) || 14, 1);
const AUTH_COOKIE_SECURE = process.env.AUTH_COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';
const AUTH_SECRET = process.env.AUTH_SECRET || '';
const AUTH_BYPASS = process.env.AUTH_BYPASS === '1';

function loadCsv(file) {
  const full = path.join(SOURCE_DATA_DIR, file);
  const content = fs.readFileSync(full, 'utf8');
  return parse(content, { columns: true, skip_empty_lines: true });
}

function parseCookieHeader(cookieHeader = '') {
  const out = {};
  cookieHeader.split(';').forEach(part => {
    const [rawKey, ...rest] = part.split('=');
    if (!rawKey) return;
    const key = rawKey.trim();
    const value = rest.join('=').trim();
    if (!key) return;
    try {
      out[key] = decodeURIComponent(value || '');
    } catch {
      out[key] = value || '';
    }
  });
  return out;
}

function buildCookie(name, value, maxAgeSeconds) {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax'
  ];
  if (AUTH_COOKIE_SECURE) attrs.push('Secure');
  if (typeof maxAgeSeconds === 'number') attrs.push(`Max-Age=${Math.max(Math.floor(maxAgeSeconds), 0)}`);
  return attrs.join('; ');
}

function normalizeUsername(username = '') {
  return String(username).trim().toLowerCase();
}

function pbkdf2Hash(password, iterations = 210000) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');
  return `pbkdf2$sha256$${iterations}$${salt}$${hash}`;
}

function verifyPassword(password = '', stored = '') {
  if (!stored) return false;
  if (stored.startsWith('pbkdf2$')) {
    const parts = stored.split('$');
    if (parts.length !== 5) return false;
    const algorithm = parts[1];
    const iterations = Number(parts[2]);
    const salt = parts[3];
    const expected = parts[4];
    if (algorithm !== 'sha256' || !Number.isFinite(iterations) || iterations < 1000 || !salt || !expected) {
      return false;
    }
    const digest = crypto.pbkdf2Sync(password, salt, iterations, 32, algorithm).toString('hex');
    const digestBuffer = Buffer.from(digest);
    const expectedBuffer = Buffer.from(expected);
    if (digestBuffer.length !== expectedBuffer.length) return false;
    return crypto.timingSafeEqual(digestBuffer, expectedBuffer);
  }
  const left = Buffer.from(String(password));
  const right = Buffer.from(String(stored));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

const AUTH_ADMIN_USERS = new Set((process.env.AUTH_ADMIN_USERS || '')
  .split(',')
  .map(normalizeUsername)
  .filter(Boolean));
const AUTH_BOOTSTRAP_ADMIN_USERNAME = process.env.AUTH_BOOTSTRAP_ADMIN_USERNAME || 'admin';
const AUTH_BOOTSTRAP_ADMIN_DISPLAY_NAME = process.env.AUTH_BOOTSTRAP_ADMIN_DISPLAY_NAME || 'Admin';
const AUTH_BOOTSTRAP_ADMIN_PASSWORD = process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD || '';

function normalizeRole(rawRole = '') {
  const role = String(rawRole || '').trim().toLowerCase();
  return role === 'admin' ? 'admin' : 'expert';
}

function normalizeUserRecord(raw = {}) {
  const username = normalizeUsername(raw.username);
  if (!username) return null;
  const passwordHash = String(raw.passwordHash || '').trim();
  const password = String(raw.password || '').trim();
  if (!passwordHash && !password) return null;
  const role = AUTH_ADMIN_USERS.has(username) ? 'admin' : normalizeRole(raw.role);
  return {
    username,
    displayName: String(raw.displayName || username).trim() || username,
    passwordHash: passwordHash || pbkdf2Hash(password),
    role
  };
}

function loadUsersFromFile() {
  if (!fs.existsSync(USERS_PATH)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn('users.json could not be parsed', err);
    return [];
  }
}

function saveUsersToFile(list) {
  fs.writeFileSync(USERS_PATH, JSON.stringify(list, null, 2), 'utf8');
}

function ensureBootstrapAdminUser() {
  // Only bootstrap when env users are not set and file-based users are empty.
  if (process.env.AUTH_USERS_JSON || process.env.AUTH_USERS) return false;
  const existing = loadUsersFromFile();
  if (existing.length > 0) return false;
  if (!AUTH_BOOTSTRAP_ADMIN_PASSWORD) return false;

  const record = normalizeUserRecord({
    username: AUTH_BOOTSTRAP_ADMIN_USERNAME,
    displayName: AUTH_BOOTSTRAP_ADMIN_DISPLAY_NAME,
    password: AUTH_BOOTSTRAP_ADMIN_PASSWORD,
    role: 'admin'
  });
  if (!record) return false;
  saveUsersToFile([record]);
  return true;
}

function loadAuthUsers() {
  let rawUsers = [];
  let source = 'none';
  const rawJson = process.env.AUTH_USERS_JSON;
  const rawInline = process.env.AUTH_USERS;
  if (rawJson) {
    try {
      const parsed = JSON.parse(rawJson);
      if (Array.isArray(parsed)) rawUsers = parsed;
      source = 'env';
    } catch (err) {
      console.warn('AUTH_USERS_JSON could not be parsed', err);
    }
  } else if (rawInline) {
    rawUsers = rawInline
      .split(',')
      .map(part => part.trim())
      .filter(Boolean)
      .map(pair => {
        const idx = pair.indexOf(':');
        if (idx === -1) return { username: pair, password: '' };
        return {
          username: pair.slice(0, idx).trim(),
          password: pair.slice(idx + 1).trim()
        };
      });
    source = 'env';
  } else {
    rawUsers = loadUsersFromFile();
    if (rawUsers.length > 0) source = 'file';
  }

  const users = new Map();
  rawUsers.forEach(entry => {
    const normalized = normalizeUserRecord(entry);
    if (!normalized) return;
    users.set(normalized.username, normalized);
  });
  return { users, source };
}

let authUsers = new Map();
let authUserSource = 'none';

function refreshAuthUsers() {
  ensureBootstrapAdminUser();
  const loaded = loadAuthUsers();
  authUsers = loaded.users;
  authUserSource = loaded.source;
}

function isAuthEnabled() {
  return !AUTH_BYPASS && authUsers.size > 0;
}

refreshAuthUsers();

if (isAuthEnabled() && !AUTH_SECRET) {
  throw new Error('AUTH_SECRET is required when authentication is enabled.');
}
if (!isAuthEnabled()) {
  console.warn('Authentication is disabled. Set AUTH_USERS/AUTH_USERS_JSON and AUTH_SECRET to require login.');
}

function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', AUTH_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function readSession(token) {
  if (!token || !isAuthEnabled()) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, signature] = parts;
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload?.username || !payload?.exp) return null;
    if (Date.now() >= payload.exp) return null;
    const user = authUsers.get(normalizeUsername(payload.username));
    if (!user) return null;
    return { username: user.username, displayName: user.displayName, role: user.role || 'expert' };
  } catch {
    return null;
  }
}

function getUserFromRequest(req) {
  if (!isAuthEnabled()) {
    return { username: 'anonymous', displayName: 'Anonymous', role: 'anonymous' };
  }
  const cookies = parseCookieHeader(req.headers.cookie || '');
  return readSession(cookies[AUTH_COOKIE_NAME]);
}

function isAdminUser(user) {
  return Boolean(user && user.role === 'admin');
}

function requireAdmin(req, res, next) {
  if (!isAdminUser(req.user)) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  return next();
}

const FIELD_KEYWORDS = {
  population: [/population/i, /participants/i, /sample/i, /patients/i, /subjects/i],
  symptoms: [/symptom/i, /presentation/i, /clinical feature/i],
  riskFactors: [/risk/i, /trigger/i, /cause/i, /predictor/i],
  interventions: [/intervention/i, /treatment/i, /therapy/i, /strategy/i],
  outcomes: [/outcome/i, /result/i, /effect/i, /impact/i]
};

function stripMarkdown(text) {
  return (text || '')
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\[(.*?)\]\((.*?)\)/g, '$1')
    .replace(/[_#>]/g, '')
    .trim();
}

function parseExtractionSummary(raw) {
  const original = String(raw || '').replace(/\r/g, '').trim();
  const sections = {};
  const lines = original.split('\n');
  let current = 'Summary';
  sections[current] = [];

  const setHeading = (heading) => {
    const cleaned = stripMarkdown(heading || '').trim();
    if (!cleaned) return;
    current = cleaned;
    if (!sections[current]) sections[current] = [];
  };

  for (const line of lines) {
    const rawLine = String(line || '').trim();
    if (!rawLine) continue;

    const hashMatch = rawLine.match(/^#{2,}\s*(.+?)\s*:?\s*$/);
    if (hashMatch) {
      setHeading(hashMatch[1]);
      continue;
    }

    const boldMatch = rawLine.match(/^(?:[-*]|\d+\.)?\s*\*\*(.+?)\*\*\s*:?\s*$/);
    if (boldMatch) {
      setHeading(boldMatch[1]);
      continue;
    }

    const numberedHeadingMatch = rawLine.match(/^\d+\.\s*([^:]{2,120})\s*:\s*$/);
    if (numberedHeadingMatch) {
      setHeading(numberedHeadingMatch[1]);
      continue;
    }

    const plainHeadingMatch = rawLine.match(/^([A-Za-z][A-Za-z0-9 /_-]{2,80})\s*:\s*$/);
    if (plainHeadingMatch) {
      setHeading(plainHeadingMatch[1]);
      continue;
    }

    let cleaned = stripMarkdown(rawLine);
    cleaned = cleaned.replace(/^[-*]\s*/, '').replace(/^\d+\.\s*/, '').trim();
    if (!cleaned) continue;
    sections[current] = sections[current] || [];
    sections[current].push(cleaned);
  }

  const normalized = Object.entries(sections).map(([heading, bullets]) => ({ heading, bullets }));
  return { raw: stripMarkdown(original), sections: normalized };
}

function categorizeExtraction(parsed) {
  const buckets = {
    population: [],
    symptoms: [],
    riskFactors: [],
    interventions: [],
    outcomes: [],
    other: []
  };

  const assign = (text, fallbackHeading = '') => {
    const cleaned = (text || '').trim();
    if (!cleaned) return;
    const normalised = `${fallbackHeading} ${cleaned}`.toLowerCase();
    for (const [key, patterns] of Object.entries(FIELD_KEYWORDS)) {
      if (patterns.some(rx => rx.test(normalised))) {
        buckets[key].push(cleaned);
        return;
      }
    }
    buckets.other.push(cleaned);
  };

  (parsed.sections || []).forEach(section => {
    const heading = section.heading || '';
    const bullets = section.bullets || [];
    if (bullets.length === 0) {
      assign(heading, heading);
      return;
    }
    bullets.forEach(bullet => {
      // split "Label: value" forms
      const parts = bullet.split(/:\s*/);
      if (parts.length > 1 && parts[0].length < 80) {
        assign(parts.slice(1).join(': '), `${heading} ${parts[0]}`);
      } else {
        assign(bullet, heading);
      }
    });
  });

  const summaryPieces = [];
  ['population', 'symptoms', 'riskFactors', 'interventions', 'outcomes'].forEach(key => {
    const unique = Array.from(new Map(buckets[key].map(v => [v.toLowerCase(), v])).values()).slice(0, 5);
    buckets[key] = unique;
    if (!buckets[key].length) return;
    const label = key.replace(/([A-Z])/g, ' $1');
    const first = buckets[key][0];
    const compact = first.length > 160 ? `${first.slice(0, 157)}...` : first;
    summaryPieces.push(`${label}: ${compact}`);
  });
  if (!summaryPieces.length && buckets.other.length) {
    summaryPieces.push(buckets.other[0]);
  }

  return {
    population: buckets.population,
    symptoms: buckets.symptoms,
    riskFactors: buckets.riskFactors,
    interventions: buckets.interventions,
    outcomes: buckets.outcomes,
    summaryFallback: summaryPieces.join(' | ')
  };
}

function parseJsonArrayCell(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== 'string') return [];
  const trimmed = raw.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function dedupeStrings(values) {
  return Array.from(new Map(values.map(v => [v.toLowerCase(), v])).values());
}

function buildJsonExtractionParsed(row) {
  const sections = [];
  const addSection = (heading, bullets) => {
    const cleaned = (bullets || []).map(stripMarkdown).map(s => s.trim()).filter(Boolean);
    sections.push({ heading, bullets: cleaned });
  };

  if (row.ex_design) addSection('Study design', [row.ex_design]);
  if (row.ex_justification) addSection('Justification', [row.ex_justification]);

  const symptoms = parseJsonArrayCell(row.ex_symptoms).map(entry => {
    const term = entry?.term || '';
    const evidence = entry?.evidence || '';
    return evidence ? `${term} - ${evidence}` : term;
  });
  const population = parseJsonArrayCell(row.ex_population).map(entry => {
    const term = entry?.term || '';
    const category = entry?.category ? ` (${entry.category})` : '';
    const evidence = entry?.evidence || '';
    const label = `${term}${category}`.trim();
    return evidence ? `${label} - ${evidence}` : label;
  });
  const riskFactors = parseJsonArrayCell(row.ex_risk_factors).map(entry => {
    const term = entry?.term || '';
    const direction = entry?.direction ? ` (${entry.direction})` : '';
    const evidence = entry?.evidence || '';
    const label = `${term}${direction}`.trim();
    return evidence ? `${label} - ${evidence}` : label;
  });
  const interventions = parseJsonArrayCell(row.ex_interventions).map(entry => {
    const name = entry?.name || entry?.term || '';
    const type = entry?.type ? ` (${entry.type})` : '';
    const comparator = entry?.comparator ? `; comparator: ${entry.comparator}` : '';
    const evidence = entry?.evidence || '';
    const label = `${name}${type}${comparator}`.trim();
    return evidence ? `${label} - ${evidence}` : label;
  });
  const outcomes = parseJsonArrayCell(row.ex_outcomes).map(entry => {
    const metric = entry?.metric || entry?.term || '';
    const direction = entry?.direction ? ` (${entry.direction})` : '';
    const evidence = entry?.evidence || '';
    const label = `${metric}${direction}`.trim();
    return evidence ? `${label} - ${evidence}` : label;
  });

  addSection('Population', population);
  addSection('Symptoms', symptoms);
  addSection('Risk factors', riskFactors);
  addSection('Interventions', interventions);
  addSection('Outcomes', outcomes);

  return { raw: '', sections };
}

const EXPECTED_SOURCE_FILES = {
  qa: 'qa_pairs.csv',
  extracted: 'extracted_insights.csv'
};

const EVAL_QUESTION_IDS = {
  qa: ['qa_reflects', 'qa_quality'],
  extracted: ['extracted_accuracy']
};

function readFileStatus(fullPath) {
  try {
    const stat = fs.statSync(fullPath);
    return {
      path: fullPath,
      exists: stat.isFile(),
      sizeBytes: stat.size,
      mtime: stat.mtime.toISOString()
    };
  } catch {
    return { path: fullPath, exists: false };
  }
}

function tryLoadCsv(file) {
  const full = path.join(SOURCE_DATA_DIR, file);
  const status = readFileStatus(full);
  if (!status.exists) {
    return { rows: [], status, error: 'missing' };
  }
  try {
    const content = fs.readFileSync(full, 'utf8');
    const rows = parse(content, { columns: true, skip_empty_lines: true });
    return { rows, status };
  } catch (err) {
    return { rows: [], status, error: err?.message || 'parse_failed' };
  }
}

function cleanTitle(title = '') {
  return title.replace(/^\s*\[/, '').replace(/\]\s*$/, '').trim();
}

let datasets = {
  extracted: { key: 'extracted', label: 'Extraction Validation', items: [] },
  qa: { key: 'qa', label: 'Q&A Validation', items: [], byPmid: {} }
};
let datasetIndex = { qa: {}, extracted: {} };
let dataStatus = {
  sourceDataDir: SOURCE_DATA_DIR,
  runtimeDataDir: RUNTIME_DATA_DIR,
  bundledDataDir: BUNDLED_DATA_DIR,
  loadedAt: null,
  files: {}
};

async function refreshDatasets() {
  const qaLoad = tryLoadCsv(EXPECTED_SOURCE_FILES.qa);
  const extractedLoad = tryLoadCsv(EXPECTED_SOURCE_FILES.extracted);

  const qaItems = (qaLoad.rows || []).map((row, idx) => ({
    id: `${row.pmid || 'unknown'}-${idx}`,
    pmid: row.pmid,
    title: cleanTitle(row.title || ''),
    question: row.qa_question,
    answer: row.qa_answer,
    explanation: row.qa_explanation,
    qa_type: row.qa_type,
    journal: row.journal,
    year: row.year,
    abstract: row.abstract,
    classification: row.classification,
    sourceIndex: idx
  }));

  const qaByPmid = qaItems.reduce((acc, item) => {
    if (!acc[item.pmid]) acc[item.pmid] = [];
    acc[item.pmid].push(item);
    return acc;
  }, {});

  const extractedSample = (extractedLoad.rows || [])[0] || {};
  const structuredColumnsPresent = (extractedLoad.rows || []).length > 0 &&
    Object.prototype.hasOwnProperty.call(extractedSample, 'population');
  const jsonExtractionColumnsPresent = (extractedLoad.rows || []).length > 0 && [
    'ex_population',
    'ex_symptoms',
    'ex_risk_factors',
    'ex_interventions',
    'ex_outcomes'
  ].some(col => Object.prototype.hasOwnProperty.call(extractedSample, col));

  const extractedItems = (extractedLoad.rows || []).map((row, idx) => {
    const parseField = (value) => {
      if (!value) return [];
      if (Array.isArray(value)) return value;
      return value.split('||').map(part => stripMarkdown(part)).map(s => s.trim()).filter(Boolean);
    };

    let parsed = null;
    let categorized = null;
    let summary = '';
    let extractionFormat = 'markdown';

    if (structuredColumnsPresent) {
      extractionFormat = 'structured';
      parsed = parseExtractionSummary(row.gpt_output);
      categorized = {
        population: parseField(row.population),
        symptoms: parseField(row.symptoms),
        riskFactors: parseField(row.risk_factors || row.riskFactors),
        interventions: parseField(row.interventions),
        outcomes: parseField(row.outcomes)
      };
      summary = stripMarkdown(row.structured_summary || row.summary || categorized.summaryFallback);
    } else if (jsonExtractionColumnsPresent) {
      extractionFormat = 'json_fields';
      parsed = buildJsonExtractionParsed(row);

      const pullTerms = (value, key) => (
        dedupeStrings(parseJsonArrayCell(value)
          .map(entry => stripMarkdown(entry?.[key] || '').trim())
          .filter(Boolean))
      );

      categorized = {
        population: pullTerms(row.ex_population, 'term'),
        symptoms: pullTerms(row.ex_symptoms, 'term'),
        riskFactors: pullTerms(row.ex_risk_factors, 'term'),
        interventions: dedupeStrings(parseJsonArrayCell(row.ex_interventions)
          .map(entry => stripMarkdown(entry?.name || entry?.term || '').trim())
          .filter(Boolean)),
        outcomes: dedupeStrings(parseJsonArrayCell(row.ex_outcomes)
          .map(entry => stripMarkdown(entry?.metric || entry?.term || '').trim())
          .filter(Boolean))
      };
      categorized.summaryFallback = [
        categorized.population?.[0] ? `Population: ${categorized.population[0]}` : null,
        categorized.symptoms?.[0] ? `Symptoms: ${categorized.symptoms[0]}` : null,
        categorized.riskFactors?.[0] ? `Risk factors: ${categorized.riskFactors[0]}` : null,
        categorized.interventions?.[0] ? `Interventions: ${categorized.interventions[0]}` : null,
        categorized.outcomes?.[0] ? `Outcomes: ${categorized.outcomes[0]}` : null
      ].filter(Boolean).join(' | ');
      summary = stripMarkdown(row.ex_justification || row.ex_design || categorized.summaryFallback);
    } else {
      extractionFormat = 'markdown';
      parsed = parseExtractionSummary(row.gpt_output);
      categorized = categorizeExtraction(parsed);
      summary = categorized.summaryFallback;
    }

    return {
      id: `${row.pmid || 'unknown'}-${idx}`,
      pmid: row.pmid,
      title: cleanTitle(row.title || ''),
      journal: row.journal,
      year: row.year,
      abstract: row.abstract,
      gpt_output: row.gpt_output,
      classification: row.classification,
      sourceIndex: idx,
      parsed,
      categorized,
      summary,
      extractionFormat
    };
  });

  const needsEnrichment = extractedItems.length > 0 &&
    !structuredColumnsPresent &&
    !jsonExtractionColumnsPresent &&
    process.env.CURATOR_USE_SUMMARY !== '0';
  if (needsEnrichment) {
    await enrichSummaries(extractedItems);
  }

  datasets = {
    extracted: {
      key: 'extracted',
      label: 'Extraction Validation',
      items: extractedItems
    },
    qa: {
      key: 'qa',
      label: 'Q&A Validation',
      items: qaItems,
      byPmid: qaByPmid
    }
  };

  datasetIndex = Object.fromEntries(Object.values(datasets).map(ds => [
    ds.key,
    Object.fromEntries(ds.items.map(item => [item.id, item]))
  ]));

  dataStatus = {
    sourceDataDir: SOURCE_DATA_DIR,
    runtimeDataDir: RUNTIME_DATA_DIR,
    bundledDataDir: BUNDLED_DATA_DIR,
    loadedAt: new Date().toISOString(),
    files: {
      qa: {
        filename: EXPECTED_SOURCE_FILES.qa,
        ...qaLoad.status,
        error: qaLoad.error || null,
        rows: qaLoad.rows.length,
        items: qaItems.length,
        uniquePmids: new Set(qaItems.map(it => it.pmid).filter(Boolean)).size
      },
      extracted: {
        filename: EXPECTED_SOURCE_FILES.extracted,
        ...extractedLoad.status,
        error: extractedLoad.error || null,
        rows: extractedLoad.rows.length,
        items: extractedItems.length,
        uniquePmids: new Set(extractedItems.map(it => it.pmid).filter(Boolean)).size,
        structuredColumnsPresent,
        jsonExtractionColumnsPresent
      }
    }
  };
}

await refreshDatasets();

async function callAmplify(messages) {
  const apiKey = process.env.AMPLIFY_API_KEY;
  const baseUrl = process.env.AMPLIFY_API_URL;
  if (!apiKey || !baseUrl) return null;
  try {
    const headerName = process.env.AMPLIFY_HEADER_NAME || 'Authorization';
    const headers = { 'Content-Type': 'application/json' };
    if (headerName.toLowerCase() === 'authorization') {
      headers[headerName] = `Bearer ${apiKey}`;
    } else {
      headers[headerName] = apiKey;
    }
    const payload = baseUrl.replace(/\/$/, '').endsWith('/chat')
      ? { data: { messages, max_tokens: 250, temperature: 0, options: { model: { id: process.env.AMPLIFY_MODEL || 'gpt-4o-mini' }, skipRag: true }, dataSources: [] } }
      : { model: process.env.AMPLIFY_MODEL || 'gpt-4o-mini', messages, max_tokens: 250, temperature: 0 };
    const res = await fetch(baseUrl, { method: 'POST', headers, body: JSON.stringify(payload) });
    if (!res.ok) return null;
    const data = await res.json();
    const text = data?.choices?.[0]?.message?.content || data?.data?.output_text || JSON.stringify(data);
    return text;
  } catch (err) {
    console.error('Amplify summary failed', err);
    return null;
  }
}

async function enrichSummaries(items) {
  if (!items.length) return;
  let cache = {};
  if (fs.existsSync(SUMMARY_CACHE_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(SUMMARY_CACHE_PATH, 'utf8'));
      cache = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (err) {
      console.warn('Failed to parse summary cache', err);
    }
  }
  // Ignore stale cache entries (e.g., generated under earlier parsing logic).
  cache = Object.fromEntries(Object.entries(cache).filter(([_id, entry]) => (
    entry && typeof entry === 'object' && entry.version === SUMMARY_CACHE_VERSION
  )));
  const limit = parseInt(process.env.CURATOR_SUMMARY_LIMIT || '40', 10);
  let updated = false;
  for (const item of items.slice(0, Math.max(limit, 1))) {
    if (cache[item.id]) {
      item.summary = cache[item.id].summary || item.summary;
      if (cache[item.id].categorized) {
        item.categorized = cache[item.id].categorized;
      }
      continue;
    }
    const prompt = `You curate concise clinical evidence. Based on the raw extraction notes below, respond with strict JSON: {"population":[],"symptoms":[],"risk_factors":[],"interventions":[],"outcomes":[],"summary":""}.\n- Each list must contain up to 2 distinct entries.\n- Each entry must be ≤20 words and answer what the abstract says about that category.\n- Use "Not reported" if the abstract provides no support.\n- The summary must be ≤40 words.\nRaw notes:\n${item.gpt_output}`;
    const response = await callAmplify([
      { role: 'system', content: 'You craft concise, structured medical summaries without speculation.' },
      { role: 'user', content: prompt }
    ]);
    if (response) {
      try {
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        const parsed = jsonMatch ? JSON.parse(jsonMatch[0]) : JSON.parse(response);
        const sanitise = (val) => {
          if (!val) return [];
          if (Array.isArray(val)) return val.map(stripMarkdown).filter(Boolean);
          return [stripMarkdown(val)];
        };
        const dedupe = (arr) => Array.from(new Map(arr.map(v => [v.toLowerCase(), v])).values());
        const enriched = {
          population: dedupe(sanitise(parsed.population)),
          symptoms: dedupe(sanitise(parsed.symptoms)),
          riskFactors: dedupe(sanitise(parsed.risk_factors || parsed.riskFactors)),
          interventions: dedupe(sanitise(parsed.interventions)),
          outcomes: dedupe(sanitise(parsed.outcomes))
        };
        item.categorized = enriched;
        item.summary = stripMarkdown(parsed.summary || item.summary);
        cache[item.id] = { version: SUMMARY_CACHE_VERSION, summary: item.summary, categorized: enriched };
        updated = true;
        continue;
      } catch (err) {
        console.warn('Failed to parse LLM response', err);
      }
    }
    cache[item.id] = { version: SUMMARY_CACHE_VERSION, summary: item.summary, categorized: item.categorized };
    updated = true;
  }
  if (updated) {
    fs.writeFileSync(SUMMARY_CACHE_PATH, JSON.stringify(cache, null, 2), 'utf8');
  }
  items.forEach(item => {
    if (cache[item.id]) {
      item.summary = cache[item.id].summary || item.summary;
      item.categorized = cache[item.id].categorized || item.categorized;
    }
  });
}

function normalizeStore(store = {}) {
  const ensureObj = (value) => (
    value && typeof value === 'object' && !Array.isArray(value) ? value : {}
  );

  const normalised = {
    responses: store.responses || {},
    compare: store.compare || {},
    compareAudit: Array.isArray(store.compareAudit) ? store.compareAudit : [],
    reviewedItems: ensureObj(store.reviewedItems),
    reviewedByUser: ensureObj(store.reviewedByUser)
  };
  for (const [questionId, payload] of Object.entries(normalised.responses)) {
    if (!payload) {
      normalised.responses[questionId] = { counts: {}, records: [] };
      continue;
    }
    const hasNewShape = Object.prototype.hasOwnProperty.call(payload, 'records');
    if (!hasNewShape) {
      const counts = {};
      for (const [key, value] of Object.entries(payload)) {
        if (typeof value === 'number') counts[key] = value;
      }
      normalised.responses[questionId] = { counts, records: [] };
    } else {
      payload.counts = payload.counts || {};
      payload.records = payload.records || [];
    }
  }

  // Backfill reviewedByUser from the historical audit log when migrating older response stores.
  if (!store.reviewedByUser) {
    for (const [questionId, payload] of Object.entries(normalised.responses)) {
      for (const record of (payload.records || [])) {
        const reviewer = normalizeUsername(record.reviewer || 'anonymous') || 'anonymous';
        const itemId = record.itemId;
        if (!itemId) continue;
        normalised.reviewedByUser[reviewer] = normalised.reviewedByUser[reviewer] || {};
        normalised.reviewedByUser[reviewer][itemId] = normalised.reviewedByUser[reviewer][itemId] || {};
        const existing = normalised.reviewedByUser[reviewer][itemId][questionId];
        if (!existing || String(existing.timestamp || '') < String(record.timestamp || '')) {
          normalised.reviewedByUser[reviewer][itemId][questionId] = record;
        }
      }
    }
  }
  return normalised;
}

function createEmptyDatasetStore() {
  return { responses: {}, compare: {}, compareAudit: [], reviewedItems: {}, reviewedByUser: {} };
}

function loadResponses() {
  if (!fs.existsSync(RESPONSE_PATH)) {
    return {
      qa: createEmptyDatasetStore(),
      extracted: createEmptyDatasetStore()
    };
  }
  try {
    const raw = fs.readFileSync(RESPONSE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      qa: normalizeStore(parsed.qa || createEmptyDatasetStore()),
      extracted: normalizeStore(parsed.extracted || createEmptyDatasetStore())
    };
  } catch (err) {
    console.error('Failed to load response store', err);
    return {
      qa: createEmptyDatasetStore(),
      extracted: createEmptyDatasetStore()
    };
  }
}

let responseStore = loadResponses();

function saveResponses() {
  fs.writeFileSync(RESPONSE_PATH, JSON.stringify(responseStore, null, 2), 'utf8');
}

function ensureQuestionStore(store, questionId) {
  if (!store.responses[questionId]) {
    store.responses[questionId] = {
      counts: {},
      records: []
    };
  }
  return store.responses[questionId];
}

function aggregateSummary(datasetKey, reviewer = 'anonymous') {
  const store = responseStore[datasetKey];
  if (!store) {
    return { totalDecisions: 0, reviewed: 0, questionSummaries: {}, compare: {} };
  }
  const questionIds = EVAL_QUESTION_IDS[datasetKey] || [];

  const reviewerKey = normalizeUsername(reviewer || 'anonymous') || 'anonymous';
  const reviewerItems = (store.reviewedByUser || {})[reviewerKey] || {};
  const reviewedByUser = Object.entries(reviewerItems).reduce((acc, [itemId, byQuestion]) => {
    const done = questionIds.length > 0 && questionIds.every(qid => Boolean(byQuestion?.[qid]));
    return acc + (done ? 1 : 0);
  }, 0);

  const questionSummaries = {};
  let totalDecisions = 0;

  const latestRecordsForQuestion = (questionId) => {
    const out = [];
    const byUser = store.reviewedByUser || {};
    for (const user of Object.keys(byUser)) {
      const byItem = byUser[user] || {};
      for (const itemId of Object.keys(byItem)) {
        const rec = byItem[itemId]?.[questionId];
        if (rec) out.push(rec);
      }
    }
    return out;
  };

  for (const questionId of Object.keys(store.responses || {})) {
    const latest = latestRecordsForQuestion(questionId)
      .sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));
    const counts = latest.reduce((acc, rec) => {
      const key = `${rec.answer}_${rec.sure ? 'sure' : 'unsure'}`;
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    totalDecisions += Object.values(counts).reduce((a, b) => a + b, 0);
    const yes = latest.filter(r => r.answer === 'yes');
    const no = latest.filter(r => r.answer === 'no');
    questionSummaries[questionId] = {
      counts,
      yes,
      no
    };
  }
  const reviewedGlobal = Object.keys(store.reviewedItems || {}).length;
  return {
    totalDecisions,
    reviewed: reviewedByUser,
    reviewedByUser,
    reviewedGlobal,
    questionSummaries,
    compare: store.compare || {}
  };
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/healthz', (_req, res) => {
  res.json({
    ok: true,
    authEnabled: isAuthEnabled(),
    usersConfigured: authUsers.size,
    authSource: authUserSource
  });
});

app.get('/api/auth/me', (req, res) => {
  const user = getUserFromRequest(req);
  if (!isAuthEnabled()) {
    return res.json({ authEnabled: false, user, authSource: authUserSource });
  }
  if (!user) return res.status(401).json({ authEnabled: true, error: 'Not authenticated' });
  return res.json({
    authEnabled: true,
    user,
    isAdmin: user.role === 'admin',
    authSource: authUserSource
  });
});

app.post('/api/auth/login', (req, res) => {
  refreshAuthUsers();
  if (!isAuthEnabled()) {
    return res.status(400).json({ error: 'Authentication is not configured on this server.' });
  }
  const { username, password } = req.body || {};
  const key = normalizeUsername(username);
  if (!key || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  const user = authUsers.get(key);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const now = Date.now();
  const maxAgeSeconds = AUTH_SESSION_DAYS * 24 * 60 * 60;
  const token = signSession({
    username: user.username,
    iat: now,
    exp: now + maxAgeSeconds * 1000
  });
  res.setHeader('Set-Cookie', buildCookie(AUTH_COOKIE_NAME, token, maxAgeSeconds));
  return res.json({
    ok: true,
    authEnabled: true,
    authSource: authUserSource,
    user: { username: user.username, displayName: user.displayName, role: user.role || 'expert' }
  });
});

app.post('/api/auth/logout', (_req, res) => {
  res.setHeader('Set-Cookie', buildCookie(AUTH_COOKIE_NAME, '', 0));
  res.json({ ok: true });
});

app.use('/api', (req, res, next) => {
  const publicPaths = new Set(['/healthz', '/auth/me', '/auth/login', '/auth/logout']);
  if (publicPaths.has(req.path)) {
    return next();
  }
  const user = getUserFromRequest(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  req.user = user;
  return next();
});

app.get('/api/data-status', (_req, res) => {
  res.json({
    ...dataStatus,
    expectedFiles: Object.values(EXPECTED_SOURCE_FILES)
  });
});

app.get('/api/admin/users', requireAdmin, (_req, res) => {
  const users = Array.from(authUsers.values()).map(u => ({
    username: u.username,
    displayName: u.displayName,
    role: u.role || 'expert'
  }));
  res.json({ source: authUserSource, mutable: authUserSource !== 'env', users });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  if (authUserSource === 'env') {
    return res.status(409).json({ error: 'User management is disabled when AUTH_USERS/AUTH_USERS_JSON is set.' });
  }
  const { username, displayName, password, role } = req.body || {};
  const normalized = normalizeUsername(username);
  if (!normalized || !/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(normalized)) {
    return res.status(400).json({ error: 'Invalid username (use 3-32 chars: letters, numbers, ._-).' });
  }
  const pwd = String(password || '');
  if (pwd.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const list = loadUsersFromFile();
  const exists = list.some(u => normalizeUsername(u.username) === normalized);
  if (exists) return res.status(409).json({ error: 'Username already exists.' });

  const record = normalizeUserRecord({
    username: normalized,
    displayName: String(displayName || normalized),
    password: pwd,
    role: normalizeRole(role)
  });
  if (!record) return res.status(400).json({ error: 'Could not create user record.' });
  list.push(record);
  saveUsersToFile(list);
  refreshAuthUsers();
  return res.json({ ok: true, user: { username: record.username, displayName: record.displayName, role: record.role } });
});

app.post('/api/admin/users/:username/password', requireAdmin, (req, res) => {
  if (authUserSource === 'env') {
    return res.status(409).json({ error: 'User management is disabled when AUTH_USERS/AUTH_USERS_JSON is set.' });
  }
  const target = normalizeUsername(req.params.username);
  const pwd = String(req.body?.password || '');
  if (!target) return res.status(400).json({ error: 'Invalid username.' });
  if (pwd.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const list = loadUsersFromFile();
  const idx = list.findIndex(u => normalizeUsername(u.username) === target);
  if (idx === -1) return res.status(404).json({ error: 'User not found.' });
  list[idx] = {
    ...list[idx],
    username: target,
    passwordHash: pbkdf2Hash(pwd)
  };
  saveUsersToFile(list);
  refreshAuthUsers();
  return res.json({ ok: true });
});

app.delete('/api/admin/users/:username', requireAdmin, (req, res) => {
  if (authUserSource === 'env') {
    return res.status(409).json({ error: 'User management is disabled when AUTH_USERS/AUTH_USERS_JSON is set.' });
  }
  const target = normalizeUsername(req.params.username);
  if (!target) return res.status(400).json({ error: 'Invalid username.' });
  if (target === normalizeUsername(req.user?.username)) {
    return res.status(400).json({ error: 'You cannot delete the currently signed-in user.' });
  }
  const list = loadUsersFromFile();
  const next = list.filter(u => normalizeUsername(u.username) !== target);
  if (next.length === list.length) return res.status(404).json({ error: 'User not found.' });
  saveUsersToFile(next);
  refreshAuthUsers();
  return res.json({ ok: true });
});

app.put('/api/admin/upload/:filename',
  requireAdmin,
  express.raw({ type: '*/*', limit: '50mb' }),
  async (req, res) => {
    const filename = String(req.params.filename || '').trim();
    const allowed = new Set([
      EXPECTED_SOURCE_FILES.qa,
      EXPECTED_SOURCE_FILES.extracted,
      'extracted_summaries.json'
    ]);
    if (!allowed.has(filename)) {
      return res.status(400).json({ error: `Unsupported filename. Allowed: ${Array.from(allowed).join(', ')}` });
    }
    const buf = req.body;
    if (!Buffer.isBuffer(buf) || buf.length === 0) {
      return res.status(400).json({ error: 'Empty upload.' });
    }
    const destination = filename === 'extracted_summaries.json'
      ? SUMMARY_CACHE_PATH
      : path.join(SOURCE_DATA_DIR, filename);
    fs.writeFileSync(destination, buf);
    await refreshDatasets();
    return res.json({ ok: true, dataStatus });
  }
);

app.post('/api/admin/reload-data', requireAdmin, async (_req, res) => {
  await refreshDatasets();
  res.json({ ok: true, dataStatus });
});

app.get('/api/datasets', (_req, res) => {
  const list = Object.values(datasets).map(ds => ({
    key: ds.key,
    label: ds.label,
    count: ds.items.length,
    uniquePmids: new Set(ds.items.map(it => it.pmid)).size,
    sourceFile: EXPECTED_SOURCE_FILES[ds.key] || null,
    sourceExists: Boolean(dataStatus.files?.[ds.key]?.exists),
    sourceError: dataStatus.files?.[ds.key]?.error || null
  }));
  res.json({ datasets: list });
});

app.get('/api/items', (req, res) => {
  const { dataset: datasetKey = 'qa', offset = '0', limit = '20', q = '', unreviewed = '0' } = req.query;
  const dataset = datasets[datasetKey];
  if (!dataset) return res.status(400).json({ error: 'Unknown dataset' });
  const search = (q || '').toString().trim().toLowerCase();
  const store = responseStore[datasetKey] || createEmptyDatasetStore();
  const reviewerKey = normalizeUsername(req.user?.username || 'anonymous') || 'anonymous';
  const reviewedByUser = (store.reviewedByUser || {})[reviewerKey] || {};
  const requiredQuestionIds = EVAL_QUESTION_IDS[datasetKey] || [];

  const buildUserReview = (itemId) => {
    const byQuestion = reviewedByUser[itemId] || {};
    const review = {};
    requiredQuestionIds.forEach(qid => {
      const rec = byQuestion[qid];
      if (!rec) return;
      review[qid] = { answer: rec.answer, sure: Boolean(rec.sure), timestamp: rec.timestamp };
    });
    const reviewedAll = requiredQuestionIds.length > 0 &&
      requiredQuestionIds.every(qid => Boolean(byQuestion[qid]));
    return { review, reviewedAll };
  };

  let filtered = dataset.items.map(item => {
    const user = buildUserReview(item.id);
    return {
      ...item,
      userReview: user.review,
      userReviewedAll: user.reviewedAll
    };
  });

  const wantsUnreviewed = ['1', 'true', 'yes'].includes(String(unreviewed).toLowerCase());
  if (wantsUnreviewed) {
    filtered = filtered.filter(item => !item.userReviewedAll);
  }
  if (search) {
    filtered = filtered.filter(item => {
      return Object.values(item).some(val =>
        typeof val === 'string' && val.toLowerCase().includes(search)
      );
    });
  }
  const start = Math.max(parseInt(offset, 10) || 0, 0);
  const end = start + (Math.max(parseInt(limit, 10) || 20, 1));
  const slice = filtered.slice(start, end);
  res.json({
    items: slice,
    total: filtered.length,
    offset: start,
    limit: end - start
  });
});

app.get('/api/compare-options', (req, res) => {
  const { dataset: datasetKey = 'qa', pmid } = req.query;
  const dataset = datasets[datasetKey];
  if (!dataset) return res.status(400).json({ error: 'Unknown dataset' });
  if (!pmid) return res.status(400).json({ error: 'pmid required' });
  const list = (dataset.byPmid && dataset.byPmid[pmid]) || [];
  res.json({ items: list });
});

app.post('/api/responses', (req, res) => {
  const { dataset: datasetKey, itemId, questionId, answer, sure } = req.body || {};
  if (!datasetKey || !datasets[datasetKey]) return res.status(400).json({ error: 'Unknown dataset' });
  if (!itemId || !questionId) return res.status(400).json({ error: 'Missing item/question id' });
  if (!['yes', 'no'].includes(answer)) return res.status(400).json({ error: 'Answer must be yes or no' });
  const store = responseStore[datasetKey];
  const item = datasetIndex[datasetKey][itemId];
  if (!item) return res.status(404).json({ error: 'Item not found' });

  const questionStore = ensureQuestionStore(store, questionId);
  const reviewerKey = normalizeUsername(req.user?.username || 'anonymous') || 'anonymous';

  // Keep per-user latest decisions so experts can resume unfinished work.
  store.reviewedByUser = store.reviewedByUser || {};
  store.reviewedByUser[reviewerKey] = store.reviewedByUser[reviewerKey] || {};
  store.reviewedByUser[reviewerKey][itemId] = store.reviewedByUser[reviewerKey][itemId] || {};

  const previous = store.reviewedByUser[reviewerKey][itemId][questionId];
  if (previous) {
    const prevKey = `${previous.answer}_${previous.sure ? 'sure' : 'unsure'}`;
    if (questionStore.counts?.[prevKey]) {
      questionStore.counts[prevKey] = Math.max(0, (questionStore.counts[prevKey] || 0) - 1);
      if (questionStore.counts[prevKey] === 0) delete questionStore.counts[prevKey];
    }
  }

  const key = `${answer}_${sure ? 'sure' : 'unsure'}`;
  questionStore.counts = questionStore.counts || {};
  questionStore.counts[key] = (questionStore.counts[key] || 0) + 1;

  const record = {
    timestamp: new Date().toISOString(),
    reviewer: reviewerKey,
    reviewerRole: req.user?.role || 'expert',
    dataset: datasetKey,
    questionId,
    answer,
    sure: Boolean(sure),
    itemId,
    pmid: item.pmid,
    title: item.title,
    journal: item.journal,
    year: item.year,
    classification: item.classification,
    content: datasetKey === 'qa'
      ? { question: item.question, answer: item.answer, explanation: item.explanation }
      : { summary: item.summary, fields: item.categorized, rawSections: item.parsed.sections }
  };
  questionStore.records.push(record);

  store.reviewedItems[itemId] = store.reviewedItems[itemId] || {};
  store.reviewedItems[itemId][questionId] = record;
  store.reviewedByUser[reviewerKey][itemId][questionId] = record;

  saveResponses();
  res.json({ ok: true });
});

app.post('/api/compare', (req, res) => {
  const { dataset: datasetKey = 'qa', pmid, choiceId } = req.body || {};
  if (!datasets[datasetKey]) return res.status(400).json({ error: 'Unknown dataset' });
  if (!pmid || !choiceId) return res.status(400).json({ error: 'pmid and choice required' });
  const store = responseStore[datasetKey];
  if (!store.compare[pmid]) store.compare[pmid] = {};
  store.compare[pmid][choiceId] = (store.compare[pmid][choiceId] || 0) + 1;
  store.compareAudit.push({
    timestamp: new Date().toISOString(),
    dataset: datasetKey,
    reviewer: req.user?.username || 'anonymous',
    pmid,
    choiceId
  });
  saveResponses();
  res.json({ ok: true });
});

app.get('/api/summary', (req, res) => {
  const { dataset: datasetKey = 'qa' } = req.query;
  if (!datasets[datasetKey]) return res.status(400).json({ error: 'Unknown dataset' });
  const summary = aggregateSummary(datasetKey, req.user?.username || 'anonymous');
  res.json(summary);
});

app.get('/api/records', (req, res) => {
  const { dataset: datasetKey = 'qa', questionId, decision } = req.query;
  if (!datasets[datasetKey]) return res.status(400).json({ error: 'Unknown dataset' });
  if (!questionId) return res.status(400).json({ error: 'questionId required' });
  const store = responseStore[datasetKey];
  const questionStore = (store.responses || {})[questionId];
  if (!questionStore) return res.json({ records: [] });
  let records = questionStore.records || [];
  if (decision === 'yes' || decision === 'no') {
    records = records.filter(r => r.answer === decision);
  }
  res.json({ records });
});

function toCsv(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(headers.map(h => {
      const val = row[h] == null ? '' : String(row[h]);
      if (val.includes(',') || val.includes('"') || val.includes('\n')) {
        return '"' + val.replace(/"/g, '""') + '"';
      }
      return val;
    }).join(','));
  }
  return lines.join('\n');
}

app.get('/api/export', (req, res) => {
  const { dataset: datasetKey = 'qa', questionId, decision, format = 'csv' } = req.query;
  if (!datasets[datasetKey]) return res.status(400).json({ error: 'Unknown dataset' });
  const store = responseStore[datasetKey] || createEmptyDatasetStore();
  const questionIds = questionId
    ? [questionId]
    : (Object.keys(store.responses || {}).length ? Object.keys(store.responses || {}) : (EVAL_QUESTION_IDS[datasetKey] || []));

  const byUser = store.reviewedByUser || {};
  const records = [];
  for (const reviewer of Object.keys(byUser)) {
    const byItem = byUser[reviewer] || {};
    for (const itemId of Object.keys(byItem)) {
      for (const qid of questionIds) {
        const rec = byItem[itemId]?.[qid];
        if (!rec) continue;
        if (decision === 'yes' || decision === 'no') {
          if (rec.answer !== decision) continue;
        }
        records.push({
          timestamp: rec.timestamp,
          reviewer: rec.reviewer || reviewer || 'anonymous',
          reviewerRole: rec.reviewerRole || '',
          dataset: rec.dataset,
          questionId: rec.questionId,
          decision: rec.answer,
          sure: rec.sure,
          pmid: rec.pmid,
          title: rec.title,
          journal: rec.journal,
          year: rec.year,
          classification: rec.classification,
          summary: rec.dataset === 'qa'
            ? `${rec.content?.question || ''} | ${rec.content?.answer || ''}`
            : `${rec.content?.summary || ''}`
        });
      }
    }
  }

  if (format === 'json') {
    res.json({ records });
    return;
  }

  const csv = toCsv(records);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${datasetKey}-responses.csv"`);
  res.send(csv);
});

const port = process.env.PORT || 3400;
app.listen(port, () => {
  console.log(`human-expert-validation-v1 running at http://localhost:${port}`);
});
