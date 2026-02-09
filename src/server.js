import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { parse } from 'csv-parse/sync';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SOURCE_DATA_DIR = process.env.SOURCE_DATA_DIR
  ? path.resolve(process.env.SOURCE_DATA_DIR)
  : path.join(__dirname, '..', 'data');
const RUNTIME_DATA_DIR = process.env.RUNTIME_DATA_DIR
  ? path.resolve(process.env.RUNTIME_DATA_DIR)
  : SOURCE_DATA_DIR;
const RESPONSE_PATH = path.join(RUNTIME_DATA_DIR, 'responses.json');
const SUMMARY_CACHE_PATH = path.join(RUNTIME_DATA_DIR, 'extracted_summaries.json');
const USERS_PATH = process.env.AUTH_USERS_FILE
  ? path.resolve(process.env.AUTH_USERS_FILE)
  : path.join(RUNTIME_DATA_DIR, 'users.json');

if (!fs.existsSync(RUNTIME_DATA_DIR)) {
  fs.mkdirSync(RUNTIME_DATA_DIR, { recursive: true });
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

function normalizeUserRecord(raw = {}) {
  const username = normalizeUsername(raw.username);
  if (!username) return null;
  const passwordHash = String(raw.passwordHash || '').trim();
  const password = String(raw.password || '').trim();
  if (!passwordHash && !password) return null;
  return {
    username,
    displayName: String(raw.displayName || username).trim() || username,
    passwordHash: passwordHash || pbkdf2Hash(password)
  };
}

function loadAuthUsers() {
  let rawUsers = [];
  const rawJson = process.env.AUTH_USERS_JSON;
  const rawInline = process.env.AUTH_USERS;
  if (rawJson) {
    try {
      const parsed = JSON.parse(rawJson);
      if (Array.isArray(parsed)) rawUsers = parsed;
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
  } else if (fs.existsSync(USERS_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
      if (Array.isArray(parsed)) rawUsers = parsed;
    } catch (err) {
      console.warn('users.json could not be parsed', err);
    }
  }

  const users = new Map();
  rawUsers.forEach(entry => {
    const normalized = normalizeUserRecord(entry);
    if (!normalized) return;
    users.set(normalized.username, normalized);
  });
  return users;
}

const authUsers = loadAuthUsers();
const authEnabled = !AUTH_BYPASS && authUsers.size > 0;
if (authEnabled && !AUTH_SECRET) {
  throw new Error('AUTH_SECRET is required when authentication is enabled.');
}
if (!authEnabled) {
  console.warn('Authentication is disabled. Set AUTH_USERS/AUTH_USERS_JSON and AUTH_SECRET to require login.');
}

function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', AUTH_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function readSession(token) {
  if (!token || !authEnabled) return null;
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
    return { username: user.username, displayName: user.displayName };
  } catch {
    return null;
  }
}

function getUserFromRequest(req) {
  if (!authEnabled) {
    return { username: 'anonymous', displayName: 'Anonymous' };
  }
  const cookies = parseCookieHeader(req.headers.cookie || '');
  return readSession(cookies[AUTH_COOKIE_NAME]);
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
  const text = stripMarkdown(raw || '').replace(/\r/g, '').trim();
  const sections = {};
  const lines = text.split('\n');
  let current = 'Summary';
  sections[current] = [];
  for (const line of lines) {
    const trimmed = stripMarkdown(line);
    if (!trimmed) continue;
    const headingMatch = trimmed.match(/^[-*]?\s*\*\*(.+?)\*\*\s*:?.*$/);
    const hashMatch = trimmed.match(/^#{2,}\s*(.+?)\s*:?$/);
    if (headingMatch) {
      current = headingMatch[1].trim();
      if (!sections[current]) sections[current] = [];
      continue;
    }
    if (hashMatch) {
      current = hashMatch[1].trim();
      if (!sections[current]) sections[current] = [];
      continue;
    }
    if (!sections[current]) sections[current] = [];
    sections[current].push(trimmed.replace(/^[-*]\s*/, ''));
  }
  const normalized = Object.entries(sections).map(([heading, bullets]) => ({ heading, bullets }));
  return { raw: text, sections: normalized };
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
    const normalised = `${fallbackHeading} ${text}`.toLowerCase();
    for (const [key, patterns] of Object.entries(FIELD_KEYWORDS)) {
      if (patterns.some(rx => rx.test(normalised))) {
        buckets[key].push(text.trim());
        return;
      }
    }
    buckets.other.push(text.trim());
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
    const unique = Array.from(new Map(buckets[key].map(v => [v.toLowerCase(), v])).values()).slice(0, 2);
    buckets[key] = unique.map(v => v.length > 120 ? `${v.slice(0, 117)}…` : v);
    if (buckets[key].length) {
      summaryPieces.push(`${key.replace(/([A-Z])/g, ' $1')}: ${buckets[key][0]}`);
    }
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

const qaRaw = loadCsv('qa_pairs.csv');
const extractedRaw = loadCsv('extracted_insights.csv');
const structuredColumnsPresent = extractedRaw.length > 0 &&
  Object.prototype.hasOwnProperty.call(extractedRaw[0], 'population');

function cleanTitle(title = '') {
  return title.replace(/^\s*\[/, '').replace(/\]\s*$/, '').trim();
}

const qaItems = qaRaw.map((row, idx) => ({
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

const extractedItems = extractedRaw.map((row, idx) => {
  const parsed = parseExtractionSummary(row.gpt_output);
  const categorizedFromMarkdown = categorizeExtraction(parsed);

  const parseField = (value) => {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    return value.split('||').map(part => stripMarkdown(part)).map(s => s.trim()).filter(Boolean);
  };

  const categorized = structuredColumnsPresent ? {
    population: parseField(row.population),
    symptoms: parseField(row.symptoms),
    riskFactors: parseField(row.risk_factors || row.riskFactors),
    interventions: parseField(row.interventions),
    outcomes: parseField(row.outcomes)
  } : categorizedFromMarkdown;

  const summary = structuredColumnsPresent
    ? stripMarkdown(row.structured_summary || row.summary || categorized.summaryFallback)
    : categorized.summaryFallback;

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
  summary
};
});

const datasets = {
  qa: {
    key: 'qa',
    label: 'Q&A Validation',
    items: qaItems,
    byPmid: qaByPmid
  },
  extracted: {
    key: 'extracted',
    label: 'Extraction Validation',
    items: extractedItems
  }
};

const datasetIndex = Object.fromEntries(Object.values(datasets).map(ds => [
  ds.key,
  Object.fromEntries(ds.items.map(item => [item.id, item]))
]));

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
      cache = JSON.parse(fs.readFileSync(SUMMARY_CACHE_PATH, 'utf8'));
    } catch (err) {
      console.warn('Failed to parse summary cache', err);
    }
  }
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
        cache[item.id] = { summary: item.summary, categorized: enriched };
        updated = true;
        continue;
      } catch (err) {
        console.warn('Failed to parse LLM response', err);
      }
    }
    cache[item.id] = { summary: item.summary, categorized: item.categorized };
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

const needsEnrichment = !structuredColumnsPresent && process.env.CURATOR_USE_SUMMARY !== '0';
if (needsEnrichment) {
  await enrichSummaries(extractedItems);
}

function normalizeStore(store = {}) {
  const normalised = {
    responses: store.responses || {},
    compare: store.compare || {},
    compareAudit: Array.isArray(store.compareAudit) ? store.compareAudit : [],
    reviewedItems: store.reviewedItems || {}
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
  return normalised;
}

function createEmptyDatasetStore() {
  return { responses: {}, compare: {}, compareAudit: [], reviewedItems: {} };
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

function aggregateSummary(datasetKey) {
  const store = responseStore[datasetKey];
  if (!store) {
    return { totalDecisions: 0, reviewed: 0, questionSummaries: {}, compare: {} };
  }
  const questionSummaries = {};
  let totalDecisions = 0;
  for (const [questionId, payload] of Object.entries(store.responses)) {
    const counts = payload.counts || {};
    totalDecisions += Object.values(counts).reduce((a, b) => a + b, 0);
    const yes = payload.records.filter(r => r.answer === 'yes');
    const no = payload.records.filter(r => r.answer === 'no');
    questionSummaries[questionId] = {
      counts,
      yes,
      no
    };
  }
  const reviewed = Object.keys(store.reviewedItems || {}).length;
  return {
    totalDecisions,
    reviewed,
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
    authEnabled,
    usersConfigured: authUsers.size
  });
});

app.get('/api/auth/me', (req, res) => {
  const user = getUserFromRequest(req);
  if (!authEnabled) {
    return res.json({ authEnabled: false, user });
  }
  if (!user) return res.status(401).json({ authEnabled: true, error: 'Not authenticated' });
  return res.json({ authEnabled: true, user });
});

app.post('/api/auth/login', (req, res) => {
  if (!authEnabled) {
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
    user: { username: user.username, displayName: user.displayName }
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

app.get('/api/datasets', (_req, res) => {
  const list = Object.values(datasets).map(ds => ({
    key: ds.key,
    label: ds.label,
    count: ds.items.length,
    uniquePmids: new Set(ds.items.map(it => it.pmid)).size
  }));
  res.json({ datasets: list });
});

app.get('/api/items', (req, res) => {
  const { dataset: datasetKey = 'qa', offset = '0', limit = '20', q = '' } = req.query;
  const dataset = datasets[datasetKey];
  if (!dataset) return res.status(400).json({ error: 'Unknown dataset' });
  const search = (q || '').toString().trim().toLowerCase();
  let filtered = dataset.items;
  if (search) {
    filtered = dataset.items.filter(item => {
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
  const key = `${answer}_${sure ? 'sure' : 'unsure'}`;
  questionStore.counts[key] = (questionStore.counts[key] || 0) + 1;

  const record = {
    timestamp: new Date().toISOString(),
    reviewer: req.user?.username || 'anonymous',
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
  const summary = aggregateSummary(datasetKey);
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
  const store = responseStore[datasetKey];
  const questions = store.responses || {};
  let records = [];

  const pushRecords = (qid) => {
    const questionStore = questions[qid];
    if (!questionStore) return;
    let recs = questionStore.records || [];
    if (decision === 'yes' || decision === 'no') {
      recs = recs.filter(r => r.answer === decision);
    }
    records = records.concat(recs.map(r => ({
      timestamp: r.timestamp,
      reviewer: r.reviewer || 'anonymous',
      dataset: r.dataset,
      questionId: r.questionId,
      decision: r.answer,
      sure: r.sure,
      pmid: r.pmid,
      title: r.title,
      journal: r.journal,
      year: r.year,
      classification: r.classification,
      summary: r.dataset === 'qa'
        ? `${r.content.question} | ${r.content.answer}`
        : `${r.content.summary || ''}`
    })));
  };

  if (questionId) {
    pushRecords(questionId);
  } else {
    Object.keys(questions).forEach(pushRecords);
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
  console.log(`knowledge-curator-v1 running at http://localhost:${port}`);
});
