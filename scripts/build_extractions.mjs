#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { parse } from 'csv-parse/sync';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
const INPUT = process.env.CURATOR_INPUT || path.resolve(__dirname, '..', '..', '..', 'assignment3', 'azure_xia', 'outputs', 'step3_extracted.csv');
const OUTPUT = path.resolve(__dirname, '..', 'data', 'extracted_insights.csv');
const LIMIT = parseInt(process.env.CURATOR_INPUT_LIMIT || '80', 10);

const AMPLIFY_KEY = process.env.AMPLIFY_API_KEY;
const AMPLIFY_URL = process.env.AMPLIFY_API_URL;
const AMPLIFY_MODEL = process.env.AMPLIFY_MODEL || 'gpt-4o-mini';
const AMPLIFY_HEADER = process.env.AMPLIFY_HEADER_NAME || 'Authorization';

if (!AMPLIFY_KEY || !AMPLIFY_URL) {
  console.error('Missing Amplify credentials. Set AMPLIFY_API_KEY and AMPLIFY_API_URL.');
  process.exit(1);
}

const rawCsv = fs.readFileSync(INPUT, 'utf8');
const rows = parse(rawCsv, { columns: true, skip_empty_lines: true });
const subset = rows.slice(0, Math.min(rows.length, LIMIT));

async function callAmplify(messages) {
  const headers = { 'Content-Type': 'application/json' };
  if (AMPLIFY_HEADER.toLowerCase() === 'authorization') {
    headers[AMPLIFY_HEADER] = `Bearer ${AMPLIFY_KEY}`;
  } else {
    headers[AMPLIFY_HEADER] = AMPLIFY_KEY;
  }
  const payload = AMPLIFY_URL.replace(/\/$/, '').endsWith('/chat')
    ? { data: { messages, max_tokens: 250, temperature: 0, options: { model: { id: AMPLIFY_MODEL }, skipRag: true }, dataSources: [] } }
    : { model: AMPLIFY_MODEL, messages, max_tokens: 250, temperature: 0 };
  const res = await fetch(AMPLIFY_URL, { method: 'POST', headers, body: JSON.stringify(payload) });
  if (!res.ok) {
    throw new Error(`Amplify error ${res.status}: ${await res.text()}`);
  }
  const data = await res.json();
  return data?.choices?.[0]?.message?.content || data?.data?.output_text || JSON.stringify(data);
}

const results = [];

function flatten(list) {
  const seen = new Set();
  const items = [];
  (list || []).map(v => String(v).trim()).filter(Boolean).forEach(val => {
    const key = val.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    items.push(val);
  });
  return items.join('||');
}

for (let i = 0; i < subset.length; i++) {
  const row = subset[i];
  const prompt = `Extract structured clinical metadata from this abstract. Return strict JSON with keys: population, symptoms, risk_factors, interventions, outcomes (each list with ≤2 unique entries, each entry ≤20 words, use "Not reported" if absent) and summary (≤40 words). Base answers only on the abstract.\n\nTITLE: ${row.title}\nABSTRACT: ${row.abstract}`;
  console.log(`[${i + 1}/${subset.length}] Processing PMID ${row.pmid}`);
  let structured = { population: [], symptoms: [], risk_factors: [], interventions: [], outcomes: [], summary: '' };
  try {
    const text = await callAmplify([
      { role: 'system', content: 'You are a medical data curator. Return strict JSON only.' },
      { role: 'user', content: prompt }
    ]);
    const match = text.match(/\{[\s\S]*\}/);
    structured = match ? JSON.parse(match[0]) : JSON.parse(text);
  } catch (err) {
    console.warn(`Failed to parse Amplify response for PMID ${row.pmid}:`, err.message);
  }
  results.push({
    ...row,
    population: flatten(structured.population),
    symptoms: flatten(structured.symptoms),
    risk_factors: flatten(structured.risk_factors || structured.riskFactors),
    interventions: flatten(structured.interventions),
    outcomes: flatten(structured.outcomes),
    structured_summary: (structured.summary || '').replace(/\s+/g, ' ').trim()
  });
}

const headers = Object.keys(results[0] || {});
const csvLines = [headers.join(',')];
for (const row of results) {
  csvLines.push(headers.map(key => {
    const val = row[key] == null ? '' : String(row[key]);
    if (/[",\n]/.test(val)) {
      return '"' + val.replace(/"/g, '""') + '"';
    }
    return val;
  }).join(','));
}

fs.writeFileSync(OUTPUT, csvLines.join('\n'), 'utf8');
console.log(`Saved ${results.length} rows to ${OUTPUT}`);
