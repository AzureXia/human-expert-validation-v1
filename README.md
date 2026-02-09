# Human Expert Validation v1

Human-in-the-loop review UI for Assignment 3 outputs. This version supports authenticated domain-expert accounts, reviewer-attributed annotations, and deployment to Railway with a public URL.

## Features

- Upload-first workflow (admin uploads CSVs, then experts review).
- Extraction validation appears first (then Q&A validation).
- Structured review flow with confidence confirmation (`Yes, confident` / `No, unsure`) plus a Cancel option.
- Multi-user login (admin can create expert accounts in the UI).
- Every annotation is saved immediately (experts can pause and resume).
- Per-user progress tracker, unreviewed-only filter, summary dashboard, and CSV/JSON export.
- QA comparison modal for selecting strongest QA pair by abstract.

## Local Quick Start

```bash
cd assignment5/human-expert-validation-v1
cp .env.example .env
npm install
npm run dev
```

Open `http://localhost:3400`.

Minimum auth configuration in `.env`:

```bash
AUTH_SECRET=<long-random-secret>
# Recommended: bootstrap an admin account, then create expert users in the UI.
AUTH_BOOTSTRAP_ADMIN_USERNAME=admin
AUTH_BOOTSTRAP_ADMIN_PASSWORD=<choose-a-strong-password>
```

Generate a secure secret:

```bash
openssl rand -hex 32
```

Optional hashed-password setup:

```bash
npm run hash-password -- "StrongPassword!"
```

Use the generated hash in `AUTH_USERS_JSON` (optional alternative to UI-managed users):

```bash
AUTH_USERS_JSON=[{"username":"expert1","displayName":"Dr. Expert","passwordHash":"pbkdf2$sha256$...","role":"admin"}]
```

## Workflow (Recommended)

1. Admin signs in.
2. Admin uploads `extracted_insights.csv` and `qa_pairs.csv` (sidebar: Admin -> Upload Validation Files).
3. Admin creates expert user accounts (sidebar: Admin -> Manage Users).
4. Experts sign in and review items (use "Show unreviewed only" to keep going).
5. Download results as CSV/JSON.

Notes:
- "Items" = number of rows in the CSV.
- "Studies" = number of unique PMIDs (unique `pmid` values).

## Railway Deployment (Recommended)

1. Push this project to GitHub.
2. In Railway, create a new project from the repo and set the root directory to `human-expert-validation-v1`.
3. Add a Railway Volume and mount it to `/data`.
4. Set environment variables in Railway:
   - `NODE_ENV=production`
   - `RUNTIME_DATA_DIR=/data`
   - `AUTH_SECRET=<long-random-secret>`
   - `AUTH_BOOTSTRAP_ADMIN_PASSWORD=<choose-a-strong-password>` (then create expert users in the UI)
   - Optional Amplify variables if you use summary enrichment (`AMPLIFY_API_KEY`, `AMPLIFY_API_URL`, etc.)
5. Deploy. `railway.json` already defines start command and health check.
6. In Railway service settings, create a generated domain or attach your custom domain.

After this, experts can open the Railway URL from anywhere, sign in, and submit annotations.

## Runtime Data

- Source CSVs are read from `SOURCE_DATA_DIR`. If `SOURCE_DATA_DIR` is not set and `RUNTIME_DATA_DIR` is set (Railway), the app defaults `SOURCE_DATA_DIR` to `RUNTIME_DATA_DIR` so uploads live on the volume.
- Mutable files are written to `RUNTIME_DATA_DIR` (default: `./data`):
  - `responses.json`
  - `extracted_summaries.json`
  - `users.json` (UI-managed users)

For Railway, use a volume-backed `RUNTIME_DATA_DIR` so annotations persist across restarts/deploys.

## API

| Endpoint | Description |
|---|---|
| `GET /api/healthz` | Health + auth/runtime metadata. |
| `GET /api/auth/me` | Current authenticated user (or 401). |
| `POST /api/auth/login` | Login with `{ username, password }`. |
| `POST /api/auth/logout` | Clear session cookie. |
| `GET /api/data-status` | Shows whether CSVs exist, counts, and where they are loaded from. |
| `GET /api/datasets` | Dataset metadata (counts, unique PMIDs). |
| `GET /api/items?dataset=qa&offset=0&limit=10&q=&unreviewed=1` | Paginated items (+ optional unreviewed-only). |
| `POST /api/responses` | Store validation: `{ dataset, itemId, questionId, answer, sure }`. |
| `POST /api/compare` | Record selected QA pair: `{ dataset, pmid, choiceId }`. |
| `GET /api/compare-options?dataset=qa&pmid=` | QA pairs for comparison. |
| `GET /api/summary?dataset=qa` | Aggregated counts and recent examples. |
| `GET /api/records?dataset=qa&questionId=&decision=` | Raw records for a question. |
| `GET /api/export?dataset=qa&questionId=&decision=&format=csv` | Export responses as CSV/JSON. |
| `PUT /api/admin/upload/:filename` | (Admin) Upload `extracted_insights.csv` / `qa_pairs.csv`. |
| `GET /api/admin/users` | (Admin) List users. |
| `POST /api/admin/users` | (Admin) Create user. |

## Optional: Refresh Extraction Dataset with Amplify

```bash
cd assignment5/human-expert-validation-v1
node scripts/build_extractions.mjs
```

Ensure `.env` includes `AMPLIFY_API_KEY` and `AMPLIFY_API_URL` before running.
