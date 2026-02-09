# Human Expert Validation v1

Human-in-the-loop review UI for Assignment 3 outputs. This version supports authenticated domain-expert accounts, reviewer-attributed annotations, and deployment to Railway with a public URL.

## Features

- Loads QA (`step4`) and extraction (`step3`) CSVs from `data/`.
- Structured review flow with confidence confirmation (`Yes, confident` / `No, unsure`).
- Account login required (when auth is configured) before experts can review.
- Every annotation is saved with reviewer identity and timestamp.
- Real-time progress tracker, summary dashboard, and CSV/JSON export.
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
AUTH_USERS=expert1:ChangeMe123,expert2:ChangeMe456
```

Generate a secure secret:

```bash
openssl rand -hex 32
```

Optional hashed-password setup:

```bash
npm run hash-password -- "StrongPassword!"
```

Use the generated hash in `AUTH_USERS_JSON`:

```bash
AUTH_USERS_JSON=[{"username":"expert1","displayName":"Dr. Expert","passwordHash":"pbkdf2$sha256$..."}]
```

## Railway Deployment (Public Access)

1. Push this project to GitHub.
2. In Railway, create a new project from the repo and set the root directory to `human-expert-validation-v1`.
3. Add a Railway Volume and mount it to `/data`.
4. Set environment variables in Railway:
   - `NODE_ENV=production`
   - `RUNTIME_DATA_DIR=/data`
   - `AUTH_SECRET=<long-random-secret>`
   - `AUTH_USERS=expert1:ChangeMe123,expert2:ChangeMe456` (or `AUTH_USERS_JSON=...`)
   - Optional Amplify variables if you use summary enrichment (`AMPLIFY_API_KEY`, `AMPLIFY_API_URL`, etc.)
5. Deploy. `railway.json` already defines start command and health check.
6. In Railway service settings, create a generated domain or attach your custom domain.

After this, experts can open the Railway URL from anywhere, sign in, and submit annotations.

## Runtime Data

- Source CSVs are read from `SOURCE_DATA_DIR` (default: `./data`).
- Mutable files are written to `RUNTIME_DATA_DIR` (default: `./data`):
  - `responses.json`
  - `extracted_summaries.json`
  - `users.json` (if used)

For Railway, use a volume-backed `RUNTIME_DATA_DIR` so annotations persist across restarts/deploys.

## API

| Endpoint | Description |
|---|---|
| `GET /api/healthz` | Health + auth/runtime metadata. |
| `GET /api/auth/me` | Current authenticated user (or 401). |
| `POST /api/auth/login` | Login with `{ username, password }`. |
| `POST /api/auth/logout` | Clear session cookie. |
| `GET /api/datasets` | Dataset metadata (counts, unique PMIDs). |
| `GET /api/items?dataset=qa&offset=0&limit=10&q=` | Paginated items. |
| `POST /api/responses` | Store validation: `{ dataset, itemId, questionId, answer, sure }`. |
| `POST /api/compare` | Record selected QA pair: `{ dataset, pmid, choiceId }`. |
| `GET /api/compare-options?dataset=qa&pmid=` | QA pairs for comparison. |
| `GET /api/summary?dataset=qa` | Aggregated counts and recent examples. |
| `GET /api/records?dataset=qa&questionId=&decision=` | Raw records for a question. |
| `GET /api/export?dataset=qa&questionId=&decision=&format=csv` | Export responses as CSV/JSON. |

## Optional: Refresh Extraction Dataset with Amplify

```bash
cd assignment5/human-expert-validation-v1
node scripts/build_extractions.mjs
```

Ensure `.env` includes `AMPLIFY_API_KEY` and `AMPLIFY_API_URL` before running.
