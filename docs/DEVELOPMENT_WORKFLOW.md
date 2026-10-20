# IoT Honeypot Monitor — Collaborative Development Workflow

This document explains how **Developer 1 (Backend)** and **Developer 2 (Frontend)** can develop concurrently, independently, and effectively without stepping on each other's work.

---

## 1. Team Responsibilities & Folder Ownership

To prevent merge conflicts and maintain clean separation of concerns, strict folder ownership is enforced:

```
iot-honeypot-monitor/
├── backend/                  <-- Developer 1 (Backend) exclusive ownership
│   ├── app/
│   ├── tests/
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
│
├── frontend/                 <-- Developer 2 (Frontend) exclusive ownership
│   ├── src/
│   ├── package.json
│   ├── vite.config.ts
│   └── README.md
│
├── docs/                     <-- Shared ownership (Collaborative alignment)
│   ├── API_CONTRACT.md       <-- Primary REST contract (Source of truth)
│   ├── INTEGRATION_GUIDE.md  <-- Instructions & TypeScript examples
│   └── DEVELOPMENT_WORKFLOW.md
│
├── .gitignore                <-- Shared ownership
└── README.md                 <-- Shared ownership (Project overview)
```

### Boundary Rules
1. **Developer 1:** Does not touch `frontend/` (except for a minimal placeholder README if empty).
2. **Developer 2:** Does not modify files under `backend/`.
3. **No Cross-Module Imports:** The frontend must never attempt to import backend Python code or Pydantic models. Communication is strictly HTTP/REST over port 8000.
4. **Contract First:** Any endpoint change, parameter addition, or schema update must first be discussed and updated in `docs/API_CONTRACT.md` before altering implementation.

---

## 2. Independent Local Development Environments

Each developer runs their own independent server locally:

### Developer 1 (Backend)
- Runs FastAPI on Uvicorn: `http://127.0.0.1:8000`
- Tests with Pytest: `pytest -v` (runs against in-memory SQLite without touching dev database)
- Verifies endpoints in browser: `http://127.0.0.1:8000/docs`

### Developer 2 (Frontend)
- Runs Vite dev server: `http://localhost:5173`
- Configures API target in `frontend/.env`:
  ```env
  VITE_API_BASE_URL=http://127.0.0.1:8000/api
  ```
- Can use mock data matching `docs/API_CONTRACT.md` if working offline or while Developer 1 implements a new endpoint.

---

## 3. Git Workflow & Branching Strategy

To keep parallel work organized and safe:

### Branch Naming Conventions
- Backend features: `backend/<feature-name>` (e.g. `backend/auth-layer`, `backend/stats-aggregation`)
- Frontend features: `frontend/<feature-name>` (e.g. `frontend/event-grid`, `frontend/stats-charts`)
- Shared documentation: `docs/<topic>` (e.g. `docs/api-v2-draft`)

### Pull Request & Merge Workflow
1. Never push directly to `main`.
2. Open a Pull Request targeting `main`.
3. Verify backend tests pass (`pytest -v`) before merging any backend PR.
4. If an API contract change is introduced in a PR, both developers must review and approve it.

---

## 4. Preventing Accidental Secret & Artifact Commits

Both `.gitignore` files (root and `backend/`) are configured to ignore:
- Virtual environments: `venv/`, `.venv/`, `env/`
- Node dependencies: `node_modules/`
- Local environment files: `.env`, `.env.local`
- SQLite databases: `*.db`, `*.sqlite`, `*.sqlite3`, `honeypot.db`
- Python caches: `__pycache__/`, `*.pyc`, `.pytest_cache/`
- Build artifacts: `dist/`, `build/`

**Before committing:**
Always run `git status` to ensure untracked database files (`*.db`) or `.env` files are not staged.

---

## 5. Coordinating API Contract Changes

When a feature requires modifying or adding an API endpoint:

1. **RFC Discussion:** Propose the change via chat or issue ticket.
2. **Update `docs/API_CONTRACT.md`:** Commit the updated schema, query parameters, or response format.
3. **Backend Implementation:** Developer 1 implements the FastAPI endpoint, schema, and Pytest coverage.
4. **Frontend Integration:** Developer 2 consumes the endpoint using the TypeScript interfaces documented in `docs/INTEGRATION_GUIDE.md`.

---

## 6. End-to-End Integration Testing Checklist

Before considering an end-to-end milestone complete:
1. Start the backend: `cd backend && uvicorn app.main:app --reload`
2. Start the frontend: `cd frontend && npm run dev`
3. In browser dev tools (F12 -> Network tab):
   - Confirm preflight `OPTIONS` requests receive `200` from FastAPI.
   - Confirm `GET /api/health` returns status `ok`.
   - Confirm `GET /api/stats` loads and displays dashboard cards without console errors.
   - Confirm pagination buttons on events and logs work seamlessly.
