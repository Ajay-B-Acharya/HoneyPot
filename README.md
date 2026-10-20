# IoT Honeypot Monitor

**Embedded Network Intrusion Detection System Using NXP FRDM-RW612**

A distributed IoT cybersecurity monitoring system designed to capture, classify, and visualize network attacks against embedded IoT hardware.

---

## 1. System Overview & Architecture

```
┌─────────────────────────────────┐
│       NXP FRDM-RW612            │
│  (Embedded Honeypot Firmware)   │
└────────────────┬────────────────┘
                 │ HTTP (Telemetry / Events / Logs)
                 ▼
┌─────────────────────────────────┐
│        FastAPI Backend          │
│   • SQLite Database             │
│   • Pydantic Validations        │
│   • Threat Aggregation Engine   │
└────────────────┬────────────────┘
                 │ REST API (JSON / UTC ISO 8601)
                 ▼
┌─────────────────────────────────┐
│    React + TypeScript UI        │
│   • Intrusion Dashboard         │
│   • Real-Time Threat Metrics    │
│   • Log & Event Data Grids      │
└─────────────────────────────────┘
```

The system comprises three independent layers:
1. **Embedded Honeypot**: Deployed on NXP FRDM-RW612 dual-core Wi-Fi/BLE microcontroller boards, exposing realistic services and logging unauthorized interaction.
2. **Backend Engine**: High-performance FastAPI server running on Python 3.11+ with SQLite, recording request logs, classifying threat levels, generating security events, and compiling intrusion statistics.
3. **Frontend Dashboard**: Independent React + TypeScript interface providing security operations personnel with real-time visibility into active honeypots, severity breakdowns, and threat logs.

---

## 2. Technology Stack

- **Backend:** Python 3.11+, FastAPI, Uvicorn, SQLAlchemy 2.x, SQLite, Pydantic v2, pytest, httpx.
- **Frontend:** React, TypeScript, Vite (developed independently in `frontend/`).
- **Database:** SQLite with WAL mode enabled (fully modular SQLAlchemy design ready for PostgreSQL migration).
- **Communication:** Standardized RESTful JSON over HTTP with CORS security headers.

---

## 3. Monorepo Repository Structure

```text
iot-honeypot-monitor/
├── backend/                  # FastAPI backend, models, database & test suite
│   ├── app/
│   │   ├── models/           # SQLAlchemy 2.0 ORM models (request_log, security_event)
│   │   ├── schemas/          # Pydantic validation schemas
│   │   ├── routers/          # API endpoints (/health, /events, /logs, /stats, /device)
│   │   ├── services/         # Business logic & database aggregation queries
│   │   ├── config.py         # Application settings loaded via python-dotenv
│   │   ├── database.py       # Engine, sessionmaker, and initialization
│   │   └── main.py           # FastAPI entrypoint with CORS & lifespan handling
│   ├── tests/                # Automated pytest suite (in-memory SQLite)
│   ├── .env.example          # Environment variables template
│   ├── .gitignore            # Backend git exclusions
│   ├── requirements.txt      # Python dependencies
│   └── README.md             # Detailed backend setup guide
│
├── frontend/                 # React + TypeScript UI (Developer 2 workspace)
│   └── README.md             # Integration guide and frontend instructions
│
├── docs/                     # Shared team contracts & guides
│   ├── API_CONTRACT.md       # Complete REST API specification
│   ├── INTEGRATION_GUIDE.md  # Step-by-step frontend integration & TypeScript types
│   └── DEVELOPMENT_WORKFLOW.md # Parallel development workflow & Git rules
│
├── .gitignore                # Root monorepo git exclusions
└── README.md                 # This documentation
```

---

## 4. Collaborative Development Division

This repository is structured for concurrent development by two engineers:

- **Developer 1 (Backend):** Responsible for `backend/`, API router definitions, database models, aggregation queries, and unit/integration tests.
- **Developer 2 (Frontend):** Responsible for `frontend/`, React components, charting libraries, and state management.
- **Shared Agreement:** `docs/API_CONTRACT.md` serves as the binding contract between frontend and backend. Neither developer alters the contract without mutual review.

---

## 5. Quick Start

### Starting the Backend
```bash
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
API endpoints will be live at `http://127.0.0.1:8000/api` with interactive documentation at `http://127.0.0.1:8000/docs`.

### Running Automated Tests
```bash
cd backend
pytest -v
```

### Connecting the Frontend
Refer to [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) for pre-typed TypeScript interfaces, native `fetch` client code, and instructions on configuring `VITE_API_BASE_URL`.

---

## 6. Security & Prototype Scope

> [!WARNING]
> This system is designed as a security monitoring prototype intended for a trusted lab or development network.
> - Access control, API tokens/mTLS, and rate limiting must be introduced prior to public network exposure.
> - Automated retaliatory measures or destructive responses against attacking IPs are strictly out of scope.
