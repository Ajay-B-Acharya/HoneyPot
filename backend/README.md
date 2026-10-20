# IoT Honeypot Monitor — Backend

FastAPI backend for the IoT Honeypot Monitor system.

## Quick Start

### Prerequisites

- Python 3.11 or later

### Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create configuration
copy .env.example .env
```

### Run the Server

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API will be available at:
- **API**: http://127.0.0.1:8000/api
- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc

### Run Tests

```bash
pytest -v
```

## Configuration

Copy `.env.example` to `.env` and adjust values:

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `iot-honeypot-backend` | Application name |
| `APP_VERSION` | `0.1.0` | Application version |
| `DEBUG` | `false` | Enable debug logging |
| `DATABASE_URL` | `sqlite:///./honeypot.db` | Database connection string |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Allowed frontend origins |
| `DEVICE_INACTIVE_THRESHOLD_SECONDS` | `300` | Inactive device threshold |

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI application factory
│   ├── config.py         # Settings from environment
│   ├── database.py       # SQLAlchemy engine and session
│   ├── models/           # ORM models
│   ├── schemas/          # Pydantic validation schemas
│   ├── routers/          # API endpoint handlers
│   └── services/         # Business logic layer
├── tests/                # Automated test suite
├── .env.example          # Environment template
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## Database

SQLite is used for development. The database file (`honeypot.db`) is created automatically on first startup.

To switch to PostgreSQL, update `DATABASE_URL` in `.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/honeypot
```

> [!WARNING]
> This prototype is intended for a trusted development environment.
> Access control and authenticated device communication must be implemented
> before broader deployment. Do not expose the API directly to the public internet.
