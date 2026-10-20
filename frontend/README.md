# IoT Honeypot Monitor — Frontend

React + TypeScript dashboard for the IoT Honeypot Monitor system.

## Integration with Backend

The frontend communicates with the backend REST API. See:

- **[API Contract](../docs/API_CONTRACT.md)** — Complete endpoint reference
- **[Integration Guide](../docs/INTEGRATION_GUIDE.md)** — How to connect to the backend

### Configure API Base URL

Create a `.env` file in this directory:

```
VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

### Available Backend Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | Health check |
| `GET /api/stats` | Dashboard statistics |
| `GET /api/events` | Security events (paginated) |
| `POST /api/events` | Create security event |
| `GET /api/logs` | Request logs (paginated) |
| `POST /api/logs` | Create request log |
| `GET /api/device/status` | Device status |

### Start the Backend First

```bash
cd ../backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
