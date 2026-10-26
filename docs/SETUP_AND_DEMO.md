# IoT Honeypot Monitor — Setup and Demonstration Guide

**Step-by-Step Installation, Startup, Verification, and Live Demo Walkthrough**  
*Target Environment: Windows 10/11 (PowerShell)*

---

## 1. Prerequisites

Ensure the following tools are installed on your workstation:
- **Python**: 3.11, 3.12, or 3.13 (verified on Python 3.13.7 64-bit)
- **Node.js**: v18.0.0 or higher (with npm)
- **Git**: Installed and available in PATH
- **Web Browser**: Chrome, Edge, Firefox, or Safari

---

## 2. Installation & Setup

### 2.1 Backend Setup

Open a PowerShell terminal at the repository root:

```powershell
# Navigate to the backend directory
cd "C:\Projects\IOT honey pot monitoring\backend"

# If not already present, create virtual environment:
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Install required Python packages
pip install -r requirements.txt
```

Verify backend installation by running the automated test suite:
```powershell
python -m pytest tests -v
```
*Expected result: 88 passed tests in ~5 seconds.*

### 2.2 Frontend Setup

Open a second PowerShell terminal:

```powershell
# Navigate to the frontend directory
cd "C:\Projects\IOT honey pot monitoring\frontend"

# Install Node dependencies (if needed)
npm install

# Run TypeScript compilation and production build check
npm run build
```
*Expected result: `built in ~1s` with 0 TypeScript errors.*

---

## 3. Starting the Application

### Terminal 1: Start FastAPI Backend
```powershell
cd "C:\Projects\IOT honey pot monitoring\backend"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base URL: `http://127.0.0.1:8000`
- Interactive Swagger API Docs: `http://127.0.0.1:8000/docs`
- Redoc Documentation: `http://127.0.0.1:8000/redoc`

### Terminal 2: Start React Frontend Dashboard
```powershell
cd "C:\Projects\IOT honey pot monitoring\frontend"
npm run dev
```
- Dashboard URL: `http://localhost:5173`

---

## 4. Live Demonstration Walkthrough (Submission Presentation)

Follow this structured 5-minute walkthrough during your project demonstration:

### Step 1: System Baseline & Dual-Theme Review
1. Open `http://localhost:5173` in your browser.
2. Note the **Sticky Header**: Shows service identity and real-time auto-refresh indicator.
3. Click the **Theme Toggle** button in the top right:
   - Switch between **Warm Cream** (Light Mode `#F7F3EB`) and **True Black** (Dark Mode `#000000`).
   - Notice the deliberate typography: Space Grotesk headings, Instrument Serif italic accents, crisp Inter body text.
4. Observe the **Status Bar Cards**:
   - Backend API Server: Displays green dot and `Online (FastAPI)` with real response latency.
   - Hardware Device Status: Displays `FRDM-RW612 Not Connected` (truthfully reflecting that the physical board is pending deployment, rather than showing fake mock connectivity).

### Step 2: Normal Traffic Ingestion (Clean Request)
1. Scroll down to the **Backend Detection Testing Panel** (or click the **Simulate Telemetry** button in the hero section).
2. Click **Normal Log (/status)**.
3. **Observed Behavior**:
   - The feedback box confirms HTTP request log recorded for `/status`.
   - The **Total Requests** counter increments.
   - The **Clean Traffic** percentage updates.
   - The **HTTP Request Logs** table displays the new GET request with a green `200` status badge.
   - **No security alerts are triggered** because `/status` is an authorized allowlisted path.

### Step 3: Reconnaissance & Unknown-Endpoint Detection (Rule R1)
1. Click **Probe Unknown (/admin)** in the Testing Panel.
2. **Observed Behavior**:
   - The client submits a probe for unallowed path `/admin`.
   - The backend detection engine evaluates Rule R1, identifies `/admin` as outside `{/status, /info, /config}`, and automatically generates an `unknown_endpoint` security event.
   - In the **Security Events** table, a new warning event appears: `Request received for unknown endpoint: '/admin'`.
   - In the **Aggregated Stats Overview**, the **Security Events** counter increments immediately.

### Step 4: Rapid Sequential Burst (Sliding-Window Rule R2/R3)
1. Click **Traffic Burst (5x)** in the Testing Panel.
2. **Observed Behavior**:
   - 5 requests are delivered in rapid sequence (100ms intervals).
   - In the **HTTP Request Logs** table, all 5 entries appear with precise millisecond timestamps.
   - The in-memory sliding-window tracker increments without dropped records or database locking conflicts.

### Step 5: Direct Hardware Security Event
1. Click **Manual Critical Event** in the Testing Panel.
2. **Observed Behavior**:
   - Sends a direct `POST /api/events` simulating an enclosure tamper GPIO sensor trip.
   - A red **Critical** badge appears in the **Security Events** table displaying `tamper_detected`.
   - Statistics breakdown reflects the critical severity distribution immediately.

### Step 6: Interactive Swagger Contract Inspection
1. Open `http://127.0.0.1:8000/docs` in another tab.
2. Demonstrate the live OpenAPI schemas matching `docs/API_CONTRACT.md`.
