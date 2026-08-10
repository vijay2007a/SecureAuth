# SecureAuth Lab

SecureAuth Lab is a local cybersecurity research environment for simulating password spray and credential stuffing activity against synthetic test accounts, then detecting and analyzing the resulting events in real time.

The existing React + Vite frontend is preserved. A FastAPI backend now provides authenticated APIs, live WebSocket updates, simulation execution, alerting, analytics, and model metadata.

## Architecture

- Frontend: React, Vite, TypeScript, TailwindCSS, Recharts
- Backend: FastAPI, Pydantic, WebSockets
- Auth: Firebase Authentication token verification in production, dev-token fallback locally
- Storage: Firestore persistence through Firebase Admin SDK when configured, with a local in-memory fallback for offline development
- Detection: rule-based scoring plus IsolationForest and RandomForest training when enough data exists

## Requirements

- Node.js 18+
- Python 3.11+
- Firebase project for production use

## Environment Variables

Create a `.env` file from `.env.example`.

Frontend:

- `VITE_API_URL`
- `VITE_WS_URL`
- `VITE_DEV_AUTH_TOKEN`

Backend:

- `AUTH_MODE`
- `DEV_ADMIN_TOKEN`
- `DEV_ANALYST_TOKEN`
- `DEV_USER_TOKEN`
- `CORS_ORIGINS`
- `USE_FIRESTORE`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY`
- `GOOGLE_APPLICATION_CREDENTIALS`

## Firebase Setup

For production:

- Enable Firebase Authentication
- Create a Firestore database
- Provide service account credentials through environment variables or `GOOGLE_APPLICATION_CREDENTIALS`
- Set `USE_FIRESTORE=true`

The backend verifies Firebase ID tokens with Firebase Admin SDK when `AUTH_MODE` is not `dev`.
The live websocket emits `simulation.started`, `simulation.progress`, `login_event`, `detection_result`, `alert_created`, and `simulation.completed` events during simulations.

## Local Development

Install frontend dependencies:

```bash
npm install
```

Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Start the backend:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Start the frontend:

```bash
npm run dev
```

## Testing

Backend tests:

```bash
python -m unittest backend.tests.test_api -v
```

Frontend build:

```bash
npm run build
```

## API Overview

- `GET /api/health`
- `GET /api/me`
- `GET /api/dashboard`
- `GET /api/test-accounts`
- `POST /api/test-accounts`
- `POST /api/test-accounts/generate`
- `GET /api/ip-controls`
- `POST /api/ip-controls`
- `GET /api/login-events`
- `POST /api/simulations/password-spray`
- `POST /api/simulations/credential-stuffing`
- `POST /api/simulations/custom`
- `GET /api/alerts`
- `PUT /api/alerts/{id}`
- `GET /api/analytics`
- `GET /api/models`
- `POST /api/models/retrain`
- `GET /api/reports`
- `POST /api/reports/generate`
- `GET /ws/live?token=...`

## Notes

- This project is intended for synthetic local lab use only.
- No plaintext passwords are stored or sent to the frontend.
- No PostgreSQL, SQLite, or Docker infrastructure is used.
