# VigiDock Frontend

Responsive React + Vite dashboard for the VigiDock Spring Boot API.

## Run locally

1. Start PostgreSQL and the backend on port `8080`.
2. Install dependencies with `npm install`.
3. Copy `.env.example` to `.env` if the API is not running at `http://localhost:8080`.
4. Start the UI with `npm run dev`.

Open `http://localhost:5173`.

The dashboard supports Docker image scans, Kubernetes manifest uploads, scan history, JSON/PDF reports, and AI explanations/remediation through the existing backend endpoints. Trivy is required by the backend for real scans; Gemini is optional.
