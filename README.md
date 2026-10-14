# VigiDock AI

VigiDock is a small security workspace for developers who want to check their container images and Kubernetes manifests before those changes reach production.

It brings together:

- Trivy scans for Docker images and Kubernetes YAML files
- EPSS scores to help prioritize real-world exploit risk
- An interactive React dashboard for reviewing findings
- AI-assisted explanations and remediation suggestions
- PDF and JSON security reports
- A local H2 database for scan history during development

The project has two parts: a Spring Boot API in `BACKEND` and a React/Vite dashboard in `FRONTEND`.

## Before you start

Install the following tools:

- Java 17 or newer
- Maven
- Node.js and npm
- Trivy

On macOS with Homebrew, Trivy can be installed with:

```bash
brew install aquasecurity/trivy/trivy
```

Check that it is available:

```bash
trivy --version
```

Gemini is optional. If `GEMINI_API_KEY` is not set, VigiDock uses a deterministic fallback explanation so the rest of the workflow still works locally.

## Start the backend

Open a terminal in the project and run:

```bash
cd BACKEND
mvn spring-boot:run
```

The API starts at [http://localhost:8080](http://localhost:8080).

By default, the backend uses a file-based H2 database under `BACKEND/data`. No PostgreSQL setup is required for local development.

Useful backend URLs:

- Scan history: `GET /api/scan`
- Docker image scan: `POST /api/scan/docker`
- Kubernetes manifest scan: `POST /api/scan/k8s`
- PDF report: `GET /api/reports/download/{scanId}`
- H2 console: [http://localhost:8080/h2-console](http://localhost:8080/h2-console)

## Start the frontend

In a second terminal:

```bash
cd FRONTEND
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

The frontend connects to `http://localhost:8080/api` by default. To use another backend URL, create `FRONTEND/.env` and add:

```text
VITE_API_URL=http://localhost:8080/api
```

## Try a scan

1. Open the dashboard and choose **Image Scanner**.
2. Enter an image such as `alpine:3.12` or select a preset.
3. Click **Scan Image**.
4. Wait while Trivy scans the image and EPSS data is collected.
5. Open a finding to view its severity, exploit probability, AI explanation, remediation diff, and report actions.

For Kubernetes, choose **Manifest Auditor** and upload a `.yaml` or `.yml` file. The backend runs Trivy config scanning and returns misconfiguration findings.

## Reports and AI explanations

Completed scans are saved to the local H2 database and appear in **Reports**. From there you can download an executive PDF report.

The AI drawer contains:

- A beginner-friendly summary
- Container runtime or Kubernetes impact
- A recommended next step
- An automated Dockerfile or Kubernetes patch when available
- Copy and PDF download actions

Without a Gemini key, the backend returns a safe local fallback explanation. To enable Gemini responses, set `GEMINI_API_KEY` before starting the backend.

## Build and verify

Backend:

```bash
cd BACKEND
mvn test
```

Frontend:

```bash
cd FRONTEND
npm run build
```

## Troubleshooting

### `ERR_CONNECTION_REFUSED` on port 8080

The backend is not running. Start it from the `BACKEND` directory with `mvn spring-boot:run`.

### `Missing script: dev`

The command was run from the repository root. Run it from `FRONTEND`, where the Vite `package.json` lives.

### Trivy command not found

Install Trivy and confirm `trivy --version` works in the same terminal used to start the backend. You can also set an explicit path with `TRIVY_BINARY_PATH`.

### No scans appear in the dashboard

Confirm both services are running, refresh the page, and check that `GET http://localhost:8080/api/scan` returns HTTP `200`.

## Project layout

```text
BACKEND/   Spring Boot API, Trivy integration, persistence, AI, and reports
FRONTEND/  React/Vite security dashboard
```

VigiDock is intended for local development and demonstration. Review generated findings and remediation patches before applying them to production workloads.
