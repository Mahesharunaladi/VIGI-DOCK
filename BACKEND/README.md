# 🛡️ VigiDock AI Backend

> **Intelligent DevSecOps Container & Kubernetes Security Analysis Engine** powered by **Trivy CLI** and **Google Gemini AI**.

---

## 🏗️ Architecture Overview

```
                        ┌─────────────────────────────────────────┐
                        │            Frontend / Client            │
                        └────────────────────┬────────────────────┘
                                             │ HTTP / REST
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │          Express.js REST API            │
                        │       (Auth, Validation, Multer)        │
                        └───────┬─────────────────────────┬───────┘
                                │                         │
             ┌──────────────────▼──────┐           ┌──────▼──────────────────┐
             │   BullMQ + Redis Queue  │           │   Report Service        │
             │   (Async Scan Workers)  │           │   (PDFKit Generator)    │
             └──────────┬──────────────┘           └─────────────────────────┘
                        │
       ┌────────────────┴────────────────┐
       ▼                                 ▼
┌───────────────┐               ┌─────────────────┐
│   Trivy CLI   │               │ Google Gemini AI│
│ Scanner Engine│               │ Remediation &   │
│ (CVEs & K8s)  │               │ Code Patching   │
└───────┬───────┘               └────────┬────────┘
        │                                │
        └────────────────┬───────────────┘
                         ▼
             ┌───────────────────────┐
             │  MongoDB / Memory DB  │
             │   (Scan History)      │
             └───────────────────────┘
```

---

## 🚀 Tech Stack

- **Runtime / Framework:** Node.js & Express.js
- **Vulnerability Scanner:** Aqua Security Trivy CLI (Docker images, Dockerfiles, Kubernetes manifests)
- **AI Engine:** Google Gemini API (`@google/generative-ai`) for plain-English insights, root-cause analysis, and automatic configuration hardening
- **Job Queue:** BullMQ + Redis (with resilient automatic in-memory fallback for local dev)
- **Database:** MongoDB (via Mongoose) with automatic resilient in-memory repository store fallback
- **Report Engine:** PDFKit for professional downloadable PDF audit reports
- **Security & Utilities:** Helmet, CORS, Morgan, Multer, UUID

---

## 📂 Project Structure

```
backend/
├── src/
│   ├── config/
│   │   ├── db.js             # Database connection setup (with fallback)
│   │   └── aiConfig.js       # Google Gemini client setup
│   ├── controllers/
│   │   ├── scan.controller.js # Route logic for scans (Docker & K8s)
│   │   ├── ai.controller.js   # Route logic for requesting AI explanations
│   │   └── report.controller.js # PDF report generation route logic
│   ├── services/
│   │   ├── trivy.service.js   # Executes Trivy CLI commands
│   │   ├── ai.service.js      # Prompts Gemini for explanations & remediation
│   │   └── pdf.service.js     # Builds downloadable PDF reports
│   ├── queues/
│   │   └── scan.queue.js      # BullMQ queue & background worker
│   ├── routes/
│   │   ├── scan.routes.js     # API endpoints for triggering/getting scans
│   │   ├── ai.routes.js       # API endpoints for AI insights & chat
│   │   └── report.routes.js   # API endpoints for downloading PDF reports
│   ├── middlewares/
│   │   ├── errorHandler.js   # Centralized error handling middleware
│   │   └── upload.js         # Multer middleware for K8s YAML & Dockerfile uploads
│   ├── models/
│   │   └── scan.model.js     # Unified Mongoose & Repository scan model
│   └── app.js                # Express app setup and server listener
├── .env                      # API keys and environment variables
├── .env.example              # Environment variables template
├── package.json
└── README.md
```

---

## ⚙️ Quick Start

### 1. Install Dependencies

```bash
cd backend
npm install
```

### 2. Configure Environment Variables

Create `.env` from `.env.example`:

```bash
cp .env.example .env
```

Edit `.env` with your Google Gemini API key:

```env
PORT=5000
NODE_ENV=development
CORS_ORIGIN=*

# Google Gemini API Key (Get at https://aistudio.google.com/)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-1.5-flash

# Optional: MongoDB URI
MONGODB_URI=mongodb://localhost:27017/vigidock

# Optional: Redis (BullMQ queue)
REDIS_HOST=127.0.0.1
REDIS_PORT=6379

# Trivy Configuration
TRIVY_BINARY_PATH=trivy
ENABLE_MOCK_FALLBACK=true
```

> **Note on Zero-Config Dev Mode:** If MongoDB, Redis, or Trivy are not installed, VigiDock AI automatically uses resilient in-memory stores and mock engines so you can develop and test immediately without friction.

### 3. Start the Server

```bash
# Production mode
npm start

# Development mode with hot-reload
npm run dev
```

The server starts at `http://localhost:5000`.

---

## 📡 API Endpoints Reference

### 🔍 1. Vulnerability & Configuration Scans

#### `POST /api/scans/image`
Queue or run a Docker image scan.

**Request Body:**
```json
{
  "image": "nginx:alpine",
  "sync": false
}
```

**Response (202 Accepted):**
```json
{
  "success": true,
  "message": "Container image scan queued successfully.",
  "data": {
    "scanId": "c4d3b6a1-9b10-410a-8a40-520e181e5927",
    "target": "nginx:alpine",
    "status": "QUEUED",
    "pollUrl": "/api/scans/c4d3b6a1-9b10-410a-8a40-520e181e5927"
  }
}
```

#### `POST /api/scans/file`
Upload and scan a Kubernetes YAML manifest or Dockerfile (`multipart/form-data`).

- **Field `file`:** Kubernetes YAML or Dockerfile.
- **Field `targetType`:** `kubernetes-yaml` or `dockerfile` (optional).
- **Field `sync`:** `true` or `false` (optional).

#### `GET /api/scans/:id`
Get full scan status, security score, CVE vulnerability list, misconfigurations, and AI analysis.

#### `GET /api/scans`
List past scans with pagination (`?limit=20&offset=0`).

---

### 🤖 2. Gemini AI Insights & Remediation

#### `POST /api/ai/explain-vulnerability`
Get a developer-friendly plain-English breakdown of a specific CVE.

**Request Body:**
```json
{
  "vulnerabilityId": "CVE-2024-21626",
  "pkgName": "runc",
  "installedVersion": "1.1.11",
  "fixedVersion": "1.1.12",
  "severity": "CRITICAL",
  "description": "Container breakout via file descriptor leak."
}
```

#### `POST /api/ai/remediate-config`
Automatically patch and harden Kubernetes manifests or Dockerfiles.

**Request Body:**
```json
{
  "rawContent": "apiVersion: apps/v1\nkind: Deployment\n...",
  "targetType": "kubernetes-yaml",
  "misconfigurations": [
    { "id": "KSV001", "message": "Container running as root" }
  ]
}
```

#### `POST /api/ai/re-analyze/:scanId`
Re-run Gemini AI analysis on a previous scan.

#### `POST /api/ai/chat`
Interactive DevSecOps AI chatbot for container defense.

**Request Body:**
```json
{
  "message": "How do I secure my Node.js Docker container against root escalation?",
  "scanId": "optional-scan-id"
}
```

---

### 📄 3. Security Reports

#### `GET /api/reports/:scanId/pdf`
Stream and download a branded, publication-ready PDF security audit report.

#### `GET /api/reports/:scanId/summary`
Get an executive summary JSON payload for dashboard visualizations.

---

### 🩺 4. Health & Status

#### `GET /api/health`
Check API health, Gemini AI readiness, and active configuration.

---

## 🛠️ Installing Trivy Scanner (Optional)

To enable live local scanning with Trivy:

- **macOS (Homebrew):**
  ```bash
  brew install aquasecurity/trivy/trivy
  ```
- **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt-get install wget apt-transport-https gnupg lsb-release
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
  echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
  sudo apt-get update && sudo apt-get install trivy
  ```
- **Docker:**
  ```bash
  docker run -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image nginx:alpine
  ```

---

## 📜 License
MIT © 2026 VigiDock Team
