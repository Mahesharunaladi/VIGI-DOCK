# 🛡️ VIGI-DOCK

> **VigiDock AI** — Intelligent DevSecOps Platform for Container Security Analysis, Kubernetes Manifest Hardening, and Automated AI-Powered Remediation.

---

## 🌟 Overview

VigiDock AI integrates industry-standard vulnerability scanning via **Trivy** with generative intelligence powered by **Google Gemini AI**. It scans container images, Dockerfiles, and Kubernetes manifests, identifies vulnerabilities (CVEs) and security misconfigurations, calculates dynamic security scores, and generates actionable AI remediations alongside publication-ready PDF security audit reports.

---

## 🏗️ Monorepo Structure

```
VIGI-DOCK/
├── BACKEND/                  # Node.js & Express REST API Backend
│   ├── src/
│   │   ├── config/          # Database & AI configurations
│   │   ├── controllers/     # Scan, AI, and Report controllers
│   │   ├── middlewares/     # Upload & error handling middlewares
│   │   ├── models/          # Scan data models (Mongoose / In-memory fallback)
│   │   ├── queues/          # BullMQ background job queues
│   │   ├── routes/          # REST API endpoints
│   │   ├── services/        # Trivy scanner, Gemini AI, & PDF generation services
│   │   └── app.js           # Express application entrypoint
│   ├── .env.example         # Backend environment configuration template
│   ├── package.json         # Backend dependencies
│   └── README.md            # Detailed backend documentation
│
├── FRONTEND/                 # Frontend User Interface
│   └── Index.html           # Interactive Security Dashboard UI
│
├── .gitignore               # Ignored files and directories
└── README.md                # Project documentation
```

---

## 🚀 Quick Start

### 1. Backend Setup

```bash
cd BACKEND
npm install
cp .env.example .env
npm run dev
```

The backend server runs at `http://localhost:5000`.

### 2. Frontend Setup

Open `FRONTEND/Index.html` directly in your browser, or serve it using any static HTTP server (e.g. `npx serve FRONTEND` or Live Server).

---

## 🛠️ Key Features

- 🔍 **Trivy Vulnerability & Misconfig Scanning:** Scan Docker images, Dockerfiles, and K8s YAML manifests.
- 🤖 **Google Gemini AI Remediation:** Plain-English CVE explanations, root-cause insights, and automatic manifest patching.
- 📊 **Security Scoring Engine:** Dynamic container risk rating from 0 to 100.
- 📄 **PDF Security Reports:** Downloadable, publication-ready audit reports generated via PDFKit.
- ⚡ **Resilient Zero-Config Architecture:** Automatic fallback to in-memory queues and repositories for development without external setup hurdles.

---

## 📜 License
MIT © 2026 VigiDock Team
