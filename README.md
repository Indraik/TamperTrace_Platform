# 🛡️ TamperTrace Platform

> **Production-Grade Automated Website Defacement Detection, Threat Intelligence & Instant Disaster Recovery**

TamperTrace_Platform is an enterprise-ready Python Full-Stack cybersecurity platform designed to continuously monitor web applications against unauthorized alterations, detect malicious dependencies using VirusTotal, notify system administrators in real-time across Email and WhatsApp, and provide one-click disaster recovery to verified clean baseline states.

---

## ✨ Core Capabilities

- 🔍 **Dual-Layer Defacement Detection**:
  - **Computer Vision (OpenCV & SSIM)**: Structural pixel-level difference analysis and visual heatmap generation.
  - **Semantic HTML Analysis (BeautifulSoup)**: Core content and heading tracking while stripping noise (ads, carousels, dynamic scripts) to prevent false positives.
- ⏱️ **DOM Stabilization Engine**:
  - Injects a JavaScript `MutationObserver` to ensure all dynamic elements, animations, and lazy-loaded assets have settled before snapshot capture.
- 🔄 **Multi-Stage Baseline Lifecycle**:
  - `WARMUP` ➔ `BASELINE` (locks verified safe snapshot in database) ➔ `ACTIVE` (live scanning).
- 🧠 **Threat Intelligence Integration**:
  - Continuous integration with the **VirusTotal API v3**, scanning target URLs across 70+ security engines for malware, phishing, and crypto-mining risks.
- 🚨 **Multi-Channel Real-Time Alerting**:
  - **Rich HTML Email (SMTP)**: Direct inline side-by-side Before, After, and Diff images with one-click `[Approve]` and `[Deny]` action buttons.
  - **WhatsApp Alerting (Twilio)**: Automated instant incident dispatch to the administrator's phone.
- 🔁 **One-Click Disaster Recovery**:
  - Reverts tampered target website templates back to their last verified safe baseline snapshot with automated backup creation (`.bak`).
- 📊 **Executive PDF Audit Reports**:
  - Generates downloadable compliance and threat audit PDF reports using ReportLab.

---

## 🏗️ Architecture & Directory Structure

Built using a **Modular Flask Full-Stack Monolith** adhering to the **Application Factory Pattern**, **Flask Blueprints**, a **Domain Service Layer**, a **Repository Data Access Layer**, and an **Isolated Background Task Engine**:

```text
TamperTrace_Platform/
│
├── app/
│   ├── __init__.py                # Flask Application Factory (create_app)
│   ├── database.py                # MongoDB connection pooling & index management
│   │
│   ├── routes/                    # Presentation Layer (Thin Flask Blueprints)
│   │   ├── __init__.py            # Blueprint registry
│   │   ├── dashboard.py           # Dashboard metrics & overview (/)
│   │   ├── urls.py                # URL onboarding, approvals, denials, deletion
│   │   ├── threats.py             # Threat matrix & on-demand VT scanning
│   │   ├── recovery.py            # Disaster recovery rollback API (/restore)
│   │   ├── alerts.py              # Forensic incident logs view (/alerts)
│   │   └── system.py              # Scheduler toggle, PDF download, navigation fallbacks
│   │
│   ├── services/                  # Framework-Independent Domain Services
│   │   ├── __init__.py
│   │   ├── monitoring_service.py  # Orchestrates full monitoring cycle & baseline staging
│   │   ├── browser_service.py     # Headless Firefox lifecycle & DOM stabilization
│   │   ├── incident_service.py    # Evidence preservation & incident state management
│   │   ├── alert_service.py       # Notification coordinator for Email & WhatsApp
│   │   ├── restore_service.py     # Target template backup & safe rollback
│   │   ├── virustotal_service.py  # Threat categorization & cache policies
│   │   └── report_service.py      # ReportLab audit PDF generator
│   │
│   ├── detection/                 # Detection Algorithms & Noise Filtering
│   │   ├── __init__.py
│   │   ├── html_analyzer.py       # Semantic HTML feature extraction & noise stripping
│   │   ├── visual_analyzer.py     # SSIM difference computation & diff image generation
│   │   └── decision_engine.py     # Pure TAMPER vs IGNORE decision logic
│   │
│   ├── repositories/              # Data Access Layer (MongoDB abstraction)
│   │   ├── __init__.py
│   │   ├── url_repository.py      # Monitored URLs CRUD & status tracking
│   │   ├── scan_repository.py     # Clean snapshots & baseline storage
│   │   ├── incident_repository.py # Forensic incident logs & diff records
│   │   ├── threat_repository.py   # VirusTotal scan caching & results
│   │   ├── settings_repository.py # System configuration flags (scheduler/threat intel)
│   │   └── restore_repository.py  # Disaster recovery audit trails
│   │
│   ├── integrations/              # External Third-Party Clients
│   │   ├── __init__.py
│   │   ├── virustotal.py          # Low-level VirusTotal API v3 integration
│   │   ├── email.py               # SMTP client with inline CID image attachments
│   │   └── whatsapp.py            # Twilio REST API client
│   │
│   ├── workers/                   # Asynchronous Background Task Daemon
│   │   ├── __init__.py
│   │   └── monitoring_worker.py   # Thin worker process running the monitoring loop
│   │
│   └── utils/                     # Shared Reusable Utilities
│       ├── __init__.py
│       ├── hashing.py             # SHA-256 and MD5 hashing helpers
│       ├── file_manager.py        # Safe file copying, backups, and deletion
│       ├── validators.py          # URL and email syntax validation
│       └── logger.py              # Standardized console logging
│
├── templates/                     # Jinja2 HTML Templates (Cyber & Glassmorphism Theme)
│   ├── dashboard.html
│   ├── add_url.html
│   ├── alerts.html
│   └── threat_dashboard.html
│
├── static/                        # Frontend Assets
│   ├── css/theme.css
│   ├── screenshots/               # Active runtime screenshots (gitignored)
│   └── archive/                   # Archived historical defacement evidence (gitignored)
│
├── tests/                         # Automated Unit & Integration Test Suite
│   ├── test_routes.py
│   ├── test_detection.py
│   ├── test_monitoring.py
│   ├── test_restore.py
│   └── test_threat_intelligence.py
│
├── scripts/                       # Operational & Diagnostic Scripts
│   └── check_api_key.py           # VirusTotal credentials validator
│
├── config.py                      # Centralized configuration (Development / Production / Testing)
├── run.py                         # Web Server Entry Point (Auto-venv detection)
├── worker.py                      # Background Worker Entry Point (Auto-venv detection)
├── app.py                         # Legacy backward-compatible web wrapper
├── scheduler.py                   # Legacy backward-compatible worker wrapper
├── requirements.txt               # Pinned Python dependencies
├── .env.example                   # Sanitized configuration template
└── .gitignore                     # Git exclusion rules
```

---

## 🔁 End-to-End Workflow

```
[Admin Registers URL]
        │
        ▼
[BrowserService] ──► Captures initial baseline screenshot & SHA-256 hash
        │
        ▼
[UrlRepository] ──► Stores record (Stage: WARMUP)
        │
        ▼
[Autonomous Worker] ──► Polls active sites every 35s
        │
        ├── WARMUP   ──► Re-verifies page consistency ──► Advances to BASELINE
        ├── BASELINE ──► Stores verified safe snapshot in ScanRepository ──► Advances to ACTIVE
        └── ACTIVE   ──► Loads DOM with MutationObserver
                             │
                             ├── VisualAnalyzer (SSIM > 8%)
                             └── HtmlAnalyzer (Title, H1/H2, text delta > 20%)
                                     │
                                     ▼
                              [DecisionEngine]
                                     │
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
              [IGNORE]                               [TAMPER]
         (Ads/Sliders Noise)                   (Defacement Confirmed)
                  │                                     │
         Silently update baseline                       ├── Preserve evidence in static/archive/
                                                        ├── Record incident in IncidentRepository
                                                        ├── Dispatch Email (with inline diffs)
                                                        ├── Dispatch WhatsApp alert via Twilio
                                                        └── Freeze scans pending admin action
                                                                │
                                                                ▼
                                                       [Admin Resolution]
                                                   Approve / Deny / Restore
```

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone https://github.com/Indraik/TamperTrace_Platform.git
cd TamperTrace_Platform
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your credentials:
```bash
cp .env.example .env
```

### 4. Run the Web Application
```bash
python run.py
```
*The web dashboard is available at: [http://127.0.0.1:5000](http://127.0.0.1:5000)*

### 5. Run the Background Monitoring Worker
In a second terminal window:
```bash
python worker.py
```

### 6. Run the Automated Test Suite
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 🔒 Security Considerations

- **Secrets Management**: Sensitive credentials (`VT_API_KEY`, `EMAIL_PASSWORD`, `TWILIO_AUTH_TOKEN`, `FLASK_SECRET_KEY`) are stored in `.env` and excluded from git via `.gitignore`.
- **Pre-execution Backup**: [RestoreService](file:///d:/TamperTraceProject/app/services/restore_service.py) automatically generates a timestamped `.bak` copy of the target template before applying baseline restorations.
- **Automated Re-exec**: Entry points ([run.py](file:///d:/TamperTraceProject/run.py), [worker.py](file:///d:/TamperTraceProject/worker.py)) automatically re-execute inside the project virtual environment even if started from a global terminal, preventing dependency mismatch errors.

---

## 📄 License
This project is licensed under the MIT License.
