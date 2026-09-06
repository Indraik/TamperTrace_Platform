# 🛡️ TamperTrace

> **Automated Website Defacement Detection, Threat Intelligence & Instant Disaster Recovery Platform**

TamperTrace is a modular, production-grade Python Full-Stack security platform designed to continuously monitor websites against unauthorized modifications, detect malicious dependencies via VirusTotal, notify administrators instantly across Email and WhatsApp, and provide one-click disaster recovery to verified clean baseline states.

---

## ✨ Key Features

- 🔍 **Dual-Layer Tamper Detection**:
  - **Computer Vision (OpenCV & SSIM)**: Structural pixel-level difference analysis and visual heatmap generation.
  - **Semantic HTML Analysis (BeautifulSoup)**: Core structure and text length tracking while stripping ads, carousels, and dynamic scripts to avoid false positives.
- ⏱️ **DOM Stabilization Engine**:
  - Uses a JavaScript `MutationObserver` to ensure all dynamic elements, animations, and images have completely settled before snapshot capture.
- 🧠 **Threat Intelligence Integration**:
  - Continuous integration with the **VirusTotal API v3**, scanning target URLs across 70+ security vendors for malware, phishing, and crypto-mining indicators.
- 🚨 **Multi-Channel Instant Alerting**:
  - **Rich HTML Email (SMTP)**: Directly embeds inline side-by-side Before, After, and Diff images with one-click `[Approve]` and `[Deny]` action buttons.
  - **WhatsApp Alerting (Twilio)**: Sends instant incident notifications to the administrator's phone.
- 🔄 **One-Click Disaster Recovery**:
  - Reverts tampered target website templates back to their last verified safe baseline snapshot with automated backup creation (`.bak`).
- 📊 **Executive PDF Audit Reports**:
  - Generates downloadable compliance and threat audit PDF reports using ReportLab.

---

## 🏗️ Architecture & Tech Stack

```text
TamperTraceProject/
│
├── config.py                      # Centralized environment configuration
├── run.py                         # Web Server Entry Point (Flask)
├── worker.py                      # Background Monitoring Engine Entry Point
├── app.py                         # Backward-compatible web wrapper
├── scheduler.py                   # Backward-compatible scheduler wrapper
│
├── app/                           # Core Application Package
│   ├── __init__.py                # Application Factory (create_app)
│   ├── database.py                # MongoDB connection pooling & accessors
│   │
│   ├── services/                  # Business Logic Layer
│   │   ├── browser_service.py     # Headless Firefox & DOM stabilization
│   │   ├── detection_service.py   # SSIM visual diff & HTML semantic diff
│   │   ├── virustotal_service.py  # VirusTotal threat intelligence
│   │   ├── alert_service.py       # SMTP Email & Twilio WhatsApp
│   │   ├── restore_service.py     # Safe baseline file rollback
│   │   └── report_service.py      # ReportLab audit PDF generator
│   │
│   ├── routes/                    # Presentation Layer (Flask Blueprints)
│   │   ├── dashboard.py           # Dashboard metrics & overview
│   │   ├── urls.py                # URL onboarding, approve, deny, delete
│   │   ├── threats.py             # Threat matrix & manual scan
│   │   ├── recovery.py            # Rollback API (/restore)
│   │   └── system.py              # Settings toggles, PDF download, alerts
│   │
│   └── workers/                   # Background Task Engine
│       └── monitoring_worker.py   # Multi-stage autonomous scanning loop
│
├── templates/                     # Jinja2 HTML templates
└── static/                        # Cyber-themed CSS styles & forensic archives
```

### Technologies Used
- **Backend**: Python 3, Flask (Application Factory & Blueprints)
- **Database**: MongoDB (`pymongo`)
- **Browser Automation**: Selenium WebDriver (Headless Firefox/Gecko)
- **Computer Vision**: OpenCV (`cv2`), `scikit-image` (SSIM)
- **HTML Parsing**: BeautifulSoup4
- **Threat Intelligence**: VirusTotal API v3 (`vt-py`)
- **Alerting**: SMTP Gmail, Twilio API (WhatsApp)
- **Reporting**: ReportLab (PDF generation)
- **Frontend**: HTML5, Jinja2, CSS3 (Glassmorphism), Chart.js, Bootstrap 5

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

Key environment variables:
```dotenv
FLASK_SECRET_KEY=your-secret-key
MONGO_URI=mongodb://localhost:27017/
VT_API_KEY=your_virustotal_api_key
EMAIL_SENDER=your_email@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
TWILIO_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
ADMIN_WHATSAPP=+1234567890
TARGET_SITE_ROOT=D:\path\to\monitored\site\repo
```

### 4. Run the Web Application
```bash
python run.py
```
Open your browser at `http://127.0.0.1:5000` to view the dashboard.

### 5. Start the Background Monitoring Worker
In a separate terminal window:
```bash
python worker.py
```

---

## 📑 Core API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/dashboard` | View system status, active URLs, and threat statistics |
| `GET/POST`| `/add_url` | Onboard a new website for automated monitoring |
| `GET` | `/approve_change` | Update the baseline to the current website state |
| `GET` | `/deny_change` | Flag an unauthorized change as a defacement incident |
| `POST` | `/restore` | Rollback the target website template to its safe baseline |
| `GET` | `/threats` | View VirusTotal threat intelligence matrix |
| `POST` | `/scan_url` | Run an on-demand threat intelligence scan |
| `GET` | `/toggle_scheduler` | Start or pause the background monitoring worker |
| `GET` | `/download_report` | Download the executive PDF threat report |

---

## 📄 License
This project is licensed under the MIT License.
