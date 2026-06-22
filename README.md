<div align="center">
  <img src="https://via.placeholder.com/150/060b14/00d4ff?text=CyberRecon+Pro" alt="CyberRecon Pro Logo">
  <h1>CyberRecon Pro</h1>
  <p><b>Automated Cybersecurity Reconnaissance & Vulnerability Assessment Platform</b></p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python Version">
    <img src="https://img.shields.io/badge/Flask-3.0.3-green.svg" alt="Flask Version">
    <img src="https://img.shields.io/badge/Security-Automated_Recon-purple.svg" alt="Security">
    <img src="https://img.shields.io/badge/License-MIT-orange.svg" alt="License">
  </p>
</div>

<br>

**CyberRecon Pro** is an advanced, automated reconnaissance platform designed for Security Analysts, SOC teams, and Penetration Testers. It orchestrates industry-standard security tools (Nmap, Subfinder, Amass, FFUF, WhatWeb) into a centralized, modern web interface.

Developed as a personal portfolio project, CyberRecon Pro features AI-assisted risk analysis, multi-threaded asynchronous scanning, PDF report generation, and a centralized Vulnerability Knowledge Base (VulnKB).

---

## ⚡ Features

* **Automated Reconnaissance Workflow:** Run Nmap, Subfinder, Amass, FFUF, and WhatWeb directly from the UI.
* **Asynchronous Execution:** Multi-threaded architecture prevents UI blocking during long-running scans.
* **AI-Powered Analysis:** Rule-based engine automatically analyzes scan results (open ports, discovered subdomains, technologies) and maps them to known vulnerabilities (CVEs) and risk levels.
* **PDF Report Generation:** One-click generation of professional, executive-ready security assessment reports using ReportLab.
* **Vulnerability Knowledge Base:** Built-in VulnKB covering OWASP Top 10 vulnerabilities (XSS, SQLi, SSRF, LFI/RFI) with testing payloads, detection methods, and mitigation strategies.
* **Headless Screenshot Engine:** Integrated Playwright/Selenium capturing visual evidence of discovered web applications.
* **Secure by Design:** Features CSRF protection, password hashing (bcrypt), parameterized ORM queries, and strict sub-process execution (`shell=False`) to prevent command injection.

---

## 🛠️ Architecture & Tech Stack

* **Backend:** Python, Flask, Flask-SQLAlchemy, SQLite (Production ready via Postgres/Docker)
* **Frontend:** HTML5, CSS3 (Glassmorphism UI), Vanilla JavaScript, Chart.js
* **Security & Auth:** Flask-Login, Flask-WTF (CSRF Protection), Werkzeug Security
* **PDF Generation:** ReportLab
* **External Tools Integrated:** `nmap`, `subfinder`, `amass`, `ffuf`, `whatweb`, `whois`, `dig`, `nslookup`

---

## 🚀 Installation & Setup

### Prerequisites
Ensure the following tools are installed on your host system and accessible in your `$PATH`:
* `nmap`
* `subfinder`
* `amass`
* `ffuf`
* `whatweb`

### 1. Clone the Repository
```bash
git clone https://github.com/frharsh/CyberRecon-Pro.git
cd CyberRecon-Pro
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
playwright install chromium
```

### 4. Run the Application
```bash
python app.py
```
*The default administrator account will be created on the first run.*

---

## 📸 Application Screenshots

*(Placeholder: Add screenshots of your application here)*

*   **Dashboard:** `<img src="path/to/dashboard.png" width="600">`
*   **Recon Module:** `<img src="path/to/recon.png" width="600">`
*   **PDF Report:** `<img src="path/to/report.png" width="600">`

---

## 🔒 Security Posture

This application has been developed with a "Secure by Design" philosophy:
*   **No Command Injection:** All subprocesses use `shell=False` with safely parsed argument arrays.
*   **Path Traversal Prevention:** Secure filename validation on all file downloads and image views.
*   **XSS Protection:** Jinja2 strict auto-escaping enforced across all user-generated content, including complex multiline inputs.
*   **Database Security:** SQLAlchemy ORM used exclusively to prevent SQL Injection attacks.

---

## 👤 Developer & About Me

**Harsh Jadhav**
* **Role:** Cybersecurity Student | Security Analyst Aspirant | VAPT & Reconnaissance Enthusiast
* **GitHub:** [@frharsh](https://github.com/frharsh)
* **LinkedIn:** [Harsh Jadhav](https://www.linkedin.com/in/harsh-jadhav-335795319/)

### About the Developer
I am an aspiring Security Analyst and VAPT enthusiast passionate about constructing practical tooling that automates complex security workflows. My primary areas of interest and learning include:
*   **SOC Operations:** Understanding defensive workflows, threat analysis, log monitoring, and incident response orchestration.
*   **VAPT (Vulnerability Assessment & Penetration Testing):** Discovering vulnerabilities, analyzing software weaknesses, and performing authorized web/network exploitation.
*   **Reconnaissance:** Developing automated methods to map external attack surfaces and perform threat profiling.
*   **Security Research:** Keeping up to date with the latest CVEs, OWASP methodologies, and secure coding practices.

---

## ⚠️ Legal Disclaimer

**For Educational and Authorized Security Testing Purposes Only.**

This tool is designed to assist security professionals in authorized vulnerability assessments and penetration tests. The authors and contributors are not responsible for any misuse, damage, or illegal activities conducted with this tool. Always ensure you have explicit, written permission from the target organization before initiating any scans.

---

<div align="center">
  <i>Developed with  by Harsh Jadhav👾</i>
</div>
