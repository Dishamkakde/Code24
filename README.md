# DAMage CTRL (Code24) – Find the Flaw. Prove the Fix

> **An AI-assisted website & application security companion designed for absolutely anyone** — students, independent developers, small-business owners, non-technical creators, and builders who need verifiable security analysis without simulated mock data.

---

## 🌟 The Philosophy: Why DAMage CTRL?

Most security scanners stop at **"this looks bad."** They flood users with dozens of confusing alerts, obscure CVE acronyms, and scary red terminal warnings that cause panic or get ignored.

**DAMage CTRL re-imagines cybersecurity from the ground up:**
1. **Zero Jargon by Default**: Translates complex security vulnerabilities into relatable everyday analogies through our **Explain Like I'm 12 (ELI12)** engine.
2. **Deterministic Exploit Noise Filter**: Only confirms an issue as real if a sandboxed, reproducible exploit actually succeeds against the code. If an exploit fails (e.g. input is type-cast or sanitized), it is downgraded to a false positive.
3. **Defensive Fix Assistant**: Proposes minimal, side-by-side unified code diffs explained in plain English. Your original files are **never modified without explicit approval**; changes are tested in an isolated working copy.
4. **The Before vs. After Proof**: Re-runs the exploit (which must now be **BLOCKED**), re-scans the AST (the pattern must be **GONE**), and executes a regression suite (legitimate user actions must still **PASS**).
5. **No Passwords or Credentials**: Examines local source code, never attacks live servers, and never asks for secrets or database keys.

---

## 📂 Project Architecture & Folder Structure

```
code24/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application, CORS, static mounts
│   │   ├── config.py                   # Storage paths, upload constraints, security limits
│   │   ├── database.py                 # SQLite engine for scan history & audit persistence
│   │   ├── models/
│   │   │   └── schemas.py              # Pydantic schemas (Project, Finding, Verification, Report)
│   │   ├── routers/
│   │   │   ├── projects.py             # ZIP upload, GitHub import, demo loader, patched ZIP download
│   │   │   ├── scan.py                 # Deterministic AST scan & noise filter
│   │   │   ├── patch.py                # Fix Assistant & isolated working copy management
│   │   │   ├── verify.py               # Exploit re-tester & regression validation engine
│   │   │   ├── learn.py                # ELI12 concept library & everyday analogies
│   │   │   └── reports.py              # Exportable reports & printable PDF HTML
│   │   ├── services/
│   │   │   ├── zip_service.py          # Secure ZIP extraction (Zip Slip protection, size/count limits)
│   │   │   ├── github_service.py       # Public GitHub repository archive importer
│   │   │   ├── scanner_service.py      # AST static analyzer & language/framework detector
│   │   │   ├── patch_service.py        # Minimal unified diff & side-by-side builder
│   │   │   └── verification_engine.py  # Sandboxed fixture runner (exploits + regressions)
│   │   └── fixtures/
│   │       └── demo_notes_app/         # Built-in deliberately vulnerable target fixture
│   │           ├── app.py              # 4 planted cases (SQLi, IDOR, Traversal, Safe SQL)
│   │           ├── checks.py           # Reproducible exploit tests & 6 regression tests
│   │           ├── uploads/
│   │           │   └── hello.txt
│   │           └── secret.txt
│   ├── tests/
│   │   └── test_api_endpoints.py       # Live integration test suite (100% pass)
│   ├── run_server.py                   # One-command backend starter
│   └── requirements.txt                # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.tsx                     # Main guided workspace & continuous experience
│   │   ├── index.css                   # Custom styles, warm off-white palette, accessibility
│   │   ├── api/
│   │   │   └── client.ts               # Typed client for backend communication
│   │   ├── types/
│   │   │   └── index.ts                # TypeScript data interfaces
│   │   └── components/
│   │       ├── Navbar.tsx              # Top navigation & security status badge
│   │       ├── HeroBanner.tsx          # "Let's make your website safer!" welcoming prompt
│   │       ├── ProjectImporter.tsx     # 3 tabs: Interactive Demo, Upload ZIP, Public GitHub
│   │       ├── ScopeDetector.tsx       # Language & framework detector, file tree, scan CTA
│   │       ├── SafetySummary.tsx       # Friendly scorecards (Candidates, Confirmed, Filtered, Fixed)
│   │       ├── FindingCard.tsx         # 5 progressive disclosure sections & technical details
│   │       ├── BeforeAfterProof.tsx    # Interactive Before vs After Proof & regression table
│   │       ├── FixAssistantModal.tsx   # Side-by-side diff with explicit sandbox approval
│   │       ├── ELI12Modal.tsx          # "Explain Like I'm 12" story modal
│   │       ├── LearnHub.tsx            # Dedicated security concept library
│   │       ├── ProjectHistory.tsx      # Persistent scan history from SQLite
│   │       └── SecurityReportView.tsx  # Printable audit report & patched ZIP download
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js              # Friendly warm palette (cream, mint, soft blue)
│   └── index.html
└── README.md
```

---

## 🚀 Quickstart & Installation

### Requirements
- **Python 3.9+** (Tested on Python 3.12)
- **Node.js 18+** & npm (for frontend compilation or dev mode)

### 1. Install Backend Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the Backend Server
```bash
python run_server.py
```
> The API and built React application will be live at: **http://127.0.0.1:8000**

### 3. (Optional) Run Frontend in Vite Development Mode
```bash
cd frontend
npm install
npm run dev
```
> Development hot-reloading interface available at: **http://localhost:5173**

---

## 🧪 Running Automated Tests

Run the full end-to-end integration test suite against the active server:
```bash
python -m unittest discover -s backend/tests
```
**Test Coverage Includes:**
- `/api/health` service liveness check
- `/api/learn` ELI12 concept dictionary delivery
- Safe ZIP extraction and Zip-slip traversal prevention
- 1-Click demonstration project loading
- Deterministic AST scanning and exploit confirmation
- False-positive noise filtering
- Side-by-side defensive patch application to an isolated working copy
- Exploit re-testing and 6/6 functional regression verification
- PDF-ready report generation and patched project download

---

## 🔍 The 4 Planted Demonstration Cases

| Case ID | Function | Vulnerability | Severity | Exploit Test | Verification Proof |
|---|---|---|---|---|---|
| **PP-01** | `login()` | **SQL Injection** (`CWE-89`) | Urgent (9.8) | Input `alice' --` bypasses password check | Query parameterized with `?`; exploit rejected; valid logins work |
| **PP-02** | `get_note()` | **Broken Access Control / IDOR** (`CWE-639`) | Important (6.5) | Bob reads Alice's private note `id=1` | Added `owner_id = user_id` predicate; unauthorized access blocked |
| **PP-03** | `list_notes()` | **Safe Filter** (False Alarm) | Needs attention (0.0) | `int(user_id)` blocks SQL injection | Exploit fails before query; noise filter flags as benign |
| **PP-04** | `read_attachment()` | **Path Traversal** (`CWE-22`) | Urgent (7.5) | Filename `../secret.txt` exposes server secrets | Realpath canonicalization with `commonpath` blocks folder escape |

---

## 📖 Progressive 5-Section Disclosure on Every Finding

Within the same interface, each finding card unfolds seamlessly across five clear questions:
1. **What did we find?** — High-level summary plus an everyday story analogy.
2. **Why does it matter?** — What an attacker could actually do and who is impacted.
3. **Where is the problem?** — Exact file name, line number, and syntax-highlighted code.
4. **How can we fix it?** — Plain-English explanation and side-by-side before/after comparison.
5. **Did the fix actually work?** — The central proof: baseline exploit status, attack re-test, AST re-scan, and feature regression check.

---

## 🛡️ Security Guarantees & Privacy

- **Local Examination Only**: Analyzes source code files locally; never performs invasive scans against live public websites.
- **No Credentials Requested**: Never asks for database passwords, API tokens, secret keys, or cloud access.
- **Isolated Working Copies**: Original code is preserved untouched. Patches are applied to temporary sandbox copies and only applied with explicit user approval.
- **Zip Slip & Path Traversal Protection**: Archive imports are sanitized to prevent directory traversal, zip bombs, and arbitrary code execution.
