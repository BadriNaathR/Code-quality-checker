# CodeQuality Analyzer

A production-ready, self-hosted static analysis platform — a lightweight SonarQube alternative. Upload any Python, JavaScript/TypeScript, SQL, or C# codebase as a ZIP and get instant security, quality, and complexity insights powered by AST-based rule engines, taint analysis, dependency vulnerability scanning, and AI-generated fix recommendations.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Security Rules Coverage](#security-rules-coverage)
- [Supported Languages](#supported-languages)
- [Data Models](#data-models)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Capability | Details |
|---|---|
| **Multi-language scanning** | Python, JavaScript, TypeScript, JSX/TSX, SQL, C# |
| **AST-based analysis** | Deep Python & JS parsing — not just regex |
| **Taint analysis** | Tracks user-controlled data from sources to dangerous sinks |
| **OWASP Top 10 coverage** | All 10 categories mapped to individual rules |
| **Dependency scanning** | Queries the OSV API for CVEs in `requirements.txt` / `package.json` |
| **Dependency usage** | Detects unused declared packages (DEP002) and undeclared imports (DEP003) |
| **Maintainability rules** | Dead code, missing docstrings, duplicate literals, insecure temp files |
| **Type safety rules** | Missing annotations, `Any` overuse, implicit `Optional` misuse |
| **Async safety rules** | Blocking calls in async functions, missing `await`, sync I/O in async context |
| **Code metrics** | Cyclomatic complexity, LOC, Maintainability Index, duplication detection |
| **AI fix recommendations** | LLM-powered suggestions for critical issues |
| **Export** | Download findings as JSON or CSV |
| **Dashboard** | Aggregated charts — severity, category, OWASP, top files |
| **Session history** | Browser-side 5-minute scan history with auto-cleanup |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        React Frontend                        │
│   Dashboard · New Project · Project Details · Charts        │
└────────────────────────┬────────────────────────────────────┘
                         │ REST (JSON)
┌────────────────────────▼────────────────────────────────────┐
│                    FastAPI Backend                           │
│                                                             │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Parsers │  │ Rule Engine  │  │   Taint Engine       │  │
│  │ Python   │  │ 20+ rules    │  │ Source → Sink flow   │  │
│  │ JS/TS    │  │ OWASP mapped │  │ tracking             │  │
│  └──────────┘  └──────────────┘  └──────────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Metrics    │  │  Dependency  │  │   LLM Service    │  │
│  │  Calculator  │  │   Scanner    │  │  AI fix recs     │  │
│  │  (CC, LOC)   │  │  OSV API     │  │  (LangChain)     │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              SQLite (SQLAlchemy ORM)                 │   │
│  │   Projects · ScanResults · Issues · Metrics         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Scan Pipeline

```
ZIP Upload → Extract → File Discovery → Language Detection
    → AST Parse → Rule Engine → Taint Analysis → Metrics
    → Dependency Scan → Duplication Detection → Persist → Response
```

---

## Tech Stack

**Backend**
- Python 3.11+
- FastAPI 0.115 + Uvicorn
- SQLAlchemy 2.0 (SQLite)
- Pydantic v2
- LangChain OpenAI (AI recommendations)
- OSV API (dependency CVE lookup)

**Frontend**
- React 19 + TypeScript
- Vite 8
- React Router v7
- Recharts (data visualization)
- Tailwind CSS v4
- Lucide React (icons)

---

## Project Structure

```
code-quality-checker/
├── backend/
│   ├── api/routes/
│   │   ├── projects.py       # Projects, scans, issues, metrics, export endpoints
│   │   └── dashboard.py      # Aggregated analytics endpoints
│   ├── core/
│   │   └── config.py         # Severity levels, categories, OWASP mapping, settings
│   ├── database/
│   │   ├── connection.py     # SQLAlchemy engine & session
│   │   └── models/models.py  # ORM models: Project, ScanResult, Issue, Metric
│   ├── dependency_scanner/
│   │   └── scanner.py        # OSV API CVE lookup for pip & npm packages
│   ├── metrics/
│   │   ├── calculator.py     # Python: cyclomatic complexity, LOC, duplication
│   │   └── js_calculator.py  # JavaScript metrics
│   ├── parsers/
│   │   ├── python_parser.py  # Python AST parser
│   │   └── js_parser.py      # JavaScript/TypeScript parser
│   ├── rule_engine/
│   │   ├── base.py           # BaseRule, RuleIssue dataclasses
│   │   └── engine.py         # Rule registry & dispatcher
│   ├── rules/
│   │   ├── security/
│   │   │   ├── injection.py          # SEC001–SEC008 (SQL, command, secrets, etc.)
│   │   │   ├── advanced_security.py  # SEC009–SEC014 (path traversal, XXE, TLS, etc.)
│   │   │   ├── js_security.py        # JSEC001–JSEC013 (XSS, JWT, CORS, ReDoS, etc.)
│   │   │   ├── sql_rules.py          # SQL001–SQL005 (SQL injection, SELECT *, no WHERE, etc.)
│   │   │   └── csharp_rules.py       # CS_SEC001–CS_SEC007 (C# security rules)
│   │   ├── code_smells/
│   │   │   ├── smells.py             # CS001–CS007 (Python code smell rules)
│   │   │   └── js_smells.py          # JSCS001–JSCS008 (JS code smell rules)
│   │   ├── performance/
│   │   │   └── performance.py        # PERF001–PERF003 (performance anti-patterns)
│   │   ├── maintainability/
│   │   │   └── maintainability.py    # MAINT001–MAINT006 (dead code, docstrings, temp files)
│   │   ├── type_safety/
│   │   │   └── type_safety.py        # TYPE001–TYPE003 (annotations, Any, Optional)
│   │   └── async_rules/
│   │       └── async_rules.py        # ASYNC001–ASYNC004 (blocking calls, missing await)
│   ├── scanner/
│   │   └── engine.py         # Main scan orchestrator
│   ├── services/
│   │   └── llm_service.py    # LangChain-based AI fix recommendations
│   ├── taint_engine/
│   │   └── tracker.py        # Intra-procedural taint analysis
│   ├── workers/
│   │   └── tasks.py          # Background scan task runner
│   ├── main.py               # FastAPI app entry point
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/client.ts     # Typed API client
│   │   ├── components/
│   │   │   └── Layout.tsx    # App shell with sidebar navigation
│   │   └── pages/
│   │       ├── Dashboard.tsx     # Platform overview with charts
│   │       ├── Projects.tsx      # Upload form + session history
│   │       └── ProjectDetails.tsx # Per-project issues, metrics, export
│   ├── package.json
│   └── vite.config.ts
└── uploads/                  # Extracted project ZIPs (auto-managed)
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm or yarn

### Backend Setup

```bash
# 1. Navigate to the project root
cd code-quality-checker

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r backend/requirements.txt

# 4. Start the API server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### Frontend Setup

```bash
# In a separate terminal
cd frontend

# Install dependencies
npm install

# Start the dev server
npm run dev
```

The UI will be available at `http://localhost:5173`.

---

## Configuration

All settings are controlled via environment variables. Defaults work out of the box.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///data/codequality.db` | SQLAlchemy database URL |
| `MAX_FILE_SIZE_KB` | `500` | Maximum file size to scan (KB) |
| `API_HOST` | `0.0.0.0` | API bind host |
| `API_PORT` | `8000` | API bind port |
| `OPENAI_API_KEY` | *(required for AI recs)* | LLM API key |

To use a different database (e.g. PostgreSQL):

```bash
export DATABASE_URL="postgresql://user:password@localhost/codequality"
```

---

## API Reference

### Health

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health check |

### Projects

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/projects` | Create project from local path |
| `POST` | `/api/projects/upload` | Upload ZIP archive |
| `GET` | `/api/projects` | List all projects |
| `GET` | `/api/projects/{id}` | Get project + latest scan |
| `DELETE` | `/api/projects/{id}` | Delete project and files |

### Scanning

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan-project` | Trigger background scan |
| `POST` | `/api/scan-project-sync` | Run scan synchronously |
| `GET` | `/api/scans/{project_id}` | List scan history |

### Issues & Metrics

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/issues/{project_id}` | Get issues (filterable, paginated) |
| `GET` | `/api/metrics/{project_id}` | Get code metrics |
| `GET` | `/api/dependencies/{project_id}` | Get dependency vulnerabilities |
| `GET` | `/api/summary/{project_id}` | Full project summary |
| `GET` | `/api/issues/{issue_id}/recommendation` | AI fix recommendation |

**Issue filters:** `severity`, `category`, `language`, `file`, `rule_id`, `page`, `per_page`

### Dashboard & Export

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard` | Platform-wide analytics |
| `GET` | `/api/dashboard/{project_id}` | Per-project analytics |
| `GET` | `/api/export/{project_id}?format=json\|csv` | Export issues |
| `GET` | `/api/rules` | List all available rules |

---

## Security Rules Coverage

### Python Rules

| Rule ID | Name | Severity | OWASP |
|---|---|---|---|
| SEC001 | SQL Injection | CRITICAL | A03:2021 |
| SEC002 | OS Command Injection | CRITICAL | A03:2021 |
| SEC003 | Hardcoded Secrets | CRITICAL | A07:2021 |
| SEC004 | Insecure Deserialization | CRITICAL | A08:2021 |
| SEC005 | Weak Cryptography (MD5/SHA1) | MAJOR | A02:2021 |
| SEC006 | Server-Side Request Forgery | MAJOR | A10:2021 |
| SEC007 | Missing Security Logging | MINOR | A09:2021 |
| SEC008 | Debug Mode Enabled | MAJOR | A05:2021 |
| SEC009 | Path Traversal | CRITICAL | A01:2021 |
| SEC010 | XML External Entity (XXE) | CRITICAL | A05:2021 |
| SEC011 | Insecure TLS/SSL | CRITICAL | A02:2021 |
| SEC012 | Missing Auth Decorator | MAJOR | A01:2021 |
| SEC013 | Sensitive Data in Logs | MAJOR | A09:2021 |
| SEC014 | TOCTOU Race Condition | MAJOR | A04:2021 |
| TAINT001 | Taint Flow Detected | CRITICAL | A03:2021 |

Additional rules cover JavaScript security, SQL injection patterns, C# vulnerabilities, code smells, performance, maintainability, type safety, and async safety.

### Maintainability Rules

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| MAINT001 | Dead Code After Return/Raise | MAJOR | Statements after `return`/`raise`/`break`/`continue` are unreachable |
| MAINT002 | Missing Docstring | MINOR | Public functions and classes without docstrings |
| MAINT003 | Too Many Return Statements | MINOR | Functions with more than 4 return points |
| MAINT004 | Duplicate String Literal | MINOR | Same string repeated 3+ times — should be a named constant |
| MAINT005 | Assert Used for Security Check | CRITICAL | `assert` is stripped in optimized mode and must not guard auth/security |
| MAINT006 | Insecure Temporary File | MAJOR | `tempfile.mktemp()` is vulnerable to race conditions |

### Type Safety Rules

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| TYPE001 | Missing Type Annotations | MINOR | Public functions missing parameter or return type annotations |
| TYPE002 | Overuse of Any Type | MINOR | `typing.Any` disables type checking — use specific types |
| TYPE003 | Implicit Optional Parameter | MINOR | Parameter defaults to `None` but not annotated as `Optional[T]` |

### Async Safety Rules

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| ASYNC001 | Blocking Call in Async Function | CRITICAL | `time.sleep`, `requests.get`, `subprocess.*` inside `async def` stall the event loop |
| ASYNC002 | Missing Await on Coroutine | CRITICAL | Coroutine called without `await` — never actually executed |
| ASYNC003 | Sync open() in Async Function | MAJOR | Synchronous file I/O inside `async def` blocks the event loop |
| ASYNC004 | asyncio.sleep(0) in Loop | MINOR | Tight-loop yield point — use proper async primitives instead |

### Dependency Usage Rules

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| DEP001 | Vulnerable Dependency | MAJOR | Package has a known CVE via OSV API |
| DEP002 | Unused Dependency | MINOR | Package declared in `requirements.txt` but never imported in any `.py` file |
| DEP003 | Undeclared Dependency | MAJOR | Package imported in source code but missing from `requirements.txt` |

**How it works:**
- Parses `requirements.txt` to collect all declared packages
- Walks all `.py` files and extracts every `import` / `from X import` statement via AST
- Filters out Python standard library modules to avoid false positives
- Handles packages where the install name differs from the import name (e.g. `pillow` → `PIL`, `pyyaml` → `yaml`, `langchain-openai` → `langchain_openai`)
- Results appear in the `DEPENDENCY` category alongside CVE findings

### Taint Analysis Sources & Sinks

**Sources** (untrusted input): `request.args`, `request.form`, `request.json`, `request.GET/POST`, `input()`, `os.environ`, `sys.argv`, file reads

**Sinks** (dangerous operations): `cursor.execute`, `os.system`, `subprocess.*`, `eval`, `exec`, `pickle.loads`, `yaml.load`, `render_template_string`, `requests.get/post`, file writes

---

## Supported Languages

| Language | Extensions | AST Parsing | Taint Analysis | Metrics |
|---|---|---|---|---|
| Python | `.py` | ✅ | ✅ | ✅ |
| JavaScript | `.js`, `.jsx` | ✅ | — | ✅ |
| TypeScript | `.ts`, `.tsx` | ✅ | — | ✅ |
| SQL | `.sql` | — (regex) | — | — |
| C# | `.cs` | — (regex) | — | — |

Mixed-language projects are auto-detected and scanned with the appropriate rules per file.

---

## Data Models

```
Project
  ├── id (UUID)
  ├── name, path, language
  ├── created_at, updated_at
  ├── ScanResults[]
  ├── Issues[]
  └── Metrics[]

ScanResult
  ├── id, project_id
  ├── status (pending | running | completed | failed)
  ├── total_issues, critical_count, major_count, minor_count, info_count, blocker_count
  ├── files_scanned, lines_scanned, scan_duration_seconds
  └── started_at, completed_at

Issue
  ├── id, project_id, scan_id
  ├── file, line, column, end_line
  ├── rule_id, rule_name, severity, category
  ├── message, suggestion, owasp_category, code_snippet
  └── timestamp

Metric
  ├── id, project_id, scan_id, file
  ├── metric_type (cyclomatic_complexity | loc | ...)
  ├── metric_name, value, details (JSON)
  └── timestamp
```

---

## Screenshots

> Dashboard — platform-wide overview with severity donut chart and category bar chart.

> New Project — drag-and-drop ZIP upload with language auto-detection and 5-minute session history.

> Project Details — filterable issues table, OWASP distribution, complexity hotspots, and one-click AI fix recommendations.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-rule`
3. Add new rules by extending `BaseRule` in `backend/rules/`
4. Register the rule in `backend/rule_engine/engine.py`
5. Submit a pull request

### Adding a New Rule

```python
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category, OWASP

class MyNewRule(BaseRule):
    rule_id   = "SEC015"
    name      = "My Rule Name"
    severity  = Severity.MAJOR
    category  = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str):
        issues = []
        # ... your detection logic ...
        return issues
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
