"""
API Routes — Projects, Scanning, Issues, Metrics, Rules.
"""
import os
import csv
import io
import json
import zipfile
import uuid
import shutil
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from typing import Optional, List

from backend.database.connection import get_db
from backend.database.models.models import Project, ScanResult, Issue, Metric
from backend.workers.tasks import run_scan_sync
from backend.rule_engine.engine import RuleEngine
from backend.services.llm_service import get_recommendation

router = APIRouter()


# ── Pydantic Schemas ──────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    path: str
    language: Optional[str] = "auto"

class ScanRequest(BaseModel):
    project_id: str


# ── Project Endpoints ─────────────────────────────────────────────

@router.post("/projects", response_model=dict)
def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new project."""
    if not os.path.isdir(project.path):
        raise HTTPException(status_code=400, detail=f"Path does not exist: {project.path}")
    db_project = Project(name=project.name, path=project.path, language=project.language)
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return {"id": db_project.id, "name": db_project.name, "path": db_project.path, "message": "Project created successfully."}


@router.post("/projects/upload", response_model=dict)
def upload_project(
    db: Session = Depends(get_db),
    file: UploadFile = File(...),
    name: str = Form(...),
    language: Optional[str] = Form("auto"),
):
    """Upload a zip file containing the project source code (Python, JS, or mixed)."""
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    upload_dir = os.path.abspath("uploads")
    os.makedirs(upload_dir, exist_ok=True)

    project_id = str(uuid.uuid4())
    extract_path = os.path.join(upload_dir, f"{name}_{project_id}")
    os.makedirs(extract_path, exist_ok=True)

    zip_path = os.path.join(upload_dir, f"{project_id}.zip")
    with open(zip_path, "wb") as f:
        while chunk := file.file.read(1024 * 1024):  # stream in 1 MB chunks
            f.write(chunk)

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file")

    # Auto-detect language(s) from extracted files
    detected = _detect_project_language(extract_path)
    final_language = language if language and language != "auto" else detected

    db_project = Project(name=name, path=extract_path, language=final_language)
    db.add(db_project)
    db.commit()
    db.refresh(db_project)

    try:
        os.remove(zip_path)
    except OSError:
        pass

    return {
        "id": db_project.id,
        "name": db_project.name,
        "path": db_project.path,
        "language": final_language,
        "message": "Project uploaded and created successfully.",
    }


def _detect_project_language(path: str) -> str:
    """Walk extracted project and detect primary language(s)."""
    py_count = js_count = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {"node_modules", "__pycache__", ".git", "venv", ".venv"}]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext == ".py":
                py_count += 1
            elif ext in {".js", ".jsx", ".ts", ".tsx"}:
                js_count += 1
    if py_count > 0 and js_count > 0:
        return "mixed"
    if js_count > 0:
        return "javascript"
    return "python"


@router.get("/projects")
def list_projects(db: Session = Depends(get_db)):
    """List all projects."""
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return [
        {"id": p.id, "name": p.name, "path": p.path, "language": p.language, "created_at": str(p.created_at)}
        for p in projects
    ]


@router.get("/projects/{project_id}")
def get_project(project_id: str, db: Session = Depends(get_db)):
    """Get project details with latest scan info."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    latest_scan = db.query(ScanResult).filter(
        ScanResult.project_id == project_id
    ).order_by(ScanResult.started_at.desc()).first()

    return {
        "id": project.id,
        "name": project.name,
        "path": project.path,
        "language": project.language,
        "created_at": str(project.created_at),
        "latest_scan": {
            "id": latest_scan.id,
            "status": latest_scan.status,
            "total_issues": latest_scan.total_issues,
            "critical_count": latest_scan.critical_count,
            "major_count": latest_scan.major_count,
            "minor_count": latest_scan.minor_count,
            "info_count": latest_scan.info_count,
            "files_scanned": latest_scan.files_scanned,
            "lines_scanned": latest_scan.lines_scanned,
            "scan_duration_seconds": latest_scan.scan_duration_seconds,
            "started_at": str(latest_scan.started_at),
            "completed_at": str(latest_scan.completed_at) if latest_scan.completed_at else None,
        } if latest_scan else None,
    }


@router.delete("/projects/{project_id}")
def delete_project(project_id: str, db: Session = Depends(get_db)):
    """Delete a project, its DB records, and its uploaded files from disk."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Remove extracted upload folder if it lives inside the uploads directory
    project_path = project.path
    upload_dir = os.path.abspath("uploads")
    if project_path and os.path.abspath(project_path).startswith(upload_dir):
        if os.path.isdir(project_path):
            shutil.rmtree(project_path, ignore_errors=True)

    db.delete(project)
    db.commit()
    return {"message": "Project deleted successfully."}


# ── Scan Endpoints ────────────────────────────────────────────────

@router.post("/scan-project")
def scan_project(req: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Trigger a background scan for a project."""
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    background_tasks.add_task(run_scan_sync, project.id, project.path)
    return {"message": "Scan started", "project_id": project.id}


@router.post("/scan-project-sync")
def scan_project_sync(req: ScanRequest, db: Session = Depends(get_db)):
    """Run a synchronous scan and return results immediately."""
    project = db.query(Project).filter(Project.id == req.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    result = run_scan_sync(project.id, project.path)
    return result


@router.get("/scans/{project_id}")
def get_scans(project_id: str, db: Session = Depends(get_db)):
    """List all scans for a project."""
    scans = db.query(ScanResult).filter(
        ScanResult.project_id == project_id
    ).order_by(ScanResult.started_at.desc()).all()
    return [
        {
            "id": s.id, "status": s.status, "total_issues": s.total_issues,
            "critical_count": s.critical_count, "major_count": s.major_count,
            "minor_count": s.minor_count, "info_count": s.info_count,
            "blocker_count": s.blocker_count,
            "files_scanned": s.files_scanned, "lines_scanned": s.lines_scanned,
            "scan_duration_seconds": s.scan_duration_seconds,
            "started_at": str(s.started_at),
            "completed_at": str(s.completed_at) if s.completed_at else None,
        }
        for s in scans
    ]


# ── Issue Endpoints ───────────────────────────────────────────────

@router.get("/issues/{project_id}")
def get_issues(
    project_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    language: Optional[str] = None,
    file: Optional[str] = None,
    rule_id: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Get issues for a project with filtering and pagination."""
    query = db.query(Issue).filter(Issue.project_id == project_id)

    if severity:
        query = query.filter(Issue.severity == severity.upper())
    if category:
        query = query.filter(Issue.category == category.upper())
    if file:
        query = query.filter(Issue.file.contains(file))
    if rule_id:
        query = query.filter(Issue.rule_id == rule_id)
    # Filter by language via file extension
    if language:
        if language.lower() == "python":
            query = query.filter(Issue.file.like("%.py"))
        elif language.lower() == "javascript":
            query = query.filter(
                Issue.file.like("%.js") | Issue.file.like("%.ts") |
                Issue.file.like("%.jsx") | Issue.file.like("%.tsx")
            )

    total = query.count()
    issues = query.order_by(Issue.severity.desc(), Issue.timestamp.desc()).offset(
        (page - 1) * per_page
    ).limit(per_page).all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "issues": [
            {
                "id": i.id, "file": i.file, "line": i.line, "column": i.column,
                "rule_id": i.rule_id, "rule_name": i.rule_name,
                "severity": i.severity, "category": i.category,
                "message": i.message, "suggestion": i.suggestion,
                "owasp_category": i.owasp_category,
                "code_snippet": i.code_snippet,
                "timestamp": str(i.timestamp),
            }
            for i in issues
        ],
    }


# ── Metrics Endpoints ─────────────────────────────────────────────

@router.get("/metrics/{project_id}")
def get_metrics(project_id: str, file: Optional[str] = None, db: Session = Depends(get_db)):
    """Get metrics for a project or specific file."""
    query = db.query(Metric).filter(Metric.project_id == project_id)
    if file:
        query = query.filter(Metric.file.contains(file))
    metrics = query.order_by(Metric.timestamp.desc()).all()
    return [
        {
            "id": m.id, "file": m.file, "metric_type": m.metric_type,
            "metric_name": m.metric_name, "value": m.value,
            "details": m.details, "timestamp": str(m.timestamp),
        }
        for m in metrics
    ]


# ── LLM Recommendation Endpoint ─────────────────────────────────

@router.get("/issues/{issue_id}/recommendation")
def get_issue_recommendation(issue_id: str, db: Session = Depends(get_db)):
    """Get an AI-generated fix recommendation for a critical issue."""
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    recommendation = get_recommendation({
        "rule_id": issue.rule_id,
        "rule_name": issue.rule_name,
        "file": issue.file,
        "line": issue.line,
        "category": issue.category,
        "message": issue.message,
        "owasp_category": issue.owasp_category,
        "code_snippet": issue.code_snippet,
    })
    return {"issue_id": issue_id, "recommendation": recommendation}


# ── Rules Endpoints ───────────────────────────────────────────────

@router.get("/rules")
def list_rules():
    """List all available rules."""
    engine = RuleEngine()
    return engine.get_rules_summary()


# ── Export Endpoints ──────────────────────────────────────────────

@router.get("/export/{project_id}")
def export_issues(
    project_id: str,
    format: str = Query("json", regex="^(json|csv)$"),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Export all issues for a project as JSON or CSV."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    query = db.query(Issue).filter(Issue.project_id == project_id)
    if severity:
        query = query.filter(Issue.severity == severity.upper())
    if category:
        query = query.filter(Issue.category == category.upper())
    issues = query.order_by(Issue.severity.desc()).all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "file", "line", "rule_id", "rule_name", "severity", "category",
            "message", "suggestion", "owasp_category",
        ])
        writer.writeheader()
        for i in issues:
            writer.writerow({
                "file": i.file, "line": i.line, "rule_id": i.rule_id,
                "rule_name": i.rule_name or "", "severity": i.severity,
                "category": i.category, "message": i.message,
                "suggestion": i.suggestion or "",
                "owasp_category": i.owasp_category or "",
            })
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={project.name}_issues.csv"},
        )

    data = {
        "project": {"id": project.id, "name": project.name, "language": project.language},
        "total_issues": len(issues),
        "issues": [
            {
                "file": i.file, "line": i.line, "rule_id": i.rule_id,
                "rule_name": i.rule_name, "severity": i.severity,
                "category": i.category, "message": i.message,
                "suggestion": i.suggestion, "owasp_category": i.owasp_category,
                "code_snippet": i.code_snippet,
            }
            for i in issues
        ],
    }
    content = json.dumps(data, indent=2).encode()
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={project.name}_issues.json"},
    )


# ── Dependency Vulnerability Endpoints ───────────────────────────

@router.get("/dependencies/{project_id}")
def get_dependency_issues(project_id: str, db: Session = Depends(get_db)):
    """Get dependency vulnerability issues for a project."""
    issues = db.query(Issue).filter(
        Issue.project_id == project_id,
        Issue.category == "DEPENDENCY",
    ).order_by(Issue.severity.desc()).all()
    return [
        {
            "id": i.id, "file": i.file, "rule_id": i.rule_id,
            "severity": i.severity, "message": i.message,
            "suggestion": i.suggestion, "owasp_category": i.owasp_category,
            "timestamp": str(i.timestamp),
        }
        for i in issues
    ]


# ── Summary / Stats Endpoints ─────────────────────────────────────

@router.get("/summary/{project_id}")
def get_project_summary(project_id: str, db: Session = Depends(get_db)):
    """Comprehensive summary: severity, category, OWASP, file breakdown."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    severity_dist = db.query(Issue.severity, func.count(Issue.id)).filter(
        Issue.project_id == project_id
    ).group_by(Issue.severity).all()

    category_dist = db.query(Issue.category, func.count(Issue.id)).filter(
        Issue.project_id == project_id
    ).group_by(Issue.category).all()

    owasp_dist = db.query(Issue.owasp_category, func.count(Issue.id)).filter(
        Issue.project_id == project_id,
        Issue.owasp_category.isnot(None),
    ).group_by(Issue.owasp_category).all()

    top_files = db.query(Issue.file, func.count(Issue.id).label("count")).filter(
        Issue.project_id == project_id
    ).group_by(Issue.file).order_by(func.count(Issue.id).desc()).limit(10).all()

    latest_scan = db.query(ScanResult).filter(
        ScanResult.project_id == project_id
    ).order_by(ScanResult.started_at.desc()).first()

    return {
        "project": {"id": project.id, "name": project.name, "language": project.language},
        "latest_scan": {
            "total_issues": latest_scan.total_issues,
            "critical_count": latest_scan.critical_count,
            "major_count": latest_scan.major_count,
            "minor_count": latest_scan.minor_count,
            "info_count": latest_scan.info_count,
            "files_scanned": latest_scan.files_scanned,
            "lines_scanned": latest_scan.lines_scanned,
        } if latest_scan else None,
        "severity_distribution": [{"severity": s, "count": c} for s, c in severity_dist],
        "category_distribution": [{"category": cat, "count": c} for cat, c in category_dist],
        "owasp_distribution": [{"owasp_category": o, "count": c} for o, c in owasp_dist],
        "top_files": [{"file": f, "count": c} for f, c in top_files],
    }
