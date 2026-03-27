"""
Dashboard API Routes — Aggregated analytics for the frontend dashboard.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional

from backend.database.connection import get_db
from backend.database.models.models import Project, ScanResult, Issue, Metric

router = APIRouter()


@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    """Get overview stats for the main dashboard."""
    total_projects = db.query(Project).count()
    total_scans = db.query(ScanResult).filter(ScanResult.status == "completed").count()
    total_issues = db.query(Issue).count()

    # Severity distribution
    severity_dist = db.query(
        Issue.severity, func.count(Issue.id)
    ).group_by(Issue.severity).all()

    # Category distribution
    category_dist = db.query(
        Issue.category, func.count(Issue.id)
    ).group_by(Issue.category).all()

    # OWASP category distribution
    owasp_dist = db.query(
        Issue.owasp_category, func.count(Issue.id)
    ).filter(Issue.owasp_category.isnot(None)).group_by(Issue.owasp_category).all()

    # Recent scans
    recent_scans = db.query(ScanResult).order_by(
        ScanResult.started_at.desc()
    ).limit(10).all()

    # Top files by issue count
    top_files = db.query(
        Issue.file, func.count(Issue.id).label("count")
    ).group_by(Issue.file).order_by(func.count(Issue.id).desc()).limit(10).all()

    return {
        "overview": {
            "total_projects": total_projects,
            "total_scans": total_scans,
            "total_issues": total_issues,
        },
        "severity_distribution": [
            {"severity": sev, "count": cnt} for sev, cnt in severity_dist
        ],
        "category_distribution": [
            {"category": cat, "count": cnt} for cat, cnt in category_dist
        ],
        "owasp_distribution": [
            {"owasp_category": owasp, "count": cnt} for owasp, cnt in owasp_dist
        ],
        "recent_scans": [
            {
                "id": s.id, "project_id": s.project_id, "status": s.status,
                "total_issues": s.total_issues, "critical_count": s.critical_count,
                "major_count": s.major_count,
                "scan_duration_seconds": s.scan_duration_seconds,
                "started_at": str(s.started_at),
            }
            for s in recent_scans
        ],
        "top_files_by_issues": [
            {"file": f, "issue_count": c} for f, c in top_files
        ],
    }


@router.get("/dashboard/{project_id}")
def get_project_dashboard(project_id: str, db: Session = Depends(get_db)):
    """Get analytics for a specific project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return {"error": "Project not found"}

    # Issue counts by severity
    severity_dist = db.query(
        Issue.severity, func.count(Issue.id)
    ).filter(Issue.project_id == project_id).group_by(Issue.severity).all()

    # Issue counts by category
    category_dist = db.query(
        Issue.category, func.count(Issue.id)
    ).filter(Issue.project_id == project_id).group_by(Issue.category).all()

    # OWASP distribution
    owasp_dist = db.query(
        Issue.owasp_category, func.count(Issue.id)
    ).filter(
        Issue.project_id == project_id,
        Issue.owasp_category.isnot(None)
    ).group_by(Issue.owasp_category).all()

    # Scan history
    scans = db.query(ScanResult).filter(
        ScanResult.project_id == project_id
    ).order_by(ScanResult.started_at.desc()).limit(20).all()

    # Top rules triggered
    top_rules = db.query(
        Issue.rule_id, Issue.rule_name, func.count(Issue.id).label("count")
    ).filter(Issue.project_id == project_id).group_by(
        Issue.rule_id, Issue.rule_name
    ).order_by(func.count(Issue.id).desc()).limit(10).all()

    # File complexity metrics
    complexity_metrics = db.query(Metric).filter(
        Metric.project_id == project_id,
        Metric.metric_type == "cyclomatic_complexity"
    ).order_by(Metric.value.desc()).limit(20).all()

    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "path": project.path,
            "language": project.language or "unknown",
        },
        "severity_distribution": [{"severity": s, "count": c} for s, c in severity_dist],
        "category_distribution": [{"category": cat, "count": c} for cat, c in category_dist],
        "owasp_distribution": [{"owasp_category": o, "count": c} for o, c in owasp_dist],
        "scan_history": [
            {
                "id": s.id, "status": s.status, "total_issues": s.total_issues,
                "critical_count": s.critical_count, "major_count": s.major_count,
                "files_scanned": s.files_scanned, "lines_scanned": s.lines_scanned,
                "scan_duration_seconds": s.scan_duration_seconds,
                "started_at": str(s.started_at),
                "completed_at": str(s.completed_at) if s.completed_at else None,
            }
            for s in scans
        ],
        "top_rules": [
            {"rule_id": rid, "rule_name": rname, "count": c}
            for rid, rname, c in top_rules
        ],
        "complexity_hotspots": [
            {"file": m.file, "metric_name": m.metric_name, "value": m.value}
            for m in complexity_metrics
        ],
    }
