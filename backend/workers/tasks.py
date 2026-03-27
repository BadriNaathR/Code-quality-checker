"""
Background workers — runs scans asynchronously using asyncio / concurrent.futures.
"""
import asyncio
import concurrent.futures
import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session

from backend.scanner.engine import ScannerEngine
from backend.database.connection import SessionLocal
from backend.database.models.models import Project, ScanResult, Issue, Metric


# Thread pool for running scans without blocking
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)


def run_scan_sync(project_id: str, project_path: str) -> Dict[str, Any]:
    """
    Run a synchronous scan and persist results to the database.
    Called from within the thread pool executor.
    """
    db = SessionLocal()
    scan = None
    try:
        # Create scan record
        scan = ScanResult(project_id=project_id, status="running")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Run the scan
        engine = ScannerEngine()
        results = engine.scan_project(project_path)

        if "error" in results:
            scan.status = "failed"
            db.commit()
            return results

        # Persist issues
        for issue_data in results.get("issues", []):
            issue = Issue(
                project_id=project_id,
                scan_id=scan.id,
                file=issue_data["file"],
                line=issue_data["line"],
                column=issue_data.get("column", 0),
                end_line=issue_data.get("end_line"),
                rule_id=issue_data["rule_id"],
                rule_name=issue_data.get("rule_name"),
                severity=issue_data["severity"],
                category=issue_data["category"],
                message=issue_data["message"],
                suggestion=issue_data.get("suggestion"),
                owasp_category=issue_data.get("owasp_category"),
                code_snippet=issue_data.get("code_snippet"),
            )
            db.add(issue)

        # Persist metrics
        for metric_data in results.get("metrics", []):
            metric = Metric(
                project_id=project_id,
                scan_id=scan.id,
                file=metric_data.get("file"),
                metric_type=metric_data["metric_type"],
                metric_name=metric_data["metric_name"],
                value=metric_data["value"],
                details=metric_data.get("details"),
            )
            db.add(metric)

        # Persist dependency vulnerabilities as issues
        for dep_vuln in results.get("dependency_vulnerabilities", []):
            rule_id = dep_vuln.get("rule_id", "DEP001")
            rule_names = {
                "DEP001": "Vulnerable Dependency",
                "DEP002": "Unused Dependency",
                "DEP003": "Undeclared Dependency",
            }
            issue = Issue(
                project_id=project_id,
                scan_id=scan.id,
                file=dep_vuln["file"],
                line=0,
                rule_id=rule_id,
                rule_name=rule_names.get(rule_id, "Dependency Issue"),
                severity=dep_vuln.get("severity", "MAJOR"),
                category="DEPENDENCY",
                message=f"{dep_vuln['package']}: {dep_vuln.get('summary', dep_vuln.get('summary', ''))}",
                suggestion=dep_vuln.get("suggestion", f"Review {dep_vuln['package']} usage."),
                owasp_category="A06:2021-Vulnerable and Outdated Components" if rule_id == "DEP001" else None,
            )
            db.add(issue)

        # Update scan record
        summary = results.get("summary", {})
        severity_counts = summary.get("severity_counts", {})
        scan.status = "completed"
        scan.total_issues = summary.get("total_issues", 0) + len(results.get("dependency_vulnerabilities", []))
        scan.critical_count = severity_counts.get("CRITICAL", 0)
        scan.major_count = severity_counts.get("MAJOR", 0)
        scan.minor_count = severity_counts.get("MINOR", 0)
        scan.info_count = severity_counts.get("INFO", 0)
        scan.blocker_count = severity_counts.get("BLOCKER", 0)
        scan.files_scanned = summary.get("files_scanned", 0)
        scan.lines_scanned = summary.get("lines_scanned", 0)
        scan.scan_duration_seconds = summary.get("scan_duration_seconds", 0)
        scan.completed_at = datetime.datetime.utcnow()

        db.commit()

        return {
            "scan_id": scan.id,
            "status": "completed",
            "summary": summary,
        }

    except Exception as e:
        if scan:
            scan.status = "failed"
            db.commit()
        print(f"[Worker] Scan failed for project {project_id}: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def run_scan_async(project_id: str, project_path: str) -> Dict[str, Any]:
    """
    Run a scan asynchronously by offloading to a thread pool.
    Used by FastAPI BackgroundTasks.
    """
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_executor, run_scan_sync, project_id, project_path)
    return result
