"""
SQLAlchemy ORM models for the Code Quality & Security Analysis Platform.

Models:
    - Project: Represents a scanned codebase
    - Issue: Individual code quality / security finding
    - ScanResult: Aggregated scan metadata
    - Metric: Code metric for a file or project
"""
import datetime
import uuid
from sqlalchemy import (
    Column, String, Integer, Float, Text, DateTime, ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from backend.database.connection import Base


def generate_uuid():
    return str(uuid.uuid4())


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    path = Column(Text, nullable=False)
    language = Column(String(50), default="python")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    scans = relationship("ScanResult", back_populates="project", cascade="all, delete-orphan")
    issues = relationship("Issue", back_populates="project", cascade="all, delete-orphan")
    metrics = relationship("Metric", back_populates="project", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=generate_uuid)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    total_issues = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    major_count = Column(Integer, default=0)
    minor_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    blocker_count = Column(Integer, default=0)
    scan_duration_seconds = Column(Float, default=0.0)
    files_scanned = Column(Integer, default=0)
    lines_scanned = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")


class Issue(Base):
    __tablename__ = "issues"

    id = Column(String, primary_key=True, default=generate_uuid)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(String, ForeignKey("scan_results.id"), nullable=True)
    file = Column(Text, nullable=False)
    line = Column(Integer, nullable=False)
    column = Column(Integer, default=0)
    end_line = Column(Integer, nullable=True)
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=False)  # INFO, MINOR, MAJOR, CRITICAL, BLOCKER
    category = Column(String(50), nullable=False)  # SECURITY, CODE_SMELL, etc.
    message = Column(Text, nullable=False)
    suggestion = Column(Text, nullable=True)
    owasp_category = Column(String(100), nullable=True)
    code_snippet = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="issues")


class Metric(Base):
    __tablename__ = "metrics"

    id = Column(String, primary_key=True, default=generate_uuid)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(String, ForeignKey("scan_results.id"), nullable=True)
    file = Column(Text, nullable=True)  # NULL means project-level metric
    metric_type = Column(String(50), nullable=False)  # cyclomatic_complexity, loc, etc.
    metric_name = Column(String(100), nullable=False)
    value = Column(Float, nullable=False)
    details = Column(Text, nullable=True)  # JSON string for extra info
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="metrics")
