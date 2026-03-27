"""
FastAPI Application Entry Point for the Code Quality & Security Analysis Platform.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database.connection import init_db
from backend.api.routes.projects import router as projects_router
from backend.api.routes.dashboard import router as dashboard_router

app = FastAPI(
    title="CodeQuality Analyzer",
    description="A production-ready code quality and security analysis platform — a lightweight SonarQube alternative.",
    version="1.0.0",
)

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "CodeQuality Analyzer"}


# Mount routers
app.include_router(projects_router, prefix="/api", tags=["Projects & Scanning"])
app.include_router(dashboard_router, prefix="/api", tags=["Dashboard & Analytics"])
