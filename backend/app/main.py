from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.database import init_db
from app.worker import start_in_process_worker
from app.routers import projects, scan, patch, verify, learn, reports

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database schema
    init_db()
    # Start background scanning worker thread
    start_in_process_worker()
    yield

app = FastAPI(
    title="DAMage CTRL API",
    description="Find the Flaw. Prove the Fix. AI-assisted website & application security companion.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS setup for Vite React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(projects.router)
app.include_router(scan.router)
app.include_router(patch.router)
app.include_router(verify.router)
app.include_router(learn.router)
app.include_router(reports.router)

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "DAMage CTRL API",
        "version": "1.0.0"
    }

# Serve compiled React frontend assets if built
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/")
    @app.get("/index.html")
    async def serve_index():
        return FileResponse(str(FRONTEND_DIST / "index.html"))
