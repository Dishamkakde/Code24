import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
TEMP_DIR = STORAGE_DIR / "temp"
PROJECTS_DIR = STORAGE_DIR / "projects"
FIXTURES_DIR = BASE_DIR / "app" / "fixtures"
DB_PATH = Path(os.environ.get("DB_PATH", str(STORAGE_DIR / "damage_control.db")))

# Security & limits
MAX_ZIP_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB max ZIP size
MAX_FILE_COUNT = 2500                  # Max files in uploaded archive
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB per single file

# Supported text & code extensions for scanning
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm",
    ".css", ".scss", ".sass", ".less", ".sql", ".json",
    ".yaml", ".yml", ".env", ".env.example", ".env.local",
    ".md", ".php", ".go", ".rb", ".java", ".cs", ".rs",
    ".sh", ".bash", ".vue", ".svelte", ".toml", ".xml"
}

# Ensure storage directories exist
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
