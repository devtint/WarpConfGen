"""Page routes for serving the HTML UI via Jinja2 templates."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.services.stats import get_local_count, get_supabase_stats

import os
from pathlib import Path

from fastapi.responses import HTMLResponse, FileResponse

# Vercel and local path resolution
BASE_DIR = Path(__file__).resolve().parent.parent.parent
possible_dirs = [
    BASE_DIR / "templates",
    Path.cwd() / "templates",
    Path.cwd() / "api" / "templates",
]

TEMPLATE_DIR = str(BASE_DIR / "templates")
for d in possible_dirs:
    if d.is_dir():
        TEMPLATE_DIR = str(d)
        break

templates = Jinja2Templates(directory=TEMPLATE_DIR)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main WarpGen page."""
    supabase_count = await get_supabase_stats()
    local_count = get_local_count()
    display_count = supabase_count if supabase_count is not None else local_count

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "display_count": display_count,
            "mode": "select",
            "selected_ip": "",
            "custom_ip": "",
            "port": 500,
            "known_ips": settings.known_warp_ips,
            "isp_warp_ips": settings.isp_warp_ips,
        },
    )


@router.get("/scanner", response_class=HTMLResponse)
async def scanner_page(request: Request):
    """Serve the WarpGen Endpoint Scanner guide page."""
    return templates.TemplateResponse(
        request,
        "scanner.html",
        {
            "request": request,
        },
    )


@router.get("/download/scanner")
async def download_scanner():
    """Download the warp_scanner.py Python script."""
    filepath = Path(BASE_DIR) / "warp_scanner.py"
    if filepath.is_file():
        return FileResponse(
            path=filepath,
            filename="warp_scanner.py",
            media_type="application/octet-stream",
        )
    return {"error": "File not found"}

