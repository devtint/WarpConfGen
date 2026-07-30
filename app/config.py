"""Application configuration using Pydantic Settings."""
from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Typed, validated application settings loaded from environment."""

    supabase_url: str = ""
    supabase_key: str = ""
    stats_file: str = "warpgen_stats.json"
    telegram_bot_token: str = ""
    app_url: str = ""
    admin_secret: str = ""
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 15
    peer_public_key: str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

    known_warp_ips: list[str] = [
        "162.159.192.41", "188.114.99.30", "188.114.96.22",
        "188.114.98.242", "162.159.192.34",
    ]

    warp_cidrs: list[str] = [
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
    ]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
