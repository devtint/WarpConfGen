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

    isp_warp_ips: dict[str, list[str]] = {
        "MPT_Fiber": [
            "162.159.192.3",
            "162.159.192.11",
            "162.159.192.16",
            "162.159.195.3",
            "162.159.195.1",
            "8.34.146.113",
            "162.159.192.15",
            "162.159.195.6",
            "162.159.192.13",
            "162.159.192.19",
            "162.159.195.4",
            "162.159.195.8",
            "162.159.195.2",
            "162.159.192.6",
            "162.159.192.17",
        ],
        "U9": [
            "162.159.195.4",
            "162.159.192.2",
            "162.159.192.3",
            "162.159.192.5",
            "188.114.99.22",
        ],
        "Mytel_SIM": [
            "162.159.192.4",
            "162.159.195.5",
            "162.159.195.1",
            "162.159.192.20",
            "162.159.192.15",
            "162.159.195.4",
            "162.159.192.12",
            "162.159.195.8",
            "162.159.192.14",
            "162.159.192.13",
            "8.34.146.113",
            "162.159.195.10",
            "162.159.195.2",
            "162.159.192.5",
            "162.159.192.7",
        ],
    }

    @property
    def known_warp_ips(self) -> list[str]:
        all_ips = []
        for ips in self.isp_warp_ips.values():
            for ip in ips:
                if ip not in all_ips:
                    all_ips.append(ip)
        return all_ips

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
