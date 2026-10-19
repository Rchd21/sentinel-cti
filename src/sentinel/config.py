"""Configuration centralisée, lue depuis les variables d'environnement (.env)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///data/sentinel.db")
    user_agent: str = os.getenv("HTTP_USER_AGENT", "SentinelCTI/0.1 (projet portfolio)")
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "20"))
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    abusech_auth_key: str | None = os.getenv("ABUSECH_AUTH_KEY") or None
    otx_api_key: str | None = os.getenv("OTX_API_KEY") or None


settings = Settings()
