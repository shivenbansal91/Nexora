"""Backend settings, overridable via environment / .env."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    # Storage. Default SQLite so it runs with zero setup; docker-compose sets a
    # Postgres URL (postgresql+psycopg://user:pass@db:5432/nexora).
    database_url: str = f"sqlite:///{(REPO_ROOT / 'nexora.db').as_posix()}"

    # CORS: comma-separated origins, or "*".
    cors_origins: str = "*"

    # Live pipeline tuning.
    tick_seconds: float = Field(0.6, gt=0)
    normal_rate_per_tick: int = Field(1, ge=0, le=100)
    normal_event_interval_seconds: float = Field(3.0, gt=0)
    window_minutes: int = Field(15, ge=1)
    max_window_events: int = Field(800, ge=50)
    attack_spread_seconds: float = Field(6.0, gt=0)

    # Where the detection metrics file lives (written by train_baseline.py).
    metrics_path: str = str(REPO_ROOT / "data" / "processed" / "metrics.json")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_list(self) -> list[str]:
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
