"""Configuration settings for HookRelay."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HOOKRELAY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = Field(default=8093, ge=1, le=65535)
    data_dir: Path = Path("./data")
    admin_token: str = "hookrelay-dev-admin"
    allow_private_targets: bool = False
    worker_concurrency: int = Field(default=4, ge=1, le=32)
    worker_poll_interval_sec: float = Field(default=0.25, ge=0.05, le=10.0)
    rate_limit_per_min: int = Field(default=120, ge=1)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "hookrelay.db"

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
