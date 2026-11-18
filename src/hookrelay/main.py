"""CLI entrypoint for HookRelay."""

from __future__ import annotations

import uvicorn

from hookrelay.app import create_app
from hookrelay.config import Settings


def cli() -> None:
    cfg = Settings()
    uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port)


if __name__ == "__main__":
    cli()
