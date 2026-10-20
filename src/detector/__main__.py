"""Entry point: `python -m detector` (or the `detector` script)."""

from __future__ import annotations

import logging

from .config import Config
from .metrics import start_metrics_server
from .service import Service


def main() -> None:
    config = Config.from_env()
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    start_metrics_server(config.metrics_port)
    Service(config).run()


if __name__ == "__main__":
    main()
