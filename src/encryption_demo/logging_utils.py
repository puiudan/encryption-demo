from __future__ import annotations

import logging
from typing import Final


DEFAULT_ACTOR: Final[str] = "SYSTEM"


class ActorLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: object, kwargs: dict[str, object]) -> tuple[object, dict[str, object]]:
        extra = kwargs.setdefault("extra", {})
        if isinstance(extra, dict):
            extra.setdefault("actor", self.extra["actor"])
        return msg, kwargs


def get_actor_logger(actor: str) -> ActorLoggerAdapter:
    return ActorLoggerAdapter(logging.getLogger("encryption_demo"), {"actor": actor})


def configure_actor_logging(level: int = logging.INFO) -> None:
    root_logger = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(actor)s | %(asctime)s | %(levelname)s | %(message)s",
            defaults={"actor": DEFAULT_ACTOR},
        )
    )
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)
