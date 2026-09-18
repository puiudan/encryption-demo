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


class ActorStreamHandler(logging.StreamHandler):
    """Marker stream handler for encryption_demo actor-formatted logs."""


def configure_actor_logging(level: int = logging.INFO) -> None:
    logger = logging.getLogger("encryption_demo")
    formatter = logging.Formatter(
        "%(actor)s | %(asctime)s | %(levelname)s | %(message)s",
        defaults={"actor": DEFAULT_ACTOR},
    )

    actor_handler = next(
        (handler for handler in logger.handlers if isinstance(handler, ActorStreamHandler)),
        None,
    )
    if actor_handler is None:
        actor_handler = ActorStreamHandler()
        logger.addHandler(actor_handler)

    actor_handler.setFormatter(formatter)
    actor_handler.setLevel(level)
    logger.setLevel(level)
