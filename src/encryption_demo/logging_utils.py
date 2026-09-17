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
    logger = logging.getLogger("encryption_demo")
    formatter = logging.Formatter(
        "%(actor)s | %(asctime)s | %(levelname)s | %(message)s",
        defaults={"actor": DEFAULT_ACTOR},
    )

    actor_handler = next(
        (handler for handler in logger.handlers if getattr(handler, "_encryption_demo_actor_handler", False)),
        None,
    )
    if actor_handler is None:
        actor_handler = logging.StreamHandler()
        actor_handler._encryption_demo_actor_handler = True  # type: ignore[attr-defined]
        logger.addHandler(actor_handler)

    actor_handler.setFormatter(formatter)
    logger.setLevel(level)
    logger.propagate = False
