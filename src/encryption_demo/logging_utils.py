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
    old_record_factory = logging.getLogRecordFactory()

    def record_factory(*args: object, **kwargs: object) -> logging.LogRecord:
        record = old_record_factory(*args, **kwargs)
        if not hasattr(record, "actor"):
            record.actor = DEFAULT_ACTOR
        return record

    logging.setLogRecordFactory(record_factory)
    logging.basicConfig(
        level=level,
        format="%(actor)s | %(asctime)s | %(levelname)s | %(message)s",
    )
