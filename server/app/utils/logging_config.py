import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"

LOG_DIR = Path(os.getenv("LOG_DIR", str(DEFAULT_LOG_DIR)))
APP_LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
APP_LOG_MAX_BYTES = int(os.getenv("APP_LOG_MAX_BYTES", 1_048_576))
APP_LOG_BACKUP_COUNT = int(os.getenv("APP_LOG_BACKUP_COUNT", 5))


class SafeRotatingFileHandler(RotatingFileHandler):
    def emit(self, record):
        try:
            super().emit(record)
        except PermissionError:
            pass

    def doRollover(self):
        try:
            super().doRollover()
        except PermissionError:
            return


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("app")
    if getattr(logger, "_diplom_logging_configured", False):
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    app_handler = SafeRotatingFileHandler(
        LOG_DIR / "app.log",
        maxBytes=APP_LOG_MAX_BYTES,
        backupCount=APP_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    app_handler.setLevel(getattr(logging, APP_LOG_LEVEL, logging.INFO))
    app_handler.setFormatter(formatter)

    error_handler = SafeRotatingFileHandler(
        LOG_DIR / "error.log",
        maxBytes=APP_LOG_MAX_BYTES,
        backupCount=APP_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, APP_LOG_LEVEL, logging.INFO))

    existing_paths = {
        getattr(handler, "baseFilename", None)
        for handler in root_logger.handlers
    }

    app_log_path = str(LOG_DIR / "app.log")
    error_log_path = str(LOG_DIR / "error.log")

    if app_log_path not in existing_paths:
        root_logger.addHandler(app_handler)
    if error_log_path not in existing_paths:
        root_logger.addHandler(error_handler)

    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.setLevel(getattr(logging, APP_LOG_LEVEL, logging.INFO))
        uvicorn_logger.propagate = True

    logger._diplom_logging_configured = True
    logger.info("File logging initialized in %s", LOG_DIR)
    return logger
