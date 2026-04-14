from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return UTC timestamp as naive datetime for current DB compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)
