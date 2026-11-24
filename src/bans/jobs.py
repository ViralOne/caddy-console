"""Background jobs for IP bans; see Task 11."""
from .. import config


def start_background():
    if not config.BANS_ENABLED:
        return None
    return None
