from flask import session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)


def user_or_ip_key():
    """Clave de rate limiting: user_id de la sesión, o IP si no hay sesión."""
    uid = session.get("user_id")
    return f"user:{uid}" if uid is not None else f"ip:{get_remote_address()}"
