import os
import tempfile


os.environ.setdefault("ALERTMESH_DB_BACKEND", "sqlite")
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(tempfile.gettempdir(), "alertmesh-scapy-cache-test"))
os.environ.setdefault("EMAIL_ENABLED", "false")
