import ipaddress
import os
import time

import requests


SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")
COUNTRY_CACHE = {}


def get_float_env(name, default, minimum=None):
    try:
        value = float(os.getenv(name, default))
    except (TypeError, ValueError):
        print(f"WARNING: {name} must be a number. Using {default}.")
        value = default
    if minimum is not None and value < minimum:
        print(f"WARNING: {name} must be at least {minimum}. Using {minimum}.")
        value = minimum
    return value


def local_ip_origin(ip_addr):
    if ip_addr in SHARED_ADDRESS_SPACE:
        return "Shared Address Space"
    if ip_addr.is_private:
        return "Private Network"
    if ip_addr.is_loopback:
        return "Loopback"
    if ip_addr.is_link_local:
        return "Link-local"
    if ip_addr.is_multicast:
        return "Multicast"
    if ip_addr.is_unspecified:
        return "Unspecified"
    if ip_addr.is_reserved:
        return "Reserved"
    if not ip_addr.is_global:
        return "Non-public Network"
    return None


def cache_get(ip):
    entry = COUNTRY_CACHE.get(ip)
    if entry is None:
        return None
    if isinstance(entry, tuple):
        value, expires_at = entry
        if expires_at is None or time.time() < expires_at:
            return value
        COUNTRY_CACHE.pop(ip, None)
        return None
    return entry


def cache_set(ip, value, ttl=None):
    expires_at = None if ttl is None else time.time() + ttl
    COUNTRY_CACHE[ip] = (value, expires_at)
    return value


def success_cache_ttl():
    return get_float_env("GEOLOCATION_SUCCESS_CACHE_SECONDS", 86400, minimum=0)


def get_country_from_ip(ip, geolocation_enabled=None, timeout=None):
    """Return a useful origin label for local/special IPs or a country for public IPs."""
    cached = cache_get(ip)
    if cached is not None:
        return cached

    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return cache_set(ip, "Invalid IP")

    local_origin = local_ip_origin(ip_addr)
    if local_origin:
        return cache_set(ip, local_origin)

    if geolocation_enabled is None:
        geolocation_enabled = os.getenv("GEOLOCATION_ENABLED", "false").lower() == "true"

    if not geolocation_enabled:
        return cache_set(ip, "Unknown")

    if timeout is None:
        timeout = get_float_env("GEOLOCATION_TIMEOUT_SECONDS", 0.75, minimum=0.1)

    try:
        response = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=timeout)
        if response.status_code == 200:
            return cache_set(ip, response.text.strip() or "Unknown", ttl=success_cache_ttl())
    except requests.RequestException as exc:
        print(f"Error getting country for {ip}: {exc}")

    failure_ttl = get_float_env("GEOLOCATION_FAILURE_CACHE_SECONDS", 300, minimum=0)
    return cache_set(ip, "Unknown", ttl=failure_ttl)
