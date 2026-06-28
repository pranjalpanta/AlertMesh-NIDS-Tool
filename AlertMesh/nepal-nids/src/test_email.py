"""
AlertMesh email notification setup test.

Configure these in src/.env first:
    EMAIL_ENABLED=true
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USE_TLS=true
    SMTP_USERNAME=your_email@gmail.com
    SMTP_PASSWORD=your_app_password
    SMTP_FROM=your_email@gmail.com
    SMTP_TO=destination@example.com
"""

import os
import smtplib
import sys
from email.message import EmailMessage

from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def configure_console_encoding():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


configure_console_encoding()
load_dotenv(os.path.join(BASE_DIR, ".env"), override=False, encoding="utf-8-sig")


EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME).strip()
SMTP_TO = [value.strip() for value in os.getenv("SMTP_TO", "").split(",") if value.strip()]


def config_ready():
    if not EMAIL_ENABLED:
        return False, "EMAIL_ENABLED is false"
    if not SMTP_HOST:
        return False, "SMTP_HOST is missing"
    if not SMTP_FROM:
        return False, "SMTP_FROM or SMTP_USERNAME is missing"
    if not SMTP_TO:
        return False, "SMTP_TO is missing"
    if SMTP_USERNAME and not SMTP_PASSWORD:
        return False, "SMTP_PASSWORD is missing"
    return True, None


def main():
    print("=" * 55)
    print("  AlertMesh NIDS - Email Alert Setup & Test")
    print("=" * 55)
    print(f"\nEmail enabled : {EMAIL_ENABLED}")
    print(f"SMTP host     : {'Set' if SMTP_HOST else 'NOT SET'}")
    print(f"SMTP username : {'Set' if SMTP_USERNAME else 'NOT SET'}")
    print(f"SMTP password : {'Set' if SMTP_PASSWORD else 'NOT SET'}")
    print(f"SMTP from     : {'Set' if SMTP_FROM else 'NOT SET'}")
    print(f"SMTP to       : {'Set' if SMTP_TO else 'NOT SET'}")

    ready, reason = config_ready()
    if not ready:
        print(f"\n[ERROR] {reason}.")
        return 1

    message = EmailMessage()
    message["Subject"] = "AlertMesh email test"
    message["From"] = SMTP_FROM
    message["To"] = ", ".join(SMTP_TO)
    message.set_content(
        "AlertMesh email alerts are working.\n\n"
        "If you received this, SMTP notifications are ready for intrusion alerts."
    )

    try:
        print("\nSending test email...")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USERNAME:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        print("[OK] Test email sent successfully.")
        return 0
    except Exception as exc:
        print(f"[ERROR] Could not send email: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
