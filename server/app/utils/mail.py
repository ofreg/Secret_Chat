import os
import smtplib
from email.utils import formataddr
from email.message import EmailMessage


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL") or SMTP_USERNAME
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
MAIL_APP_NAME = os.getenv("MAIL_APP_NAME", "Mail")


def is_mail_configured() -> bool:
    return bool(SMTP_HOST and SMTP_PORT and SMTP_USERNAME and SMTP_PASSWORD and SMTP_FROM_EMAIL)


def send_password_reset_email(to_email: str, reset_link: str) -> None:
    if not is_mail_configured():
        raise RuntimeError("SMTP is not configured")

    message = EmailMessage()
    message["Subject"] = f"{MAIL_APP_NAME}: password reset"
    message["From"] = (
        formataddr((SMTP_FROM_NAME, SMTP_FROM_EMAIL))
        if SMTP_FROM_NAME
        else SMTP_FROM_EMAIL
    )
    message["To"] = to_email
    message.set_content(
        f"You requested a password reset for {MAIL_APP_NAME}.\n\n"
        f"Open this link to set a new password:\n{reset_link}\n\n"
        "If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)
