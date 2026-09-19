import asyncio
import json
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from app.core.config import settings


class LocalEmailService:
    """SMTP delivery with a local JSON/console outbox fallback."""

    def __init__(self, path: str = ".local_mail.json") -> None:
        self.path = Path(path)

    async def send(self, recipient: str, subject: str, body: str) -> None:
        message = {
            "to": recipient,
            "subject": subject,
            "body": body,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        messages = []
        if self.path.exists():
            try:
                messages = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                messages = []
        messages.append(message)
        self.path.write_text(json.dumps(messages, ensure_ascii=False, indent=2), encoding="utf-8")
        if settings.smtp_enabled:
            if not settings.smtp_username or not settings.smtp_password:
                raise RuntimeError("SMTP_ENABLED=true, but SMTP_USERNAME or SMTP_PASSWORD is not configured.")
            await asyncio.to_thread(self._send_smtp, recipient, subject, body)
            print(f"[smtp email] To: {recipient} | {subject}")
        else:
            print(f"[local email] To: {recipient} | {subject}\n{body}")

    @staticmethod
    def _send_smtp(recipient: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = settings.smtp_from_email or settings.smtp_username
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)

        if settings.smtp_starttls:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
        else:
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)


email_service = LocalEmailService()
