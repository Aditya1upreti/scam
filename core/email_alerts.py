"""
Email alerting module.

Sends a warning email to the user when their submitted content
(text/audio/video/image) is classified as SCAM by the detection pipeline.

Required environment variables:
    SMTP_HOST      - default: smtp.gmail.com
    SMTP_PORT      - default: 587
    SMTP_USER      - the sending Gmail address (e.g. yourapp@gmail.com)
    SMTP_PASSWORD  - a Gmail "App Password" (NOT your normal Gmail password)
    SMTP_FROM_NAME - display name shown to the recipient, default: "Scam Detector Alert"

How to get a Gmail App Password:
    1. Enable 2-Step Verification on the Gmail account: myaccount.google.com/security
    2. Go to myaccount.google.com/apppasswords
    3. Generate a 16-character app password, use it as SMTP_PASSWORD
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("scam_detector.core.email_alerts")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "Scam Detector Alert")


def _build_email_body(transcript: str, summary: str, scam_score: float, language: str) -> str:
    """Builds a friendly HTML warning message for the end user."""
    short_transcript = transcript.strip()
    if len(short_transcript) > 500:
        short_transcript = short_transcript[:500] + "..."

    return f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #222;">
        <div style="max-width: 560px; margin: auto; border: 1px solid #f0c2c2;
                    border-radius: 8px; overflow: hidden;">
          <div style="background: #d32f2f; color: #fff; padding: 16px 20px;">
            <h2 style="margin: 0;">&#9888; Scam Alert</h2>
          </div>
          <div style="padding: 20px;">
            <p>Hi,</p>
            <p>
              The message you submitted has been flagged as a
              <b>likely scam</b> (risk score: <b>{scam_score:.2f}</b>,
              language detected: {language}).
            </p>
            <p><b>Why it was flagged:</b><br>{summary}</p>
            <p style="background:#f7f7f7; padding:10px; border-radius:6px; font-size: 0.9em;">
              "{short_transcript}"
            </p>
            <p>
              Please do <b>not</b> share OTPs, bank details, or make any
              payment based on this message. If you already shared
              sensitive information, contact your bank immediately and
              consider reporting it at
              <a href="https://cybercrime.gov.in">cybercrime.gov.in</a>.
            </p>
            <p style="font-size: 0.8em; color: #777;">
              This is an automated alert from Scam Detector.
            </p>
          </div>
        </div>
      </body>
    </html>
    """


def send_scam_alert(to_email: str, transcript: str, summary: str, scam_score: float, language: str) -> bool:
    """
    Sends a scam-warning email to `to_email`. Returns True on success, False on failure.
    Never raises — failures are logged so they never crash the detection request.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("SMTP_USER / SMTP_PASSWORD not configured — skipping email alert.")
        return False

    if not to_email:
        logger.warning("No recipient email provided — skipping email alert.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "⚠️ Warning: This message looks like a SCAM"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
        msg["To"] = to_email

        html_body = _build_email_body(transcript, summary, scam_score, language)
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())

        logger.info(f"Scam alert email sent successfully to {to_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send scam alert email to {to_email}: {e}", exc_info=True)
        return False