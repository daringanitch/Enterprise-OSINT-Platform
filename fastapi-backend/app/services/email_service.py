"""
Email service for sending verification and notification emails
"""
import os
import secrets
from typing import Optional
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template
import structlog

logger = structlog.get_logger()


class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("FROM_EMAIL", "noreply@osint-platform.local")
        self.from_name = os.getenv("FROM_NAME", "OSINT Platform")
        
        # For development, we can use a simple SMTP server or mock
        self.enabled = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
        
    async def send_verification_email(self, to_email: str, verification_token: str, base_url: str) -> bool:
        """Send email verification email"""
        if not self.enabled:
            logger.info("Email not enabled, skipping verification email", to_email=to_email)
            return True  # Return success for development
            
        verification_url = f"{base_url}/verify-email?token={verification_token}"
        
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your Email - OSINT Platform</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #f3f4f6; }
                .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; }
                .header { background: linear-gradient(135deg, #60a5fa, #34d399); color: white; padding: 2rem; text-align: center; }
                .content { padding: 2rem; }
                .button { display: inline-block; background: #60a5fa; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 1rem 0; }
                .footer { background: #f9fafb; padding: 1rem; text-align: center; color: #6b7280; font-size: 0.9rem; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 OSINT Platform</h1>
                    <p>Email Verification Required</p>
                </div>
                <div class="content">
                    <h2>Welcome to the Enterprise OSINT Platform!</h2>
                    <p>Thank you for registering. To complete your account setup and access the platform, please verify your email address by clicking the button below:</p>
                    
                    <a href="{{ verification_url }}" class="button">Verify Email Address</a>
                    
                    <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; color: #60a5fa;">{{ verification_url }}</p>
                    
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    
                    <p>If you didn't create an account, you can safely ignore this email.</p>
                </div>
                <div class="footer">
                    <p>Enterprise OSINT Platform - Professional Open Source Intelligence</p>
                </div>
            </div>
        </body>
        </html>
        """)
        
        html_content = template.render(verification_url=verification_url)
        
        try:
            await self._send_email(
                to_email=to_email,
                subject="Verify Your Email - OSINT Platform",
                html_content=html_content
            )
            logger.info("Verification email sent", to_email=to_email)
            return True
        except Exception as e:
            logger.error("Failed to send verification email", to_email=to_email, error=str(e))
            return False
    
    async def _send_email(self, to_email: str, subject: str, html_content: str) -> None:
        """Send an email using SMTP"""
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{self.from_name} <{self.from_email}>"
        message["To"] = to_email
        
        html_part = MIMEText(html_content, "html")
        message.attach(html_part)
        
        # For development, we can use a simple SMTP configuration
        # In production, you'd configure this with your email provider
        await aiosmtplib.send(
            message,
            hostname=self.smtp_host,
            port=self.smtp_port,
            username=self.smtp_username if self.smtp_username else None,
            password=self.smtp_password if self.smtp_password else None,
            use_tls=self.smtp_port == 587
        )


def generate_verification_token() -> str:
    """Generate a secure verification token"""
    return secrets.token_urlsafe(32)


# Global email service instance
email_service = EmailService()