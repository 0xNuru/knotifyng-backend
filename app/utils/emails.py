#!/usr/bin/env python3
from typing import List
from app.config.config import settings
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, select_autoescape, PackageLoader
from pydantic import EmailStr


"""
The Jinja2 environment is configured with the following settings:
- The loader is set to PackageLoader, which loads templates from a Python package.
- The package name is 'app' and the template directory is 'templates'.
- The autoescape setting is set to select_autoescape, which automatically escapes HTML in variables to avoid XSS.
- The autoescape is set to escape HTML and XML.

This environment is used in the Email class to render HTML templates for sending emails.
"""
jinja2_env = Environment(
    loader=PackageLoader("app", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


class Email:
    """
    The Email class is used to send emails with a personalized token for verification purposes.

    Attributes:
        name (str): The name of the recipient.
        email (EmailStr): A recipient email address.
        token (str): A unique token for email verification.

    Methods:
        __init__(self, name: str, token: str, email: EmailStr): Initializes the
                Email object with the recipient's name, token, and email addresses.
        sendMail(self, subject_feild: str, template_name: str): Sends an email to the
                recipient with a personalized token and a subject field.
    """

    def __init__(self, name: str, token: str, email: List[EmailStr]):
        self.name = name
        self.email = email
        self.token = token

    async def send_mail(self, subject_feild: str, template_name: str) -> None:
        """
        Sends an email to the recipient with a personalized token and a subject field.

        Args:
            subject_feild (str): The subject field of the email.
            template_name (str): The name of the HTML template to be used for rendering the email content.

        Returns:
            None: This method does not return any value. It sends an email asynchronously.

        Raises:
            Exception: If there is an error while sending the email.

        Usage:
            email = Email(name="John Doe", token="123456", email=["john.doe@example.com"])
            await email.sendMail("Verify your account", "verify_email")
        """
        config = ConnectionConfig(
            MAIL_USERNAME=settings.EMAIL_USERNAME,
            MAIL_PASSWORD=settings.EMAIL_PASSWORD,
            MAIL_FROM=settings.EMAIL_FROM,
            MAIL_PORT=settings.EMAIL_PORT,
            MAIL_SERVER=settings.EMAIL_HOST,
            MAIL_STARTTLS=True,
            MAIL_SSL_TLS=False,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=False,
        )

        # load the template that should be used from the tamplates dir
        template = jinja2_env.get_template(f"{template_name}.html")

        # pass the required variables to the template and render it
        html = template.render(
            token_url=self.token, name=self.name, subject=subject_feild
        )

        # schema for message to be sent by FastMail
        message = MessageSchema(
            subject=subject_feild, recipients=self.email, body=html, subtype="html"
        )

        # Send mail
        fast_mail = FastMail(config)
        await fast_mail.send_message(message)
