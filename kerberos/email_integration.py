"""
ENVS:
EMAIL_SENDER
"""

import os
import logging
import json
from base64 import b64decode
from urllib.parse import unquote

import boto3
from botocore.vendored import requests
from botocore.exceptions import ClientError 

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Email:
    response_url = None
    sender = os.getenv('EMAIL_SENDER')
    user_email = None

    @staticmethod
    def process_params(event, context):
        email = event['Records'][0]['ses']['mail']
        
        auth_header = Email.get_auth_header(email['headers'])
        if not auth_header:
            print("Auth Header not found. Aborting.")
            return
        
        if Email.validate_email(auth_header):
            print("Email Authorized")
        else:
            print("Email forged!")

        subject = email['commonHeaders']['subject']
        user_email = email.get('source')
        Email.user_email = user_email

        values = {'op': 'user-database-list', 'email': user_email, 'params': subject}
        return  {'status': 'success', 'values': values}

    @staticmethod
    def respond(credentials, **kwargs):
        Email.send_email(Email.user_email, credentials)

    @staticmethod
    def validate_email(auth_header):
        """Validate that spf, dkim and dmarc have passed."""
        if (
            'spf=pass' in auth_header
            and 'dkim=pass' in auth_header
            and 'dmarc=pass' in auth_header
            ):
                return True
        
        return False

    @staticmethod
    def get_auth_header(headers):
        """Return the Authentication header"""

        # Get the name and value of the header
        for (_, name), (_, value) in [h.items() for h in headers]:
            if name == 'Authentication-Results':
                return value 

        return None

    @staticmethod
    def send_email(user_email, credentials):
        SUBJECT = "Requested Credentials"
        CHARSET = "UTF-8"
        
        db_url = credentials["db_url"]
        db_port = credentials["db_port"]
        db_name = credentials["db_name"]
        username = credentials["username"]
        passwd = credentials["passwd"]
        
        # The email body for recipients with non-HTML email clients.
        BODY_TEXT = ("Here are your credentials\r\n"
                    f"db_url: {db_url}\r\n"
                    f"db_port: {db_port}\r\n"
                    f"db_name: {db_name}\r\n"
                    f"username: {username}\r\n"
                    f"passwd: {passwd}\r\n"
                    )
        
        # The HTML body of the email.
        BODY_HTML = f"""<html>
        <head></head>
        <body>
        <h3>Here are your credentials</h3>
        <p><b>db_url:</b> {db_url}</p>
        <p><b>db_port:</b> {db_port}</p>
        <p><b>db_name:</b> {db_name}</p>
        <p><b>username:</b> {username}</p>
        <p><b>passwd:</b> {passwd}</p>
        </body>
        </html>
                    """
        
        client = boto3.client('ses')
        
        try:
            response = client.send_email(
                Destination={
                    'ToAddresses': [
                        user_email,
                    ],
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': CHARSET,
                            'Data': BODY_HTML,
                        },
                        'Text': {
                            'Charset': CHARSET,
                            'Data': BODY_TEXT,
                        },
                    },
                    'Subject': {
                        'Charset': CHARSET,
                        'Data': SUBJECT,
                    },
                },
                Source=Email.sender,
            )
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['MessageId'])
