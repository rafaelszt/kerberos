import os
import logging
import json
import boto3
import base64
from botocore.vendored import requests
from urllib.parse import unquote
import hmac
from hashlib import sha256

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Slack:
    response_url = None

    @staticmethod
    def process_params(event, context):
        """Process a Slack request."""
        body = Slack.parse_body(event.get('body'))
        # Verify if the message came from Slack
        if not Slack.validate_request(event):
            msg = 'Call with invalid token.'
            logger.error({'type': 'error', 'message': msg})
            
            return {'status': 'error', 'message': msg}

        # We need this because of Slack reponse timeout
        if not event.get('async'):
            Slack.invoke_self_async(event, context)
            return {'status': 'finalize', 'values': '{"response_type": "ephemeral", "text": ">Got it! This may take a few seconds."}'}

        # The URL we need to communicate with Slack asynchronous.
        Slack.response_url = body.get('response_url')
        if not Slack.response_url:
            msg = 'Failed to get response url.'
            logger.error({'type': 'error', 'message': msg})

            return {'status': 'error', 'message': msg} 

        # Get the user email from Slack
        user_email = Slack.get_email_from_slack(body['user_id'])
        if not user_email:
            Slack.respond('Error, please contact your administrator.')
            msg = 'Failed to get email from Slack.'
            logger.error({'type': 'error', 'message': msg})

            return {'status': 'error', 'message': msg}
        
        op = event['path'].split('/', 2)[-1].replace('/', '-')
        values = {'op': op, 'email': user_email, 'params': body['text'].split('+')}
        return  {'status': 'success', 'values': values}

    @staticmethod
    def invoke_self_async(event, context):
        """
        Invoke the Lambda again asynchronously, passing the same event it
        received, and adding the tag 'async' so we know to process it
        """
        event['async'] = True
        called_function = context.invoked_function_arn
        boto3.client('lambda').invoke(
            FunctionName=called_function,
            InvocationType='Event',
            Payload=json.dumps(event)
        )

    @staticmethod
    def get_email_from_slack(user_id):
        """Return the email address associated with the ID on Slack."""
        url = 'https://slack.com/api/users.profile.get'
        try:
            oauth_key = boto3.client('secretsmanager').get_secret_value(SecretId=os.environ['SLACK_OAUTH_TOKEN_SECRETSMANAGER_ARN'])['SecretString']
        except (TypeError, base64.binascii.Error):
            logger.error({'type': 'error', 'message': 'Failed to decrypt Slack Token.'})
            return None

        payload = {'token': oauth_key, 'user': user_id}
        response = requests.post(url, data=payload)

        try:
            return response.json()['profile']['email']
        except KeyError:
            logger.error({'type': 'error', 'message': response.text})
            return None

    @staticmethod
    def generate_response_payload(response_text):
        """Return a formated response payload to send to Slack."""
        resp = ''
        if isinstance(response_text, str):
            resp = response_text

        elif isinstance(response_text, list):
            for i in response_text:
                resp = f'{resp}{i}\n'
                    
        else:
            for k, v in response_text.items():
                try:
                    db_name, db_type = v
                    value = f'\n\tName: {db_name}\n\tType: {db_type}'
                except (ValueError, TypeError):
                    value = v             

                resp += '{}: {}\n'.format(k, value)

        return {'text': f'```{resp}```'}

    @staticmethod
    def respond(return_text):
        if not Slack.response_url:
            err_msg = 'Response URL not set.'
            logger.error({'type': 'error', 'message': err_msg})
            return err_msg

        payload = Slack.generate_response_payload(return_text)
        
        return requests.post(Slack.response_url, data=json.dumps(payload))

    @staticmethod
    def parse_body(body):
        result = {}
        params = body.split('&')
        for param in params:
            value, item = param.split('=')
            result[unquote(value)] = unquote(item)
        return result

    @staticmethod
    def validate_request(request):
        try:
            slack_signing_secret = boto3.client('secretsmanager').get_secret_value(SecretId=os.environ['SLACK_TOKEN_SECRETSMANAGER_ARN'])['SecretString']
        except (TypeError, base64.binascii.Error):
            logger.error({'type': 'error', 'message': 'Failed to decrypt Slack Token.'})
            return False

        timestamp = request['headers']['X-Slack-Request-Timestamp']
        request_body = request['body']
        sig_basestring = f'v0:{timestamp}:{request_body}'.encode()

        my_signature = 'v0=' + hmac.new(
                slack_signing_secret.encode(),
                sig_basestring,
                sha256
            ).hexdigest()

        slack_signature = request['headers']['X-Slack-Signature']
        if hmac.compare_digest(my_signature, slack_signature):
            return True

        return False
