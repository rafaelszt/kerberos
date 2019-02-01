import os
import logging
import json
import boto3
from base64 import b64decode
from botocore.vendored import requests
from urllib.parse import unquote

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Slack:
    response_url = None

    @staticmethod
    def process_params(event, context):
        """Process a Slack request."""
        body = Slack.parse_body(event.get('body'))
        # Verify if the message came from Slack
        if body.get('token') not in os.getenv('SLACK_TOKEN'):
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
            Slack.response('Error, please contact your administrator.')
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
        oauth_key = os.getenv('SLACK_OAUTH_TOKEN')
        try:
            oauth_key = boto3.client('kms').decrypt(CiphertextBlob=b64decode(oauth_key))['Plaintext']
        except TypeError:
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
    def response(credentials, **kwargs):
        if not Slack.response_url:
            err_msg = 'Response URL not set.'
            logger.error({'type': 'error', 'message': err_msg})
            return err_msg

        resp = ''
        for k, v in credentials.items():
            try:
                db_name, db_type = v
                value = f'\tName: {db_name}\n\tType: {db_type}'
            except Exception as e:
                print(e)

            else:
                value = v

            resp += '{}: {}\n'.format(k, value)

        payload = {'text': f'```{resp}```'}
        return requests.post(Slack.response_url, data=json.dumps(payload))

    @staticmethod
    def parse_body(body):
        result = {}
        params = body.split('&')
        for param in params:
            value, item = param.split('=')
            result[unquote(value)] = unquote(item)
        return result
