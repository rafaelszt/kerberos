"""
Envs:
SLACK_TOKEN
SLACK_OAUTH_TOKEN
DYNAMODB_USER_TABLE
DYNAMODB_REQUESTS_TABLE
DYNAMODB_REGISTERED_DBS
FUNCTION_NAME_PREFIX
AWS_ACCOUNT_ID
AUTH_KEY
"""

import os
import logging
import json
from base64 import b64decode

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr

from slack_integration import Slack
from duo import Duo
from user import User
from database_management import DatabaseManagement

logger = logging.getLogger()
logger.setLevel(logging.INFO)

db = DatabaseManagement()

def log(err_type, msg):
    """Logs a error with the right message format."""
    if err_type == 'error':
        logger.error({'type': 'error', 'message': msg})
    elif err_type == 'info':
        logger.info({'type': 'info', 'message': msg})
    elif err_type == 'debug':
        logger.debug({'type': 'debug', 'message': msg})


def get_item_from_dynamo(table_name, search):
    return db.get_item_from_dynamo(table_name, search)


def user_management(db_type, db_name, region, username):
    """Invoke the Lambda to change the password"""
    client = boto3.client('lambda', region_name=region)
    payload = json.dumps(
        {'db_name': db_name,
         'db_region': region,
         'db_type': db_type,
         'username': username}
        )

    # Invoke the lambda
    function_prefix = os.getenv('FUNCTION_NAME_PREFIX')
    response = client.invoke(FunctionName='{}-{}'.format(function_prefix, db_name),
                             Payload=payload)

    if response.get('FunctionError'):
        log(
            'error',
            'Error on gate lambda. Stack trace: {}'.format(response['Payload'].read())
        )
        return None

    try:
        payload = response['Payload']
        return json.loads(payload.read())
    except KeyError:
        log(
            'error',
            'Failed to get user credentials. Response: {}'.format(payload)
        )
        return None


def verify_mfa(user_email, user_type, auth_client, mfa_code=None, use_push=False):
    """Verify the user MFA with a push or code."""
    search = {'email': user_email, 'type': user_type}

    table_name = os.getenv('DYNAMODB_USER_TABLE')
    user_id = get_item_from_dynamo(table_name, search).get('user_id')
    
    if use_push:
        if not auth_client.push_request(user_id):
            log(
                'error',
                'Failed to verify push request'
            )
            return False

        return True

    # Verify with OTP
    return auth_client.verify_token_request(mfa_code, user_id)


def get_user_dbs(user_email, access_type='user'):
    table_name = os.getenv('DYNAMODB_USER_TABLE')
    return db.get_user_dbs(user_email, table_name, access_type)


def get_dbs_info(dbs_ids):
    table_name = os.getenv('DYNAMODB_REGISTERED_DBS')
    return db.get_dbs_info(dbs_ids, table_name)  


def get_user_access(db_code, username):
    """Return new credentials for the user."""
    db_info = get_dbs_info([db_code])
    if db_info:
        db_info = db_info[0]
        return user_management(db_info['type'], db_info['db'], db_info['region'], username)

    return None


def get_db_access(user_dbs, db_code, user_email):
    """Returns a formated Slack response with the secret."""
    username = user_dbs[db_code]['username']
    secret = get_user_access(db_code, username)

    if not secret:
        return '`Failed to get user credentials. Please contact your administrator`'

    response_txt = ''
    for k, v in secret.items():
        response_txt += '{}: {}\n'.format(k, v)

    return '```{}```'.format(response_txt)


def get_db_ids():
    table_name = os.getenv('DYNAMODB_REGISTERED_DBS')
    return db.get_db_ids(table_name)
        

def get_db_list(user_dbs, filter_param):
    table_name = os.getenv('DYNAMODB_REGISTERED_DBS')
    return db.get_db_list(user_dbs, filter_param, table_name)


def process_user_op(operation, user_email, auth_client, **kwargs):
    """
        Process an user operation.
        kwargs:
            dbaccess -> db_code
            dblist -> search_params
    """
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv('DYNAMODB_USER_TABLE'))

    if not User.exists(table, user_email):
        return '>User not registered.'

    response = 'Operation Successful'
    if not verify_mfa(user_email, 'user', auth_client, use_push=True):
        log(
            'info',
            'Failed MFA for User. Email: {}'.format(user_email)
        )
        return '>MFA: Failed'
        
    user_dbs = get_user_dbs(user_email)

    if not user_dbs:
        return 'You have no databases to access.'
    
    if operation == 'user-database-access':
        db_code = kwargs['db_code']
        response = get_db_access(user_dbs, db_code, user_email)

    elif operation == 'user-database-list':
        search_param = kwargs['search_param']
        response = get_db_list(user_dbs, search_param)

    return response


def process_admin_op(operation, user_email, auth_client, **kwargs):
    """
        Process an admin operation.
        kwargs:
            admin-usernew -> email, phone_number
            admin-userdelete -> email
            admin-dbadd -> email, db_id, username
            admin-dbremove -> email, db_id
    """
    dbs_id = get_db_ids()
    response = '>Operation Successful'

    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv('DYNAMODB_USER_TABLE'))

    if not verify_mfa(user_email, 'admin', auth_client, use_push=True):
        log(
            'info',
            'Failed MFA for User. Email: {}'.format(user_email)
        )
        return '>MFA: Failed'

    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv('DYNAMODB_USER_TABLE'))

    if operation == 'admin-database-list':
        return get_db_list(dbs_id, None)

    email = kwargs['email']
    if operation == 'admin-user-create':
        phone_number = kwargs['phone_number']
        User.create(table, auth_client, email, phone_number)
    
    # The operations after this require the user to exist
    if not User.exists(table, email):
        return 'This user does not exist.'

    if operation == 'admin-database-remove':
        db_id = kwargs['db_id']
        User.remove_access(table, email, db_id)

    elif operation == 'admin-database-add':
        db_id = kwargs['db_id']
        if db_id in dbs_id:
            User.grant_access(table, email, db_id, kwargs['username'])
            return response

        else:
            return  'Access Denied'

    elif operation == 'admin-user-delete':
        User.delete(table, email)

    return response


def process_command(operation, user_email, params):
    """Processes a given operation."""
    user_endpoints = ['user-database-access', 'user-database-list']
    admin_endpoints = ['admin-database-add', 'admin-database-remove', 'admin-user-create', 'admin-user-delete', 'admin-database-list']

    auth_client_key = os.environ['AUTH_KEY']
    auth_client_key = boto3.client('kms').decrypt(CiphertextBlob=b64decode(auth_client_key))['Plaintext']
    auth_client_key = json.loads(auth_client_key.decode())
    
    auth_client = Duo(**auth_client_key)
    
    if operation in user_endpoints:
        try:
            if operation == "user-database-access":
                params = {"db_code": params[0]}
            elif operation == "user-database-list":
                if params:
                    params = {"search_param": params[0]}
                else:
                    params = {"search_param": None}
        
        except KeyError:
            return "Ops, missing command parameters."

        return process_user_op(operation, user_email, auth_client, **params)

    if operation in admin_endpoints:
        try:
            if operation == "admin-user-create":
                params = {"email": params[0], "phone_number": params[1]}
            elif operation == "admin-user-delete":
                params = {"email": params[0]}
            elif operation == "admin-database-add":
                params = {"email": params[0], "db_id": params[1], "username": params[2]}
            elif operation == "admin-database-remove":
                params = {"email": params[0], "db_id": params[1]}
            else:
                params = {}

        except KeyError:
            return "Ops, missing command parameters."

        return process_admin_op(operation, user_email, auth_client, **params)

    return 'Unknown Error'


def already_requested(lambda_requestID, api_requestId, timestamp):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.getenv('DYNAMODB_REQUESTS_TABLE'))
    
    item_id = '{}:{}:{}'.format(
            lambda_requestID,
            api_requestId,
            timestamp
        )
    
    try:
        table.put_item(
            Item={
                    'id': item_id,
                    'lambda_requestID': lambda_requestID,
                    'api_requestId': api_requestId,
                    'timestamp': timestamp
                },
                ConditionExpression='attribute_not_exists(id)'
            )
        
    except ClientError as e:
        table.update_item(
           Key={
                'id': item_id
            },
            UpdateExpression='add runs :num',
            ExpressionAttributeValues={
                ':num': 1
            }
        )
    
        return True
    
    return False


def lambda_handler(event, context):
    """Main Lambda function"""
    # Check if it's our keep alive call
    if event.get('source') == 'aws.events':
        log(
            'debug',
            'Keep Warm triggered.'
        )
        return {'status_code': '200'}

    if already_requested(
            context.aws_request_id,
            event['requestContext']['requestId'],
            event['requestContext']['requestTimeEpoch']
        ):
        return {
            'isBase64Encoded': False,
            'statusCode': 200
        }

    # For now we only have Slack, we can add more methods in the future
    req = Slack.process_params(event, context)
    if req['status'] == 'finalize':
        return {
                'isBase64Encoded': False,
                'statusCode': 200,
                'body': '{"response_type": "ephemeral", "text": ">Got it! This may take a few seconds."}'
            }
    
    elif req['status'] == 'success':
        values = req['values']
        response = process_command(values['op'], values['email'], values['params'])
        Slack.response(response)

    return {
        'isBase64Encoded': False,
        'statusCode': 200
    }
    