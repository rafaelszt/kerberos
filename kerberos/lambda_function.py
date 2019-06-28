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
from email_integration import Email
from duo import Duo
from user import User
from role import Role
from schema import Schema

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def verify_mfa(user_email, user_type, auth_client, mfa_code=None, use_push=False):
    """Verify the user MFA with a push or code."""
    user_id = user_email.split('@')[0]
    
    if use_push:
        if not auth_client.push_request(user_id):
            logger.error({'status': '2fa', 'reason': 'failed to verify push request', 'user': user_email})
            return False

        return True

    # Verify with OTP
    return auth_client.verify_token_request(mfa_code, user_id)
      

def process_user_op(operation, user_email, auth_client, args):
    """
        Process an user operation.
        kwargs:
            dbaccess -> db_code
            dblist -> search_params
    """
    response = '>Operation Successful'
    if not User.exists(user_email):
        return '>User not registered.'

    if not verify_mfa(user_email, 'user', auth_client, use_push=True):
        return '>MFA: Failed'

    if operation == 'user-database-access':
        if User.has_access(user_email, args[0]):
            response = User.request_access(user_email, args[0])
        else:
            return '>Invalid ID or you don\'t have access to this schema.'

        if not response:
            return '>Failed to get user credentials. Please contact your administrator.'

    if operation == 'user-database-list':
        response = User.get_schemas(user_email)

        if not len(response):
            return '>No role associated. Please contact your administrator.'

    return response


def process_role(args):
    """
        args:
            0 -> operation
            create:
                1 -> role_name
            delete, add-schema, remove-schema:
                1 -> role_id
                add-schema, remove-schema:
                    2 -> schema_id
    """
    operation = args[0]
    
    if operation == 'list':
        return Role.list_current()

    role = args[1]
    if role == '':
        return '>Missing parameters.'
    
    if operation == 'create':
        role_id = Role.create(role)

        return f'>Role created with ID: {role_id}'

    if not Role.exists(role):
        return '>Role does not exist.'
    
    if operation == 'delete':
        Role.delete(role)
        return f'>Role {role} deleted.'

    try:
        schema_id = args[2]
    except IndexError:
        return '>No scheme id specified.'

    if operation == 'add-schema':
        Role.add_schema(role, schema_id)

        return f'>Schema {schema_id} added to role {role}'

    elif operation == 'remove-schema':
        Role.remove_schema(role, schema_id)
        return f'>Schema {schema_id} removed from role {role}'

    return False


def process_user(auth_instance, args):
    """
        args:
            0 -> operation
            1 -> email
            create:
                2 -> phone_number
            add-role, remove-role:
                2 -> role_id
    """
    operation = args[0]

    if operation == 'list':
        return User.list_current()

    email = args[1]    
    if email == '':
        return '>No email specified.'

    if operation == 'create':
        try:
            phone_number = args[2]
        except IndexError:
            return '>No phone number specified.'

        User.create(auth_instance, email, phone_number)
        return f'>User {email} created.'
    
    if not User.exists(email):
        return f'>User {email} does not exist.'

    if operation == 'delete':
        User.delete(email)
        return f'>User {email} deleted.'

    try:
        role_id = args[2]
    except IndexError:
        return '>No role id specified.'

    if operation == 'add-role':
        User.add_role(email, role_id)
        return f'>Role {role_id} added to user {email}.'
    
    elif operation == 'remove-role':
        User.remove_role(email, role_id)
        return f'>Role {role_id} removed from user {email}.'

    return False


def process_database():
    operation = 'list'

    if operation == 'list':
        return Schema.get_all()


def process_admin_op(operation, user_email, auth_client, args):
    """
        Process an admin operation.
        kwargs:
            adm-user-create -> email, phone_number
            adm-user-delete -> email
            adm-user-add-role -> email, role_id
            adm-user-remove-role -> email, role_id
            adm-role-create -> role_name
            adm-role-delete -> role_name
            adm-role-add-schema -> role_id, schema_id
            adm-role-remove-schema -> role_id, schema_id
            adm-list-role
            adm-list-schema
            adm-list-user
    """
    if not User.exists(user_email, 'admin'):
        return ">Access Denied"

    if not verify_mfa(user_email, 'admin', auth_client, use_push=True):
        return '>MFA: Failed'

    # Get only the first two parts of the operation
    main_op = "-".join(operation.split('-')[:2])

    # Get the second part of the operation
    second_op = operation.split('-', 2)[2]

    response = '>Operation Successful'  
    if main_op == 'admin-user':
        response = process_user(auth_client, [second_op] + args)

    elif main_op == 'admin-role':
        response = process_role([second_op] + args)
    
    elif main_op == 'admin-database':
        response = process_database()

    if response == False:
        response = '>Sorry, but something wen\'t wrong.'

    return response


def process_command(operation, user_email, args):
    """Processes a given operation."""
    user_endpoints = ['user-database-access', 'user-database-list']
    admin_endpoints = [
            'admin-role-add-schema', 
            'admin-role-remove-schema', 
            'admin-role-create',
            'admin-role-delete',
            'admin-role-list',
            'admin-user-create', 
            'admin-user-delete',
            'admin-user-add-role',
            'admin-user-remove-role',
            'admin-user-list',
            'admin-database-list'
        ]

    aws_conn = boto3.resource('dynamodb')
    User.table = aws_conn.Table(os.getenv('DYNAMODB_USER_TABLE'))
    Role.table = aws_conn.Table(os.getenv('DYNAMODB_ROLE_TABLE'))
    Schema.table = aws_conn.Table(os.getenv('DYNAMODB_REGISTERED_DBS'))

    auth_client_key = boto3.client('secretsmanager').get_secret_value(SecretId=os.environ['AUTH_KEY_SECRETSMANAGER_ARN'])['SecretString']
    auth_client_key = json.loads(auth_client_key)
    
    auth_client = Duo(**auth_client_key)
    
    if operation in user_endpoints:
        return process_user_op(operation, user_email, auth_client, args)

    if operation in admin_endpoints:
        return process_admin_op(operation, user_email, auth_client, args)

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
        logger.info({'status': 'aws.events', 'info': 'keep warm triggered'})
        return {'status_code': '200'}

    # Avoid the same request multiple times
    if already_requested(
            context.aws_request_id,
            event['requestContext']['requestId'],
            event['requestContext']['requestTimeEpoch']
        ):
        return {
            'isBase64Encoded': False,
            'statusCode': 200
        }

    request_type = None
    if event.get('Records') and event['Records'][0].get('eventSource') == 'aws:ses':
        request_type = Email()
    else:
        request_type = Slack()
        
    req = request_type.process_params(event, context)
    
    if req.get('status') == 'finalize':
        return   {
                'isBase64Encoded': False,
                'statusCode': 200,
                'body': '{"response_type": "ephemeral", "text": ">Got it! This may take a few seconds."}'
            }
    
    elif req.get('status') == 'success':
        values = req['values']
        response = process_command(values['op'], values['email'], values['params'])
        request_type.respond(response)

    return {
        'isBase64Encoded': False,
        'statusCode': 200
    }
    