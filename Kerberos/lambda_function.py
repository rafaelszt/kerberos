"""
Envs:
SLACK_TOKEN
SLACK_OAUTH_TOKEN
DYNAMODB_USER_TABLE
DYNAMODB_REQUESTS_TABLE
AWS_ACCOUNT_ID
AUTH_KEY
"""

import os
import logging
import json
from base64 import b64decode
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr

from slack_integration import Slack
from duo import Duo
from user import User

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def log(err_type, msg):
    """Logs a error with the right message format."""
    if err_type == "error":
        logger.error({"type": "error", "message": msg})
    elif err_type == "info":
        logger.info({"type": "info", "message": msg})
    elif err_type == "debug":
        logger.debug({"type": "debug", "message": msg})


def get_item_from_dynamo(table_name, search):
    """Return an item from a given table in JSON format."""
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(table_name)

    response = table.get_item(Key=search)
    try:
        return response["Item"]
    except KeyError:
        log(
            "error",
            "Could not get item from dynamo on table {} with search {}".format(table_name, search)
        )
        return {}


def user_management(db_type, db_name, region, username):
    """Invoke the Lambda to change the password"""
    client = boto3.client('lambda', region_name=region)
    payload = json.dumps(
        {"db_name": db_name,
         "db_region": region,
         "db_type": db_type,
         "username": username}
        )

    # Invoke the lambda
    response = client.invoke(FunctionName="alpha_v2_{}".format(db_name),
                             Payload=payload)

    try:
        payload = response["Payload"]
        return json.loads(payload.read())
    except KeyError:
        log(
            "error",
            "Failed to get user credentials. Response: {}".format(payload)
        )
        return None


def verify_mfa(user_email, user_type, auth_client, mfa_code=None, use_push=False):
    """Verify the user MFA with a push or code."""
    table_name = "DYNAMODB_USER_TABLE"
    search = {"email": user_email, "type": user_type}

    table_name = os.getenv(table_name)
    try:
        user_id = get_item_from_dynamo(table_name, search).get("user_id")
    except KeyError:
        log(
            "error",
            "Failed to get data from Users table"
        )
        return None

    if use_push:
        if not auth_client.push_request(user_id):
            log(
                "error",
                "Failed to verify push request"
            )
            return False

        return True

    # Verify with OTP
    return auth_client.verify_token_request(mfa_code, user_id)


def get_user_dbs(user_email, access_type="user"):
    """Return the databases ID the user has access to."""
    access_table = "DYNAMODB_USER_TABLE"
    search = {"email": user_email, "type": access_type}

    result = get_item_from_dynamo(os.getenv(access_table), search)
    return result.get("db_list")


def get_dbs_info(dbs_ids):
    """Return the databases names."""
    dbs_info = []
    table_name = os.getenv("DYNAMODB_REGISTERED_DBS")

    for db_id in dbs_ids:
        db_info = get_item_from_dynamo(table_name, {"id": db_id})

        if not db_info:
            log(
                "error",
                "Failed to get Database information."
            )
            return None

        dbs_info.append(db_info)

    return dbs_info


def get_user_access(db_code, username):
    """Return new credentials for the user."""
    db_info = get_dbs_info([db_code])
    if db_info:
        db_info = db_info[0]
        return user_management(db_info["type"], db_info["name"], db_info["region"], username)

    return None


def update_last_used(email, db_code):
    """Update when the user last used the database."""
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv("DYNAMODB_USER_TABLE"))
    hour = datetime.now().hour - 1

    table.update_item(
        Key={
            'email': email,
            'type': 'user'
        },
        UpdateExpression='SET db_list.#db_code.last_used = :hour',
        ExpressionAttributeValues={
            ':hour': hour
        },
        ExpressionAttributeNames={
            '#db_code': db_code
        }
    )


def get_db_access(user_dbs, db_code, user_email):
    """Returns a formated Slack response with the secret."""
    username = user_dbs[db_code]["username"]
    secret = get_user_access(db_code, username)

    if not secret:
        return None

    response_txt = ""
    for k, v in secret.items():
        response_txt += "{}: {}\n".format(k, v)

    update_last_used(user_email, db_code)
    return "```{}```".format(response_txt)


def get_db_ids():
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv('DYNAMODB_REGISTERED_DBS'))

    dbs_info = table.scan()['Items']
    
    ids = []
    for db in dbs_info:
        ids.append(db['id'])
        
    return ids
        

def get_db_list(user_dbs, filter_param):
    """Return a formated message to Slack with the database information."""
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv('DYNAMODB_REGISTERED_DBS'))

    dbs_info = {}
    if filter_param:
        fe = Attr('name').contains(filter_param)
        dbs_info = table.scan(FilterExpression=fe)['Items']
        
    else:
        dbs_info = table.scan()['Items']

    response_txt = ""
    for db in dbs_info:
        if db["id"] in user_dbs:
            response_txt += "Id: {}\n\tName: {}\n\tType: {}\n".format(
                db["id"], db["name"], db["type"])
    
    return "```{}```".format(response_txt)


def process_user_op(operation, user_email, auth_client, **kwargs):
    """
        Process an user operation.
        kwargs:
            dbaccess -> db_code
            dblist -> search_params
    """
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv("DYNAMODB_USER_TABLE"))

    if not User.exists(table, user_email):
        return ">User not registered."

    response = "Operation Successful"
    if not verify_mfa(user_email, "user", auth_client, use_push=True):
        log(
            "info",
            "Failed MFA for User. Email: {}".format(user_email)
        )
        return ">MFA: Failed"
        
    user_dbs = get_user_dbs(user_email)

    if not user_dbs:
        return "You have no databases to access."
    
    if operation == "user-database-access":
        db_code = kwargs["db_code"]
        response = get_db_access(user_dbs, db_code, user_email)

    elif operation == "user-database-list":
        search_param = kwargs["search_param"]
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
    response = ">Operation Successful"

    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv("DYNAMODB_USER_TABLE"))

    if not verify_mfa(user_email, "admin", auth_client, use_push=True):
        log(
            "info",
            "Failed MFA for User. Email: {}".format(user_email)
        )
        return ">MFA: Failed"

    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv("DYNAMODB_USER_TABLE"))

    if operation == "admin-database-list":
        return get_db_list(dbs_id, None)

    email = kwargs["email"]
    if operation == "admin-user-create":
        phone_number = kwargs["phone_number"]
        User.create(table, auth_client, email, phone_number)
    
    # The operations after this require the user to exist
    if not User.exists(table, email):
        return "This user does not exist."

    if operation == "admin-database-remove":
        db_id = kwargs["db_id"]
        User.remove_access(table, email, db_id)

    elif operation == "admin-database-add":
        db_id = kwargs["db_id"]
        if db_id in dbs_id:
            User.grant_access(table, email, db_id, kwargs["username"])
            return response

        else:
            return  "Access Denied"

    elif operation == "admin-user-delete":
        User.delete(table, email)

    return response


def process_command(operation, user_email, params):
    """Processes a given operation."""
    user_endpoints = ["user-database-access", "user-database-list"]
    admin_endpoints = ["admin-database-add", "admin-database-remove", "admin-user-create", "admin-user-delete", "admin-database-list"]

    auth_client_key = os.environ["AUTH_KEY"]
    auth_client_key = boto3.client('kms').decrypt(CiphertextBlob=b64decode(auth_client_key))["Plaintext"]
    auth_client_key = json.loads(auth_client_key.decode())
    
    auth_client = Duo(**auth_client_key)
    
    if operation in user_endpoints:
        if operation == "user-database-access":
            params = {"db_code": params[0]}
        elif operation == "user-database-list":
            if params:
                params = {"search_param": params[0]}
            else:
                params = {"search_param": None}

        return process_user_op(operation, user_email, auth_client, **params)

    if operation in admin_endpoints:
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

        return process_admin_op(operation, user_email, auth_client, **params)

    return "Unknown Error"


def reset_passw():
    """Reset the user passwords if 24 hours has passed."""
    aws_conn = boto3.resource('dynamodb')
    table = aws_conn.Table(os.getenv("DYNAMODB_USER_TABLE"))
    hour = datetime.now().hour

    items = table.scan()["Items"]

    for user in items:
        db_list = user["db_list"]
        for db_code, db_values in db_list.items():
            if hour - db_values["last_used"] == 0:
                get_user_access(db_code, db_values["username"])


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
            UpdateExpression="add runs :num",
            ExpressionAttributeValues={
                ':num': 1
            }
        )
    
        return True
    
    return False


def lambda_handler(event, context):
    """Main Lambda function"""
    # Check if it's our keep alive call
    if event.get("source") == "aws.events" and event.get("account") == os.getenv("AWS_ACCOUNT_ID"):
        if (
                event.get("resources")[0] ==
                "arn:aws:events:us-east-1:401945422757:rule/Kerberos_Reset_Passw"
            ):
            reset_passw()
            return None

        log(
            "debug",
            "Keep Warm triggered."
        )
        return {"status_code": "200"}

    if already_requested(
            context.aws_request_id,
            event['requestContext']['requestId'],
            event['requestContext']['requestTimeEpoch']
        ):
        return {
            "isBase64Encoded": False,
            "statusCode": 200
        }

    # For now we only have Slack, we can add more methods in the future
    req = Slack.process_params(event, context)
    if req["status"] == "finalize":
        return {
                "isBase64Encoded": False,
                "statusCode": 200,
                "body": '{"response_type": "ephemeral", "text": ">Got it! This may take a few seconds."}'
            }
    
    elif req["status"] == "success":
        values = req["values"]
        response = process_command(values["op"], values["email"], values["params"])
        Slack.response(response)

    return {
        "isBase64Encoded": False,
        "statusCode": 200
    }
    