import os
import boto3
from base64 import b64decode
import logging
import json

from role import Role
from schema import Schema


logger = logging.getLogger()
logger.setLevel(logging.INFO)

class User:
    table = None

    @staticmethod
    def create(auth_instance, email, phone_number):
        logger.info({'status': 'create', 'type': 'user', 'email': email})

        auth_user = auth_instance.create_user(email, phone_number, use_push=True)
        user_id = auth_user['user_id']

        User.table.put_item(
            Item={
                'email': email,
                'type': 'user',
                'user_id': user_id,
                'role_list': set("0")
        })
        
        return True

    @staticmethod
    def delete(email):
        logger.info({'status': 'delete', 'type': 'user', 'email': email})
        User.table.delete_item(
            Key={
                'email': email,
                'type': 'user'
            }
        )

        return True

    @staticmethod
    def add_role(email, role_id):
        logger.info({'status': 'grant', 'type': 'user', 'email': email, 'role_id': role_id})
        User.table.update_item(
            Key={
                'email': email,
                'type': 'user'
            },
            UpdateExpression='ADD role_list :role_id',
            ExpressionAttributeValues={
                ':role_id': set([role_id])
                }
        )

        role_name = Role.get_role_name(role_id)
        schemas = Role.get_schemas(role_id)

        for schema in schemas:
            if schema == '0':
                continue
            User.change_role(email, schema, role_name, 'add_group')

        return True

    @staticmethod
    def remove_role(email, role_id):
        logger.info({'status': 'remove', 'type': 'user', 'email': email, 'role_id': role_id})
        User.table.update_item(
            Key={
                'email': email,
                'type': 'user'
            },
            UpdateExpression='DELETE role_list :role_id',
            ExpressionAttributeValues={
                ':role_id': set([role_id])
            }
        )

        role_name = Role.get_role_name(role_id)
        schemas = Role.get_schemas(role_id)

        for schema in schemas:
            if schema == '0':
                continue
            User.change_role(email, schema, role_name, 'drop_group')

    @staticmethod
    def list_current():
        logger.info({'status': 'list', 'type': 'user'})
        user_list = User.table.scan()['Items']
        
        users = []
        for c_user in user_list:
            if c_user['type'] == 'user':
                c_user['role_list'] = list(c_user['role_list'])
            
            users.append(c_user)

        return users

    @staticmethod
    def exists(email, access_level='user'):
        return User.table.get_item(
                Key={
                    'email': email,
                    'type': access_level
                }
            ).get('Item')
        
    @staticmethod
    def get_schemas(email):
        logger.info({'status': 'get_schemas', 'type': 'user', 'email': email})

        user_info =  User.table.get_item(
            Key={
                'email': email,
                'type': 'user'
            }
        ).get('Item')

        schemas = []
        for role in list(user_info['role_list']):
            if role == '0':
                continue

            schemas = schemas + Role.get_schemas_info(role)

        return schemas

    @staticmethod
    def has_access(email, schema_id):
        user_schemas = User.get_schemas(email)
        for schema in user_schemas:
            if schema['id'] == schema_id:
                return True
        
        return False

    @staticmethod
    def get_roles(email):
        user_info = User.table.get_item(
            Key={
                'email': email,
                'type': 'user'
            }
        ).get('Item')

        return list(user_info['role_list'])

    @staticmethod
    def clean_username(username):
        username = username.replace('.', '')
        username = username.replace('-', '')
        username = username.replace('_', '')
        
        return username

    @staticmethod
    def request_access(email, schema_id):
        logger.info({'status': 'access', 'type': 'user', 'email': email, 'schema_id': schema_id})
        user_id = User.clean_username(email.split('@')[0])

        schema_info = Schema.get_info(schema_id)

        payload = json.dumps(
            {'db_name': schema_info['db'],
            'db_region': schema_info['region'],
            'db_type': schema_info['type'],
            'username': user_id}
            )

        # Invoke the lambda
        client = boto3.client('lambda', region_name=schema_info['region'])
        function_prefix = os.getenv('FUNCTION_NAME_PREFIX')
        response = client.invoke(FunctionName='{}-{}'.format(function_prefix, schema_info['db']),
                                Payload=payload)
        
        try:
            payload = response['Payload']
            return json.loads(payload.read())

        except KeyError as e:
            logger.info({'status': 'error', 'type': 'user', 'email': email, 'error': e})
            return False

    
    @staticmethod
    def change_role(email, schema_id, role_name, type_change):
        logger.info({'status': 'change_role', 'type': 'user', 'email': email, 'schema_id': schema_id, 'type_change': type_change})
        user_id = User.clean_username(email.split('@')[0])

        schema_info = Schema.get_info(schema_id)

        payload = json.dumps(
            {'db_name': schema_info['db'],
            'db_region': schema_info['region'],
            'db_type': schema_info['type'],
            'username': user_id,
            'type': type_change,
            'group': role_name}
            )

        # Invoke the lambda
        client = boto3.client('lambda', region_name=schema_info['region'])
        function_prefix = os.getenv('FUNCTION_NAME_PREFIX')
        response = client.invoke(FunctionName='{}-{}'.format(function_prefix, schema_info['db']),
                                Payload=payload)
        
        try:
            payload = response['Payload']
            return json.loads(payload.read())

        except KeyError as e:
            logger.info({'status': 'error', 'type': 'user', 'email': email, 'error': e})
            return False

    @staticmethod
    def get_users_with_role(role_id):
        current_users = User.list_current()

        users = []
        print(current_users)
        for current_user in current_users:
            print(current_user)
            if current_user.get('type') == 'user' and role_id in current_user.get('role_list'):
                users.append(current_user.get('email'))
        
        return users