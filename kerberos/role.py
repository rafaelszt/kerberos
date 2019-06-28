import logging
import boto3
import uuid
import json

from schema import Schema

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class Role:
    table = None

    @staticmethod
    def create(name):
        role_id = uuid.uuid4().hex[:4]
        logger.info({'status': 'create', 'type': 'role', 'id': role_id})

        Role.table.put_item(
            Item={
                'id': role_id,
                'name': name,
                'schema_list': set("0")
        })
        
        return role_id

    @staticmethod
    def delete(role_id):
        logger.info({'status': 'delete', 'type': 'role', 'id': role_id})
        Role.table.delete_item(
            Key={
                'id': role_id
            }
        )

        return True

    @staticmethod
    def add_schema(role_id, schema_id):
        from user import User

        logger.info({'status': 'add', 'type': 'role', 'role_id': role_id, 'schema_id': schema_id})
        Role.table.update_item(
            Key={
                'id': role_id
            },
            UpdateExpression='ADD schema_list :schema_id',
            ExpressionAttributeValues={':schema_id': set(schema_id)} 
        )

        users = User.get_users_with_role(role_id)
        role_name = Role.get_role_name(role_id)
        for email in users:
            User.change_role(email, schema_id, role_name, 'add_group')

        return True

    @staticmethod
    def remove_schema(role_id, schema_id):
        from user import User

        logger.info({'status': 'remove', 'type': 'role', 'role_id': role_id, 'schema_id': schema_id})

        Role.table.update_item(
            Key={
                'id': role_id
            },
            UpdateExpression='DELETE schema_list :schema_id',
            ExpressionAttributeValues={
                ':schema_id': set(schema_id)
            }
        )

        users = User.get_users_with_role(role_id)
        role_name = Role.get_role_name(role_id)
        for email in users:
            User.change_role(email, schema_id, role_name, 'drop_group')

        return True

    @staticmethod
    def list_current():
        logger.info({'status': 'list', 'type': 'role'})
        roles_info = Role.table.scan().get('Items')

        roles = ''
        for role in roles_info:
            role['schema_list'] = list(role['schema_list'])
            roles += json.dumps(role, indent=4)

        return roles

    @staticmethod
    def exists(role_id):
        return Role.table.get_item(
                Key={
                    'id': role_id
                }
            ).get('Item')
        
    @staticmethod
    def get_schemas_info(role_id):
        logger.info({'status': 'get_schemas', 'type': 'role', 'role_id': role_id})
        schemas_info = Role.table.get_item(
                            Key={
                                'id': role_id
                            }
                        ).get('Item')

        schemas = []
        for schema in list(schemas_info['schema_list']):
            if schema == '0':
                continue

            schemas.append(Schema.get_info(schema))

        return schemas

    @staticmethod
    def get_role_name(role_id):
        role = Role.table.get_item(
                            Key={
                                'id': role_id
                            }
                        ).get('Item')

        return role['name']

    @staticmethod
    def get_schemas(role_id):
        schemas_info = Role.table.get_item(
                            Key={
                                'id': role_id
                            }
                        ).get('Item')

        return list(schemas_info['schema_list'])
