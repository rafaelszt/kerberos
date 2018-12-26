import os
import boto3
from base64 import b64decode
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)

class User:
    @staticmethod
    def create(table, auth_instance, email, phone_number):
        logger.info({'status': 'create', 'type': 'user', 'email': email})

        auth_user = auth_instance.create_user(email, phone_number, use_push=True)
        user_id = auth_user['user_id']

        table.put_item(
            Item={
                'email': email,
                'type': 'user',
                'user_id': user_id,
                'db_list': {}
        })
        
        return True

    @staticmethod
    def delete(table, email):
        logger.info({'status': 'delete', 'type': 'user', 'email': email})
        table.delete_item(
            Key={
                'email': email,
                'type': 'user'
            }
        )

        return True

    @staticmethod
    def grant_access(table, email, db_id, db_username):
        logger.info({'status': 'grant', 'type': 'user', 'email': email, 'db_id': db_id, 'username': db_username})
        table.update_item(
            Key={
                'email': email,
                'type': 'user'
            },
            UpdateExpression='SET db_list.#db_id = :db_data',
            ExpressionAttributeValues={
                ':db_data': {
                    'username': db_username,
                    'last_used': 0
                }},
            ExpressionAttributeNames={
                '#db_id': db_id
            }
        )

        return True

    @staticmethod
    def remove_access(table, email, db_id):
        logger.info({'status': 'remove', 'type': 'user', 'email': email, 'db_id': db_id})

        table.update_item(
            Key={
                'email': email,
                'type': 'user'
            },
            UpdateExpression='REMOVE db_list.#db_id',
            ExpressionAttributeNames={
                '#db_id': db_id
            }
        )

    @staticmethod
    def exists(table, email):
        return table.get_item(
                Key={
                    'email': email,
                    'type': 'user'
                }
            ).get('Item')
        