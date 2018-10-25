import os
import boto3
from base64 import b64decode
from authy import Authy

class Admin:
    @staticmethod
    def create(table, auth_instance, email, phone_number):
        authy_user = auth_instance.create_user(email, phone_number, use_authy=True)
        authy_id = authy_user['user']['id']

        table.put_item(
            Item={
                'email': email,
                'type': 'admin',
                'authy_id': authy_id,
                'db_list': set('0')
            }
        )
        
        return True

    @staticmethod
    def delete(table, email):
        table.delete_item(
            Key={
                'email': email,
                'type': 'admin'
            }
        )

        return True

    @staticmethod
    def grant_access(table, email, db_id):
        table.update_item(
            Key={
                'email': email,
                'type': 'admin'
            },
            UpdateExpression='ADD db_list :db_id',
            ExpressionAttributeValues={
                ':db_id':  set(db_id)
            }
        )

    @staticmethod
    def remove_access(table, email, db_id):
        table.update_item(
            Key={
                'email': email,
                'type': 'admin'
            },
            UpdateExpression='DELETE db_list :db_id',
            ExpressionAttributeValues={
                ':db_id': set(db_id)
            }
        )

    @staticmethod
    def exists(table, email):
        return table.get_item(
            Key={
                'email': email,
                'type': 'admin'
            }
        ).get("Item")