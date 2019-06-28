import logging
import boto3
import uuid
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class Schema:
    table = None

    @staticmethod
    def get_info(schema_id):
        return Schema.table.get_item(
            Key={
                'id': schema_id
            }
        ).get('Item')

    @staticmethod
    def get_all():
        schemas = Schema.table.scan().get('Items')

        all_schemas = ''
        for schema in schemas:
            all_schemas += json.dumps(schema, sort_keys=True, indent=4)

        return all_schemas

