import boto3
import logging

from boto3.dynamodb.conditions import Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class DatabaseManagement:
    def __init__(self):
        self.aws_conn = boto3.resource('dynamodb')

    def get_item_from_dynamo(self, table_name, search):
        """Return an item from a given table in JSON format."""
        table = self.aws_conn.Table(table_name)

        response = table.get_item(Key=search)
        try:
            return response['Item']
        except KeyError:
            logger.error({
                'type': 'error', 'message': 
                'Could not get item from dynamo on table {} with search {}'
                                                .format(table_name, search)
            })
            return {}

    def get_user_dbs(self, user_email, table_name, access_type='user'):
        """Return the databases ID the user has access to."""
        search = {'email': user_email, 'type': access_type}

        result = self.get_item_from_dynamo(table_name, search)
        return result.get('db_list')

    def get_dbs_info(self, dbs_ids, table_name):
        """Return the databases names."""
        dbs_info = []

        for db_id in dbs_ids:
            db_info = self.get_item_from_dynamo(table_name, {'id': db_id})

            if not db_info:
                logger.error({
                    'error',
                    'Failed to get Database information.'
                })
                return None

            dbs_info.append(db_info)

        return dbs_info

    def get_db_ids(self, table_name):
        table = self.aws_conn.Table(table_name)
        dbs_info = table.scan()['Items']
        
        ids = []
        for db in dbs_info:
            ids.append(db['id'])
            
        return ids

    def get_db_list(self, user_dbs, filter_param, table_name):
        """Return a formated message to Slack with the database information."""
        table = self.aws_conn.Table(table_name)

        dbs_info = {}
        if filter_param:
            fe = Attr('name').contains(filter_param)
            dbs_info = table.scan(FilterExpression=fe)['Items']
            
        else:
            dbs_info = table.scan()['Items']

        response_txt = ''
        for db in dbs_info:
            if db['id'] in user_dbs:
                response_txt += 'Id: {}\n\tName: {}\n\tType: {}\n'.format(
                    db['id'], db['name'], db['type'])
        
        return '```{}```'.format(response_txt)
