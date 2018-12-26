import os
import unittest
from unittest.mock import patch
import logging

from Kerberos.slack_integration import Slack

logger = logging.getLogger()

class TestSlackIntegration(unittest.TestCase):
    def test_parse_body_correctly(self):
        body = 'param1=value1&param2=value2&param3=value3'
        result = {'param1': 'value1', 'param2': 'value2', 'param3': 'value3'}

        parsed_body = Slack.parse_body(body)
        self.assertEqual(parsed_body, result)

    def test_response_url_not_set(self):
        Slack.response_url = None
        with self.assertLogs(level='ERROR') as cm:
            log_name = logger.name
            err_msg = '{"type": "error", "message": "Response URL not set."}'
            Slack.response('')
            self.assertEqual(cm.output, ['ERROR:{}:{}'.format(log_name, err_msg)])

    def test_process_params(self):
        event = {}
        event['body'] = 'token=abc123&response_url=https://example.com&user_id=123'
        event['async'] = True

        with patch.dict('os.environ', {'SLACK_TOKEN': 'abc123'}):
            with self.assertLogs(level='ERROR') as cm:
                Slack.process_params(event, None)

                log_name = logger.name
                err_msg_1 = '{"type": "error", "message": "Failed to decrypt Slack Token."}'
                err_msg_2 = '{"type": "error", "message": "Failed to get email from Slack."}'

                self.assertEqual(cm.output, [
                    'ERROR:{}:{}'.format(log_name, err_msg_1),
                    'ERROR:{}:{}'.format(log_name, err_msg_2)
                    ])    

if __name__ == '__main__':
    unittest.main()
    