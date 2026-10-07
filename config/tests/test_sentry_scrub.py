from django.test import SimpleTestCase

from config.sentry_scrub import scrub_sentry_event


class SentryScrubTests(SimpleTestCase):
    def test_strips_query_referer_authorization_and_frame_vars(self):
        event = {
            'message': 'GET https://host/?setup_token=secret failed',
            'request': {
                'url': 'https://host/storage/v1/share/link/sekret-token?setup_token=secret',
                'query_string': 'setup_token=secret',
                'cookies': {'sessionid': 'abc'},
                'data': {'password': 'x'},
                'headers': {
                    'Authorization': 'Bearer tok',
                    'Referer': 'https://evil/?token=1',
                    'Cookie': 'a=b',
                    'User-Agent': 'curl',
                },
            },
            'exception': {
                'values': [
                    {
                        'value': 'Bearer supersecrettoken',
                        'stacktrace': {'frames': [{'vars': {'api_key': 'esk_secret'}}]},
                    }
                ]
            },
        }
        scrub_sentry_event(event, {})
        self.assertEqual(event['request']['url'], 'https://host/storage/v1/share/link/[filtered]')
        self.assertNotIn('query_string', event['request'])
        self.assertNotIn('cookies', event['request'])
        self.assertNotIn('data', event['request'])
        self.assertEqual(event['request']['headers'], {'User-Agent': 'curl'})
        self.assertNotIn('setup_token', event['message'])
        self.assertNotIn('sekret-token', event['request']['url'])
        self.assertNotIn('vars', event['exception']['values'][0]['stacktrace']['frames'][0])
        self.assertNotIn('supersecrettoken', event['exception']['values'][0]['value'])
        self.assertIn('[Filtered]', event['exception']['values'][0]['value'])
