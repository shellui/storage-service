import uuid
from datetime import datetime

from django.test import SimpleTestCase
from django.utils import timezone

from apps.actions.registry import DomainEventType, EventFieldDoc
from apps.actions.sample_data import payload_data_from_event


class PayloadDataFromEventTests(SimpleTestCase):
    def test_static_examples_when_unique_values_false(self) -> None:
        event = DomainEventType(
            id='test.event',
            label='Test',
            description='',
            payload_fields=(
                EventFieldDoc('object_id', 'id', '550e8400-e29b-41d4-a716-446655440000'),
                EventFieldDoc('created_at', 'when', '2020-01-01T00:00:00+00:00'),
            ),
        )
        data = payload_data_from_event(event, unique_values=False)
        self.assertEqual(data['object_id'], '550e8400-e29b-41d4-a716-446655440000')
        self.assertEqual(data['created_at'], '2020-01-01T00:00:00+00:00')

    def test_unique_uuid_and_live_timestamp_when_unique_values_true(self) -> None:
        event = DomainEventType(
            id='test.event',
            label='Test',
            description='',
            payload_fields=(
                EventFieldDoc('object_id', 'id', '550e8400-e29b-41d4-a716-446655440000'),
                EventFieldDoc('created_at', 'when', '2020-01-01T00:00:00+00:00'),
            ),
        )
        before = timezone.now()
        data = payload_data_from_event(event, unique_values=True)
        after = timezone.now()
        uuid.UUID(data['object_id'])
        self.assertNotEqual(data['object_id'], '550e8400-e29b-41d4-a716-446655440000')
        parsed = datetime.fromisoformat(data['created_at'])
        self.assertGreaterEqual(parsed, before)
        self.assertLessEqual(parsed, after)
