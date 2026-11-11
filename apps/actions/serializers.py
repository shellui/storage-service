from rest_framework import serializers

from apps.authapi.mcp_fields import McpSecretCharField
from apps.actions.registry import is_webhook_event, webhook_event_types

_EVENT_TYPE_HELP = 'Shellui Actions event id for this rule.'


def _webhook_event_choices() -> list[tuple[str, str]]:
    import apps.actions.storage_events  # noqa: F401

    return [(event.id, event.label) for event in webhook_event_types()]


class OpenAPISerializer(serializers.Serializer):
    """Placeholder for APIView classes documented via @extend_schema_view."""


class ActionRuleWriteSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    event_type = serializers.ChoiceField(
        choices=_webhook_event_choices(),
        required=False,
        help_text=_EVENT_TYPE_HELP,
    )
    enabled = serializers.BooleanField(required=False)

    url = serializers.URLField(required=False, allow_blank=True)
    secret = McpSecretCharField(required=False, allow_blank=True, trim_whitespace=False)
    authorization_header = serializers.CharField(required=False, allow_blank=True, trim_whitespace=False)
    allow_private_urls = serializers.BooleanField(required=False)

    def validate_event_type(self, value):
        if value and not is_webhook_event(value):
            raise serializers.ValidationError('Unknown event type.')
        return value


class ActionRuleCreateSerializer(ActionRuleWriteSerializer):
    name = serializers.CharField(max_length=200)
    event_type = serializers.ChoiceField(
        choices=_webhook_event_choices(),
        help_text=_EVENT_TYPE_HELP,
    )
    secret = McpSecretCharField(required=False, allow_blank=True, trim_whitespace=False)

    def validate_event_type(self, value):
        if not is_webhook_event(value):
            raise serializers.ValidationError('Unknown event type.')
        return value


class ActionRuleUpdateSerializer(ActionRuleWriteSerializer):
    pass
