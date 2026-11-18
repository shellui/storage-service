# Connector bucket lifecycle fields (settings, encrypted credential, health).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('storage', '0005_grant_foreign_keys'),
    ]

    operations = [
        migrations.AddField(
            model_name='bucket',
            name='connector_settings',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='bucket',
            name='connector_credential_encrypted',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='bucket',
            name='connector_last_refresh_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='bucket',
            name='connector_last_test_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='bucket',
            name='connector_last_error',
            field=models.CharField(blank=True, default='', max_length=512),
        ),
        migrations.AddField(
            model_name='bucket',
            name='connector_retry_after',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='bucket',
            name='connector_credential_updated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
