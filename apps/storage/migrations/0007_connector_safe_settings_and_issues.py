# Sanitize connector settings and store safe issue codes instead of free-text errors.

from django.db import migrations, models

# Allowlisted top-level keys (see connector_services.ALLOWED_CONNECTOR_SETTING_KEYS).
_ALLOWED_TOP = frozenset(
    {
        'display_name',
        'external_root_path',
        'tenant_id',
        'site_id',
        'drive_id',
        'resource_id',
    }
)


def _scrub_settings(raw):
    if not isinstance(raw, dict):
        return {}
    out = {}
    for k, v in raw.items():
        if k not in _ALLOWED_TOP:
            continue
        if k in {'display_name', 'external_root_path'} and isinstance(v, str):
            out[k] = v[:512]
        elif k in {'tenant_id', 'site_id', 'drive_id', 'resource_id'} and isinstance(v, str):
            s = v.strip()
            if len(s) <= 128 and s.replace('-', '').replace('_', '').isalnum():
                out[k] = s
    return out


def forwards_scrub(apps, schema_editor):
    Bucket = apps.get_model('storage', 'Bucket')
    for bucket in Bucket.objects.filter(kind='connector'):
        clean = _scrub_settings(bucket.connector_settings or {})
        code = ''
        # Column was renamed from connector_last_error; values may still be legacy free text.
        msg = (bucket.connector_last_issue_code or '').strip().lower()
        if msg:
            if 'simulated' in msg or 'simulation' in msg:
                code = 'dev_simulation_removed'
            elif 'credential' in msg or 'decrypt' in msg:
                code = 'credential_error'
            elif 'provider' in msg or 'configured' in msg:
                code = 'adapter_unavailable'
            else:
                code = 'configuration_invalid'
        bucket.connector_settings = clean
        bucket.connector_last_issue_code = code[:64]
        bucket.save(update_fields=['connector_settings', 'connector_last_issue_code', 'updated_at'])


class Migration(migrations.Migration):

    dependencies = [
        ('storage', '0006_connector_bucket_lifecycle'),
    ]

    operations = [
        migrations.RenameField(
            model_name='bucket',
            old_name='connector_last_error',
            new_name='connector_last_issue_code',
        ),
        migrations.AlterField(
            model_name='bucket',
            name='connector_last_issue_code',
            field=models.CharField(
                blank=True,
                default='',
                max_length=64,
                help_text='Stable code for the last configuration or credential check (never raw provider text).',
            ),
        ),
        migrations.RunPython(forwards_scrub, migrations.RunPython.noop),
    ]
